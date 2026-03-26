package iam

import (
	"fmt"
	"strings"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&DelegationChains{})
}

// DelegationChains maps multi-hop SA impersonation chains from collected IAM data.
type DelegationChains struct{}

func (m *DelegationChains) Info() module.Info {
	return module.Info{
		Name:         "analyze.iam.delegation-chains",
		Tactic:       module.TacticAnalyze,
		Service:      "iam",
		Description:  "Map multi-hop service account impersonation and delegation chains",
		RequiresAuth: false,
	}
}

// impersonationEdge represents a direct impersonation link.
type impersonationEdge struct {
	From       string
	To         string
	Permission string
	Via        string // Role that grants this
}

func (m *DelegationChains) Run(ctx module.RunContext) error {
	output.Info("Analyzing SA impersonation and delegation chains...")

	// Load all role bindings.
	rows, err := ctx.Store.DB.Query(
		`SELECT identity, role, scope, project FROM role_bindings WHERE workspace_id = ?`,
		ctx.Workspace,
	)
	if err != nil {
		return fmt.Errorf("query bindings: %w", err)
	}
	defer rows.Close()

	type binding struct {
		identity, role, scope, project string
	}
	var bindings []binding
	for rows.Next() {
		var b binding
		if err := rows.Scan(&b.identity, &b.role, &b.scope, &b.project); err != nil {
			return err
		}
		bindings = append(bindings, b)
	}

	if len(bindings) == 0 {
		output.Warn("No IAM bindings found. Run 'recon.iam.list-bindings' first.")
		return nil
	}

	// Load all service accounts.
	serviceAccounts, err := ctx.Store.ListResources(ctx.Workspace, "iam", "service_account")
	if err != nil {
		return err
	}

	saSet := make(map[string]bool)
	for _, sa := range serviceAccounts {
		saSet[sa.Name] = true
	}

	// Roles that grant impersonation capabilities.
	impersonationRoles := map[string]string{
		"roles/iam.serviceAccountTokenCreator": "iam.serviceAccounts.getAccessToken",
		"roles/iam.serviceAccountUser":         "iam.serviceAccounts.actAs",
		"roles/owner":                          "iam.serviceAccounts.getAccessToken",
		"roles/editor":                         "iam.serviceAccounts.actAs",
	}

	// Build the impersonation graph.
	// edge: identity -> SA they can impersonate, via which role.
	var edges []impersonationEdge

	for _, b := range bindings {
		perm, isImpersonation := impersonationRoles[b.role]
		if !isImpersonation {
			continue
		}

		// If the binding scope is a specific SA, it's a targeted impersonation.
		// If it's a project-level binding, the identity can impersonate all SAs in the project.
		if strings.Contains(b.scope, "serviceAccount") {
			// Extract the SA email from the scope.
			targetSA := extractSAFromScope(b.scope)
			if targetSA != "" {
				edges = append(edges, impersonationEdge{
					From: b.identity, To: targetSA, Permission: perm, Via: b.role,
				})
			}
		} else {
			// Project-level binding — can impersonate any SA in the project.
			for _, sa := range serviceAccounts {
				if sa.Project == b.project || b.project == "" {
					edges = append(edges, impersonationEdge{
						From: b.identity, To: sa.Name, Permission: perm, Via: b.role,
					})
				}
			}
		}
	}

	if len(edges) == 0 {
		output.Success("No impersonation paths found.")
		return nil
	}

	// Build adjacency list for multi-hop chain detection.
	adj := make(map[string][]impersonationEdge)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e)
	}

	// Find all chains (BFS up to depth 5).
	type chain struct {
		path  []string
		edges []impersonationEdge
	}

	var allChains []chain
	for _, e := range edges {
		// Only start from non-SA identities (users, groups) for interesting chains.
		if strings.HasPrefix(e.From, "serviceAccount:") {
			continue
		}
		visited := map[string]bool{e.From: true}
		queue := []chain{{path: []string{e.From, e.To}, edges: []impersonationEdge{e}}}

		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			lastNode := current.path[len(current.path)-1]
			allChains = append(allChains, current)

			if len(current.path) >= 5 {
				continue
			}

			// Look for next hops from the last SA.
			saIdentity := "serviceAccount:" + lastNode
			for _, next := range adj[saIdentity] {
				if !visited[next.To] {
					visited[next.To] = true
					newPath := make([]string, len(current.path)+1)
					copy(newPath, current.path)
					newPath[len(current.path)] = next.To
					newEdges := make([]impersonationEdge, len(current.edges)+1)
					copy(newEdges, current.edges)
					newEdges[len(current.edges)] = next
					queue = append(queue, chain{path: newPath, edges: newEdges})
				}
			}
		}
	}

	// Display results.
	// Show direct impersonation links.
	output.Warn("Found %d impersonation edge(s) and %d chain(s)", len(edges), len(allChains))
	fmt.Println()

	output.Info("Direct impersonation links:")
	headers := []string{"FROM", "TO", "VIA ROLE", "PERMISSION"}
	var tableRows [][]string
	seen := make(map[string]bool)
	for _, e := range edges {
		key := e.From + "->" + e.To
		if seen[key] {
			continue
		}
		seen[key] = true
		tableRows = append(tableRows, []string{
			truncateStr(e.From, 40), truncateStr(e.To, 40), e.Via, e.Permission,
		})
	}
	output.Table(headers, tableRows)

	// Show multi-hop chains (length > 2).
	multiHop := 0
	for _, c := range allChains {
		if len(c.path) > 2 {
			multiHop++
		}
	}

	if multiHop > 0 {
		output.Warn("Multi-hop delegation chains:")
		fmt.Println()
		displayed := 0
		for _, c := range allChains {
			if len(c.path) <= 2 {
				continue
			}
			displayed++
			if displayed > 20 {
				output.Info("  ... and %d more chains (use --verbose to show all)", multiHop-20)
				break
			}

			parts := make([]string, len(c.path))
			for i, p := range c.path {
				parts[i] = truncateStr(p, 35)
			}
			fmt.Printf("  [%d] %s\n", displayed, strings.Join(parts, " -> "))

			if ctx.Verbose {
				for _, e := range c.edges {
					fmt.Printf("       via %s (%s)\n", e.Via, e.Permission)
				}
			}
		}
		fmt.Println()
	}

	// Emit findings.
	if ctx.Findings != nil {
		for _, e := range edges {
			if !strings.HasPrefix(e.From, "serviceAccount:") {
				ctx.Findings <- module.Finding{
					Module:      "analyze.iam.delegation-chains",
					Severity:    module.SevHigh,
					Title:       "SA impersonation path",
					Description: fmt.Sprintf("%s can impersonate %s via %s", e.From, e.To, e.Via),
					Resource:    e.To,
					Data:        map[string]any{"from": e.From, "to": e.To, "role": e.Via, "permission": e.Permission},
				}
			}
		}

		if multiHop > 0 {
			ctx.Findings <- module.Finding{
				Module:      "analyze.iam.delegation-chains",
				Severity:    module.SevCritical,
				Title:       fmt.Sprintf("%d multi-hop delegation chain(s) detected", multiHop),
				Description: "Identities can chain through multiple service accounts to reach privileged SAs",
				Data:        map[string]any{"multi_hop_count": multiHop, "total_edges": len(edges)},
			}
		}
	}

	// Save edges as resources for the attack path engine.
	for _, e := range edges {
		ctx.Store.SaveResource(&db.Resource{
			WorkspaceID:  ctx.Workspace,
			Service:      "iam",
			ResourceType: "impersonation_edge",
			Name:         fmt.Sprintf("%s->%s", e.From, e.To),
			Data: map[string]any{
				"from":       e.From,
				"to":         e.To,
				"role":       e.Via,
				"permission": e.Permission,
			},
		})
	}

	return nil
}

func extractSAFromScope(scope string) string {
	// Scope might be: projects/x/serviceAccounts/email@project.iam.gserviceaccount.com
	parts := strings.Split(scope, "/")
	for i, p := range parts {
		if p == "serviceAccounts" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
