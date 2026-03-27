package risk

import (
	"fmt"
	"strings"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
	"github.com/user/nimbus/internal/risk"
)

func init() {
	module.Register(&RiskReport{})
}

// RiskReport scores all discovered identities by risk level and outputs a
// ranked report.
type RiskReport struct{}

func (m *RiskReport) Info() module.Info {
	return module.Info{
		Name:         "analyze.risk.score-identities",
		Tactic:       module.TacticAnalyze,
		Service:      "iam",
		Description:  "Score and rank all identities by risk based on permissions and role bindings",
		RequiresAuth: false,
		Concurrent:   false,
	}
}

func (m *RiskReport) Run(ctx module.RunContext) error {
	// Query all distinct identities from role_bindings.
	identities, err := queryIdentities(ctx)
	if err != nil {
		return fmt.Errorf("query identities: %w", err)
	}

	if len(identities) == 0 {
		output.Warn("No identities found in role_bindings. Run recon.iam.list-bindings first.")
		return nil
	}

	output.Info("Scoring %d identities...", len(identities))
	fmt.Println()

	// Score all identities.
	scores := risk.RankIdentities(identities)

	// Output the ranked table.
	fmt.Printf("%s%s", output.Bold, output.Cyan)
	fmt.Printf("  %-6s  %-60s  %-7s  %s\n", "RANK", "IDENTITY", "SCORE", "TOP RISK FACTORS")
	fmt.Printf("  %-6s  %-60s  %-7s  %s%s\n",
		strings.Repeat("-", 6),
		strings.Repeat("-", 60),
		strings.Repeat("-", 7),
		strings.Repeat("-", 40),
		output.Reset)

	criticalCount := 0
	highCount := 0

	for i, s := range scores {
		rankStr := fmt.Sprintf("#%d", i+1)

		// Color-code by score.
		var scoreColor string
		var label string
		switch {
		case s.Score >= 80:
			scoreColor = output.Red + output.Bold
			label = "CRITICAL"
			criticalCount++
		case s.Score >= 60:
			scoreColor = output.Red
			label = "HIGH"
			highCount++
		case s.Score >= 40:
			scoreColor = output.Yellow
			label = "MEDIUM"
		default:
			scoreColor = output.Green
			label = "LOW"
		}

		// Truncate identity if too long.
		ident := s.Identity
		if len(ident) > 58 {
			ident = ident[:55] + "..."
		}

		// Collect top factors (up to 3).
		var topFactors []string
		for j, f := range s.Factors {
			if j >= 3 {
				topFactors = append(topFactors, fmt.Sprintf("+%d more", len(s.Factors)-3))
				break
			}
			topFactors = append(topFactors, f.Name)
		}
		factorStr := strings.Join(topFactors, ", ")

		fmt.Printf("  %-6s  %-60s  %s%-3d %-4s%s  %s%s%s\n",
			rankStr, ident, scoreColor, s.Score, label, output.Reset,
			output.Dim, factorStr, output.Reset)
	}

	fmt.Println()

	// Print score distribution.
	fmt.Printf("%s%s=== RISK DISTRIBUTION ===%s\n", output.Bold, output.Cyan, output.Reset)
	fmt.Println()

	var critCount, highCnt, medCount, lowCount int
	for _, s := range scores {
		switch {
		case s.Score >= 80:
			critCount++
		case s.Score >= 60:
			highCnt++
		case s.Score >= 40:
			medCount++
		default:
			lowCount++
		}
	}

	fmt.Printf("  %s%sCRITICAL (80-100):%s  %d identities\n", output.Red, output.Bold, output.Reset, critCount)
	fmt.Printf("  %sHIGH     (60-79):%s   %d identities\n", output.Red, output.Reset, highCnt)
	fmt.Printf("  %sMEDIUM   (40-59):%s   %d identities\n", output.Yellow, output.Reset, medCount)
	fmt.Printf("  %sLOW      (0-39):%s    %d identities\n", output.Green, output.Reset, lowCount)
	fmt.Println()

	// Emit findings for high-risk identities (score > 60).
	if ctx.Findings != nil {
		for _, s := range scores {
			if s.Score < 60 {
				continue
			}
			sev := module.SevHigh
			if s.Score >= 80 {
				sev = module.SevCritical
			}

			var factorDescs []string
			for _, f := range s.Factors {
				factorDescs = append(factorDescs, fmt.Sprintf("%s (+%d): %s", f.Name, f.Points, f.Description))
			}

			ctx.Findings <- module.Finding{
				Module:   "analyze.risk.score-identities",
				Severity: sev,
				Title:    fmt.Sprintf("High-risk identity: %s (score %d/100)", s.Identity, s.Score),
				Description: fmt.Sprintf(
					"Identity %s scored %d/100 in risk assessment. Risk factors: %s",
					s.Identity, s.Score, strings.Join(factorDescs, "; "),
				),
				Resource: s.Identity,
				Data: map[string]any{
					"score":   s.Score,
					"factors": factorDescs,
				},
			}
		}
	}

	if criticalCount+highCount > 0 {
		output.Warn("%d identities scored HIGH or CRITICAL — review their permissions and bindings", criticalCount+highCount)
	} else {
		output.Success("No identities scored above 60 — no high-risk identities detected")
	}
	fmt.Println()

	return nil
}

// queryIdentities reads all distinct identities from the role_bindings table
// and enriches them with permission data and role counts.
func queryIdentities(ctx module.RunContext) ([]risk.IdentityInfo, error) {
	// Get all distinct identities and their role counts.
	rows, err := ctx.Store.DB.Query(
		`SELECT identity, COUNT(*) as role_count
		 FROM role_bindings WHERE workspace_id = ?
		 GROUP BY identity ORDER BY role_count DESC`,
		ctx.Workspace,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type identEntry struct {
		identity  string
		roleCount int
	}
	var entries []identEntry
	for rows.Next() {
		var e identEntry
		if err := rows.Scan(&e.identity, &e.roleCount); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// For each identity, gather their roles to check for owner/editor.
	identRoles := make(map[string][]string)
	roleRows, err := ctx.Store.DB.Query(
		`SELECT identity, role FROM role_bindings WHERE workspace_id = ?`,
		ctx.Workspace,
	)
	if err != nil {
		return nil, err
	}
	defer roleRows.Close()

	for roleRows.Next() {
		var ident, role string
		if err := roleRows.Scan(&ident, &role); err != nil {
			return nil, err
		}
		identRoles[ident] = append(identRoles[ident], role)
	}
	if err := roleRows.Err(); err != nil {
		return nil, err
	}

	// Get granted permissions for the current session (if available) to
	// enrich identities that match the current session email.
	var sessionPerms []string
	if ctx.Session != nil {
		perms, err := ctx.Store.ListGrantedPermissions(ctx.Session.ID)
		if err == nil {
			permSet := make(map[string]bool)
			for _, p := range perms {
				if !permSet[p.Permission] {
					permSet[p.Permission] = true
					sessionPerms = append(sessionPerms, p.Permission)
				}
			}
		}
	}

	// Build IdentityInfo for each identity.
	var identities []risk.IdentityInfo
	for _, e := range entries {
		info := risk.IdentityInfo{
			Identity:  e.identity,
			RoleCount: e.roleCount,
		}

		// Check if this is the current session identity.
		if ctx.Session != nil && strings.EqualFold(e.identity, ctx.Session.Email) {
			info.Permissions = sessionPerms
		}

		// Pass actual roles so the scorer can detect owner/editor.
		info.Roles = identRoles[e.identity]

		// Check if it's a default compute SA (pattern: <project-number>-compute@developer.gserviceaccount.com).
		if strings.HasSuffix(e.identity, "-compute@developer.gserviceaccount.com") {
			info.IsDefaultSA = true
		}
		// Also check for App Engine default SA.
		if strings.HasSuffix(e.identity, "@appspot.gserviceaccount.com") {
			info.IsDefaultSA = true
		}

		identities = append(identities, info)
	}

	return identities, nil
}
