package graph

import (
	"fmt"

	"github.com/user/nimbus/internal/privesc"
)

// Analyzer overlays the privesc knowledge base onto the graph to discover escalation edges.
type Analyzer struct {
	graph *Graph
}

// NewAnalyzer creates an analyzer for a graph.
func NewAnalyzer(g *Graph) *Analyzer {
	return &Analyzer{graph: g}
}

// AnnotateEscalations walks all identity nodes, collects their effective permissions
// from role bindings, and checks for known privesc techniques. For each match,
// it adds a can_escalate edge to the graph.
func (a *Analyzer) AnnotateEscalations() []privesc.MatchResult {
	var allMatches []privesc.MatchResult

	for _, identity := range a.graph.IdentityNodes() {
		// Collect all roles this identity has.
		permissions := a.collectPermissionsForIdentity(identity.ID)

		// Match against known techniques.
		matches := privesc.MatchTechniques(permissions)
		for _, match := range matches {
			if !match.FullMatch {
				continue
			}

			allMatches = append(allMatches, match)

			// Add escalation edge.
			targetID := fmt.Sprintf("technique:%s", match.Technique.ID)
			a.graph.AddNode(&Node{
				ID:    targetID,
				Type:  NodeResource,
				Label: match.Technique.Name,
				Metadata: map[string]any{
					"technique_id": match.Technique.ID,
					"severity":     match.Technique.Severity,
					"description":  match.Technique.Description,
				},
			})

			a.graph.AddEdge(&Edge{
				From:      identity.ID,
				To:        targetID,
				Type:      EdgeCanEscalate,
				Label:     match.Technique.Name,
				Technique: match.Technique.ID,
				Metadata: map[string]any{
					"severity":    match.Technique.Severity,
					"permissions": match.MatchedPerms,
				},
			})
		}
	}
	return allMatches
}

// collectPermissionsForIdentity gathers all permissions granted to an identity
// through its role bindings. This is a simplified model — in production you'd
// resolve predefined role -> permission mappings.
func (a *Analyzer) collectPermissionsForIdentity(identityID string) []string {
	permSet := make(map[string]bool)

	// Walk outgoing edges to find role bindings.
	for _, edge := range a.graph.OutEdges(identityID) {
		if edge.Type != EdgeHasBinding {
			continue
		}
		roleNode, exists := a.graph.Nodes[edge.To]
		if !exists {
			continue
		}

		// Map well-known roles to their dangerous permissions.
		perms := roleToPermissions(roleNode.Label)
		for _, p := range perms {
			permSet[p] = true
		}
	}

	permissions := make([]string, 0, len(permSet))
	for p := range permSet {
		permissions = append(permissions, p)
	}
	return permissions
}

// roleToPermissions maps known GCP roles to their security-relevant permissions.
// This is a subset focused on privesc-relevant permissions.
func roleToPermissions(role string) []string {
	roleMap := map[string][]string{
		"roles/owner": {
			"iam.serviceAccountKeys.create",
			"iam.serviceAccounts.getAccessToken",
			"iam.serviceAccounts.signBlob",
			"iam.serviceAccounts.signJwt",
			"iam.serviceAccounts.implicitDelegation",
			"iam.serviceAccounts.actAs",
			"iam.roles.update",
			"resourcemanager.projects.setIamPolicy",
			"compute.instances.setMetadata",
			"compute.projects.setCommonInstanceMetadata",
			"compute.instances.create",
			"cloudfunctions.functions.create",
			"cloudfunctions.functions.update",
			"run.services.create",
			"storage.hmacKeys.create",
			"secretmanager.versions.access",
			"cloudsql.instances.export",
			"logging.sinks.delete",
			"logging.sinks.update",
		},
		"roles/editor": {
			"iam.serviceAccounts.actAs",
			"compute.instances.setMetadata",
			"compute.projects.setCommonInstanceMetadata",
			"compute.instances.create",
			"cloudfunctions.functions.create",
			"cloudfunctions.functions.update",
			"run.services.create",
			"storage.hmacKeys.create",
			"secretmanager.versions.access",
			"cloudsql.instances.export",
		},
		"roles/iam.serviceAccountAdmin": {
			"iam.serviceAccountKeys.create",
			"iam.serviceAccounts.getAccessToken",
		},
		"roles/iam.serviceAccountKeyAdmin": {
			"iam.serviceAccountKeys.create",
		},
		"roles/iam.serviceAccountUser": {
			"iam.serviceAccounts.actAs",
		},
		"roles/iam.serviceAccountTokenCreator": {
			"iam.serviceAccounts.getAccessToken",
			"iam.serviceAccounts.signBlob",
			"iam.serviceAccounts.signJwt",
			"iam.serviceAccounts.implicitDelegation",
		},
		"roles/iam.securityAdmin": {
			"resourcemanager.projects.setIamPolicy",
		},
		"roles/compute.admin": {
			"compute.instances.setMetadata",
			"compute.projects.setCommonInstanceMetadata",
			"compute.instances.create",
		},
		"roles/compute.instanceAdmin.v1": {
			"compute.instances.setMetadata",
		},
		"roles/cloudfunctions.admin": {
			"cloudfunctions.functions.create",
			"cloudfunctions.functions.update",
		},
		"roles/run.admin": {
			"run.services.create",
		},
		"roles/storage.admin": {
			"storage.hmacKeys.create",
		},
		"roles/secretmanager.secretAccessor": {
			"secretmanager.versions.access",
		},
		"roles/cloudsql.admin": {
			"cloudsql.instances.export",
		},
		"roles/logging.admin": {
			"logging.sinks.delete",
			"logging.sinks.update",
		},
	}

	if perms, ok := roleMap[role]; ok {
		return perms
	}
	return nil
}
