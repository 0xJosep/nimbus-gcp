package risk

import (
	"fmt"
	"sort"
)

// Factor represents a single risk factor contributing to an identity's score.
type Factor struct {
	Name        string
	Points      int
	Description string
}

// Score represents the computed risk score for an identity.
type Score struct {
	Identity string
	Score    int
	Factors  []Factor
}

// RoleBinding represents an IAM role binding for scoring purposes.
type RoleBinding struct {
	Role  string
	Scope string
}

// Resource represents a resource associated with an identity for scoring.
type Resource struct {
	Type       string
	Name       string
	Properties map[string]any
}

// IdentityInfo contains the data needed to score an identity.
type IdentityInfo struct {
	Identity      string
	Permissions   []string
	Roles         []string
	RoleCount     int
	IsDefaultSA   bool
	HasExternalIP bool
}

// ScoreIdentity computes a risk score (0-100) for a single identity based on
// its permissions, role bindings, and resource associations.
func ScoreIdentity(identity string, permissions []string, bindings []RoleBinding, resources []Resource) Score {
	s := Score{Identity: identity}

	permSet := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		permSet[p] = true
	}

	roleSet := make(map[string]bool, len(bindings))
	for _, b := range bindings {
		roleSet[b.Role] = true
	}

	// Role-based scoring.
	if roleSet["roles/owner"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "roles/owner",
			Points:      40,
			Description: "Has Owner role — full control over the project",
		})
	}

	if roleSet["roles/editor"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "roles/editor",
			Points:      30,
			Description: "Has Editor role — broad read/write access to most resources",
		})
	}

	// Permission-based scoring.
	if permSet["iam.serviceAccountKeys.create"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "iam.serviceAccountKeys.create",
			Points:      20,
			Description: "Can create SA keys — persistent credential generation",
		})
	}

	if permSet["iam.serviceAccounts.getAccessToken"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "iam.serviceAccounts.getAccessToken",
			Points:      20,
			Description: "Can generate SA access tokens — identity impersonation",
		})
	}

	if permSet["resourcemanager.projects.setIamPolicy"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "resourcemanager.projects.setIamPolicy",
			Points:      25,
			Description: "Can modify project IAM policy — grant any role",
		})
	}

	if permSet["compute.instances.setMetadata"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "compute.instances.setMetadata",
			Points:      15,
			Description: "Can set instance metadata — startup script injection or SSH key injection",
		})
	}

	if permSet["secretmanager.versions.access"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "secretmanager.versions.access",
			Points:      10,
			Description: "Can read secret values — potential credential exposure",
		})
	}

	if permSet["storage.objects.get"] {
		s.Factors = append(s.Factors, Factor{
			Name:        "storage.objects.get",
			Points:      5,
			Description: "Can read storage objects — data exfiltration risk",
		})
	}

	// Identity-type scoring.
	isDefault := false
	for _, r := range resources {
		if r.Type == "service_account" {
			if props := r.Properties; props != nil {
				if def, ok := props["is_default"]; ok {
					if b, ok := def.(bool); ok && b {
						isDefault = true
					}
				}
			}
		}
	}
	if isDefault {
		s.Factors = append(s.Factors, Factor{
			Name:        "default_compute_sa",
			Points:      15,
			Description: "Is a default compute service account — commonly over-privileged",
		})
	}

	// Resource association scoring.
	hasExtIP := false
	for _, r := range resources {
		if r.Type == "instance" {
			if props := r.Properties; props != nil {
				if ext, ok := props["has_external_ip"]; ok {
					if b, ok := ext.(bool); ok && b {
						hasExtIP = true
					}
				}
			}
		}
	}
	if hasExtIP {
		s.Factors = append(s.Factors, Factor{
			Name:        "external_ip_attached",
			Points:      10,
			Description: "Attached to a VM with an external IP — increased attack surface",
		})
	}

	// Binding count scoring.
	if len(bindings) > 5 {
		s.Factors = append(s.Factors, Factor{
			Name:        "excessive_bindings",
			Points:      5,
			Description: "Has more than 5 role bindings — broad access surface",
		})
	}

	// Sum the score and cap at 100.
	total := 0
	for _, f := range s.Factors {
		total += f.Points
	}
	if total > 100 {
		total = 100
	}
	s.Score = total

	return s
}

// RankIdentities scores all identities and returns them sorted by risk score
// in descending order (highest risk first).
func RankIdentities(identities []IdentityInfo) []Score {
	scores := make([]Score, 0, len(identities))
	for _, info := range identities {
		// Build bindings and resources from IdentityInfo fields.
		var bindings []RoleBinding
		var resources []Resource

		if info.IsDefaultSA {
			resources = append(resources, Resource{
				Type: "service_account",
				Name: info.Identity,
				Properties: map[string]any{
					"is_default": true,
				},
			})
		}

		if info.HasExternalIP {
			resources = append(resources, Resource{
				Type: "instance",
				Name: info.Identity,
				Properties: map[string]any{
					"has_external_ip": true,
				},
			})
		}

		// Build bindings from actual roles if available.
		if len(info.Roles) > 0 {
			for _, role := range info.Roles {
				bindings = append(bindings, RoleBinding{
					Role:  role,
					Scope: "project",
				})
			}
		} else {
			// Synthesize bindings to match binding count threshold.
			for i := 0; i < info.RoleCount; i++ {
				bindings = append(bindings, RoleBinding{
					Role:  fmt.Sprintf("role_%d", i),
					Scope: "project",
				})
			}
		}

		score := ScoreIdentity(info.Identity, info.Permissions, bindings, resources)
		scores = append(scores, score)
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})

	return scores
}
