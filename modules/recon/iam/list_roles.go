package iam

import (
	"context"
	"fmt"
	"strings"

	iamv1 "google.golang.org/api/iam/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ListRoles{})
}

// ListRoles discovers custom IAM roles and their permissions.
type ListRoles struct{}

func (m *ListRoles) Info() module.Info {
	return module.Info{
		Name:         "recon.iam.list-roles",
		Tactic:       module.TacticRecon,
		Service:      "iam",
		Description:  "List custom IAM roles and flag overly permissive ones",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

// Permissions that are dangerous in custom roles.
var dangerousPermissions = map[string]string{
	"iam.serviceAccountKeys.create":             "Can create SA keys (NIM-001)",
	"iam.serviceAccounts.getAccessToken":         "Can impersonate SAs (NIM-002)",
	"iam.serviceAccounts.signBlob":               "Can sign as SA (NIM-004)",
	"iam.serviceAccounts.signJwt":                "Can forge SA JWTs (NIM-005)",
	"iam.serviceAccounts.implicitDelegation":     "Can delegate to SAs (NIM-003)",
	"iam.serviceAccounts.actAs":                  "Can act as any SA",
	"iam.roles.update":                           "Can modify custom roles (NIM-008)",
	"resourcemanager.projects.setIamPolicy":      "Can modify project IAM (NIM-006)",
	"resourcemanager.organizations.setIamPolicy": "Can modify org IAM (NIM-007)",
	"resourcemanager.folders.setIamPolicy":       "Can modify folder IAM (NIM-018)",
	"compute.instances.setMetadata":              "Can inject startup scripts (NIM-009)",
	"cloudfunctions.functions.create":            "Can deploy functions (NIM-011)",
	"cloudfunctions.functions.update":            "Can update functions (NIM-012)",
	"run.services.create":                        "Can deploy Cloud Run (NIM-013)",
	"secretmanager.versions.access":              "Can read secrets (NIM-016)",
}

func (m *ListRoles) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := iamv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create IAM client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Listing custom roles in project: %s", project)

		resp, err := svc.Projects.Roles.List(
			fmt.Sprintf("projects/%s", project),
		).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Roles) == 0 {
			output.Info("No custom roles found in %s", project)
			continue
		}

		headers := []string{"ROLE", "TITLE", "STAGE", "PERMISSIONS", "DANGEROUS"}
		var rows [][]string

		for _, role := range resp.Roles {
			// Get full role details with permissions.
			fullRole, err := svc.Projects.Roles.Get(role.Name).Do()
			if err != nil {
				output.Error("Get role %s: %v", role.Name, err)
				continue
			}

			permCount := len(fullRole.IncludedPermissions)
			shortName := lastRoleSegment(role.Name)

			// Check for dangerous permissions.
			var dangerousFound []string
			for _, perm := range fullRole.IncludedPermissions {
				if desc, ok := dangerousPermissions[perm]; ok {
					dangerousFound = append(dangerousFound, desc)
				}
			}

			dangerousStr := fmt.Sprintf("%d", len(dangerousFound))
			if len(dangerousFound) == 0 {
				dangerousStr = "-"
			}

			rows = append(rows, []string{
				shortName, fullRole.Title, fullRole.Stage,
				fmt.Sprintf("%d", permCount), dangerousStr,
			})

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "iam",
				ResourceType: "custom_role",
				Project:      project,
				Name:         role.Name,
				Data: map[string]any{
					"name":                 role.Name,
					"title":                fullRole.Title,
					"description":          fullRole.Description,
					"stage":                fullRole.Stage,
					"permission_count":     permCount,
					"permissions":          fullRole.IncludedPermissions,
					"dangerous_count":      len(dangerousFound),
					"dangerous_details":    dangerousFound,
				},
			}); err != nil {
				output.Error("Save role %s: %v", shortName, err)
			}

			// Flag roles with dangerous permissions.
			if len(dangerousFound) > 0 && ctx.Findings != nil {
				sev := module.SevMedium
				if len(dangerousFound) >= 3 {
					sev = module.SevCritical
				} else if len(dangerousFound) >= 1 {
					sev = module.SevHigh
				}

				ctx.Findings <- module.Finding{
					Module:   "recon.iam.list-roles",
					Severity: sev,
					Title:    fmt.Sprintf("Custom role with %d dangerous permission(s)", len(dangerousFound)),
					Description: fmt.Sprintf("Role %s has: %s",
						shortName, strings.Join(dangerousFound, "; ")),
					Resource: role.Name,
					Project:  project,
					Data:     map[string]any{"dangerous_permissions": dangerousFound},
				}
			}

			// Show dangerous permission details in verbose mode.
			if ctx.Verbose && len(dangerousFound) > 0 {
				output.Warn("  %s dangerous permissions:", shortName)
				for _, d := range dangerousFound {
					fmt.Printf("    - %s\n", d)
				}
			}
		}

		output.Success("Found %d custom roles in %s", len(resp.Roles), project)
		output.Table(headers, rows)
	}
	return nil
}

func lastRoleSegment(name string) string {
	parts := strings.Split(name, "/")
	return parts[len(parts)-1]
}
