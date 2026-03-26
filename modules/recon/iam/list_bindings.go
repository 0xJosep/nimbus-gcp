package iam

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ListBindings{})
}

// ListBindings retrieves IAM policy bindings on projects and flags dangerous roles.
type ListBindings struct{}

func (m *ListBindings) Info() module.Info {
	return module.Info{
		Name:         "recon.iam.list-bindings",
		Tactic:       module.TacticRecon,
		Service:      "iam",
		Description:  "List IAM policy bindings and flag dangerous roles",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

var dangerousRoles = map[string]string{
	"roles/owner":                    "Full project owner",
	"roles/editor":                   "Broad edit access (near-owner)",
	"roles/iam.securityAdmin":        "Can manage all IAM policies",
	"roles/iam.serviceAccountAdmin":  "Can manage all service accounts",
	"roles/iam.serviceAccountUser":   "Can impersonate service accounts",
	"roles/iam.serviceAccountKeyAdmin": "Can create SA keys",
	"roles/compute.admin":            "Full compute access",
	"roles/storage.admin":            "Full storage access",
	"roles/cloudfunctions.admin":     "Can deploy functions as any SA",
}

func (m *ListBindings) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := cloudresourcemanager.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create resource manager client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Retrieving IAM bindings for project: %s", project)

		policy, err := svc.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		headers := []string{"ROLE", "MEMBER", "CONDITION"}
		var rows [][]string

		for _, binding := range policy.Bindings {
			condition := ""
			if binding.Condition != nil {
				condition = binding.Condition.Title
			}

			for _, member := range binding.Members {
				rows = append(rows, []string{binding.Role, member, condition})

				// Store in role_bindings table.
				_, err := ctx.Store.DB.Exec(
					`INSERT OR IGNORE INTO role_bindings (workspace_id, identity, role, scope, project)
					 VALUES (?, ?, ?, ?, ?)`,
					ctx.Workspace, member, binding.Role, fmt.Sprintf("project/%s", project), project,
				)
				if err != nil {
					output.Error("Save binding: %v", err)
				}

				// Flag dangerous roles.
				if desc, ok := dangerousRoles[binding.Role]; ok && ctx.Findings != nil {
					sev := module.SevHigh
					if binding.Role == "roles/owner" || binding.Role == "roles/editor" {
						sev = module.SevCritical
					}
					ctx.Findings <- module.Finding{
						Module:      "recon.iam.list-bindings",
						Severity:    sev,
						Title:       fmt.Sprintf("Dangerous role: %s", binding.Role),
						Description: fmt.Sprintf("%s has %s (%s)", member, binding.Role, desc),
						Resource:    member,
						Project:     project,
						Data:        map[string]any{"role": binding.Role, "member": member},
					}
				}
			}
		}

		output.Success("Found %d bindings in %s", len(rows), project)
		output.Table(headers, rows)
	}
	return nil
}
