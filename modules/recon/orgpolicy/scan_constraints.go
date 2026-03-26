package orgpolicy

import (
	"context"
	"fmt"
	"strings"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanConstraints{})
}

// ScanConstraints lists effective org policy constraints on each project and flags risky configurations.
type ScanConstraints struct{}

func (m *ScanConstraints) Info() module.Info {
	return module.Info{
		Name:         "recon.orgpolicy.scan-constraints",
		Tactic:       module.TacticRecon,
		Service:      "orgpolicy",
		Description:  "List org policy constraints per project, flag missing security enforcements",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1562",
	}
}

// securityConstraints maps constraint names to their expected enforcement and severity.
var securityConstraints = map[string]struct {
	severity    module.Severity
	title       string
	description string
}{
	"iam.disableServiceAccountKeyCreation": {
		severity:    module.SevHigh,
		title:       "SA key creation not restricted",
		description: "Constraint iam.disableServiceAccountKeyCreation is NOT enforced, allowing service account key creation",
	},
	"iam.disableServiceAccountCreation": {
		severity:    module.SevMedium,
		title:       "SA creation not restricted",
		description: "Constraint iam.disableServiceAccountCreation is NOT enforced, allowing unrestricted SA creation",
	},
	"compute.requireShieldedVm": {
		severity:    module.SevMedium,
		title:       "Shielded VM not required",
		description: "Constraint compute.requireShieldedVm is NOT enforced",
	},
	"storage.uniformBucketLevelAccess": {
		severity:    module.SevMedium,
		title:       "Uniform bucket access not required",
		description: "Constraint storage.uniformBucketLevelAccess is NOT enforced",
	},
}

func (m *ScanConstraints) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := crm.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create cloudresourcemanager client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning org policy constraints for project: %s", project)

		resp, err := svc.Projects.ListAvailableOrgPolicyConstraints(
			"projects/"+project,
			&crm.ListAvailableOrgPolicyConstraintsRequest{},
		).Context(context.Background()).Do()
		if err != nil {
			output.Error("Project %s list constraints: %v", project, err)
			continue
		}

		headers := []string{"CONSTRAINT", "TYPE", "ENFORCED"}
		var rows [][]string
		enforcedConstraints := make(map[string]bool)

		for _, constraint := range resp.Constraints {
			// Get the effective policy for each constraint.
			constraintName := constraint.Name
			shortName := constraintName
			if idx := strings.LastIndex(constraintName, "/"); idx != -1 {
				shortName = constraintName[idx+1:]
			}

			policy, err := svc.Projects.GetEffectiveOrgPolicy(
				"projects/"+project,
				&crm.GetEffectiveOrgPolicyRequest{
					Constraint: constraintName,
				},
			).Context(context.Background()).Do()

			enforced := "NOT SET"
			if err == nil && policy.BooleanPolicy != nil {
				if policy.BooleanPolicy.Enforced {
					enforced = "ENFORCED"
					enforcedConstraints[shortName] = true
				} else {
					enforced = "NOT ENFORCED"
				}
			} else if err == nil && policy.ListPolicy != nil {
				enforced = "LIST POLICY"
				enforcedConstraints[shortName] = true
			}

			constraintType := "boolean"
			if constraint.ListConstraint != nil {
				constraintType = "list"
			}

			rows = append(rows, []string{shortName, constraintType, enforced})

			data := map[string]any{
				"constraint": constraintName,
				"short_name": shortName,
				"type":       constraintType,
				"enforced":   enforced,
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "orgpolicy",
				ResourceType: "constraint",
				Project:      project,
				Name:         fmt.Sprintf("%s/%s", project, shortName),
				Data:         data,
			}); err != nil {
				output.Error("Save constraint %s: %v", shortName, err)
			}
		}

		// Check security-critical constraints.
		if ctx.Findings != nil {
			for constraintName, check := range securityConstraints {
				if !enforcedConstraints[constraintName] {
					ctx.Findings <- module.Finding{
						Module:      "recon.orgpolicy.scan-constraints",
						Severity:    check.severity,
						Title:       check.title,
						Description: fmt.Sprintf("Project %s: %s", project, check.description),
						Resource:    fmt.Sprintf("%s/%s", project, constraintName),
						Project:     project,
					}
				}
			}
		}

		if len(rows) == 0 {
			output.Info("No org policy constraints found in %s", project)
		} else {
			output.Success("Found %d constraints in %s", len(rows), project)
			output.Table(headers, rows)
		}
	}
	return nil
}
