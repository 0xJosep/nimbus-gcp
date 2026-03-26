package iam

import (
	"context"
	"fmt"

	iamv1 "google.golang.org/api/iam/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ListPrincipals{})
}

// ListPrincipals discovers service accounts, their status, and optionally their keys.
type ListPrincipals struct{}

func (m *ListPrincipals) Info() module.Info {
	return module.Info{
		Name:         "recon.iam.list-principals",
		Tactic:       module.TacticRecon,
		Service:      "iam",
		Description:  "Discover service accounts and their key metadata",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1087.004",
	}
}

func (m *ListPrincipals) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified. Use --project-ids or set a default project.")
		return nil
	}

	svc, err := iamv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create IAM client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Discovering principals in project: %s", project)

		resp, err := svc.Projects.ServiceAccounts.List(
			fmt.Sprintf("projects/%s", project),
		).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Accounts) == 0 {
			output.Info("No service accounts found in %s", project)
			continue
		}

		headers := []string{"EMAIL", "DISPLAY NAME", "DISABLED", "KEYS"}
		var rows [][]string

		for _, sa := range resp.Accounts {
			keyCount := "-"
			if ctx.Verbose {
				keysResp, err := svc.Projects.ServiceAccounts.Keys.List(
					fmt.Sprintf("projects/%s/serviceAccounts/%s", project, sa.Email),
				).Do()
				if err == nil {
					keyCount = fmt.Sprintf("%d", len(keysResp.Keys))
				}
			}

			rows = append(rows, []string{sa.Email, sa.DisplayName, fmt.Sprintf("%v", sa.Disabled), keyCount})

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "iam",
				ResourceType: "service_account",
				Project:      project,
				Name:         sa.Email,
				Data: map[string]any{
					"email":        sa.Email,
					"display_name": sa.DisplayName,
					"unique_id":    sa.UniqueId,
					"disabled":     sa.Disabled,
					"description":  sa.Description,
				},
			}); err != nil {
				output.Error("Save %s: %v", sa.Email, err)
			}

			// Flag disabled SAs with keys as a finding.
			if sa.Disabled {
				if ctx.Findings != nil {
					ctx.Findings <- module.Finding{
						Module:      "recon.iam.list-principals",
						Severity:    module.SevLow,
						Title:       "Disabled service account exists",
						Description: fmt.Sprintf("SA %s is disabled but still present — verify no lingering keys", sa.Email),
						Resource:    sa.Email,
						Project:     project,
					}
				}
			}
		}

		output.Success("Found %d service accounts in %s", len(resp.Accounts), project)
		output.Table(headers, rows)
	}
	return nil
}
