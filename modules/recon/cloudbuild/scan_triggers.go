package cloudbuild

import (
	"context"
	"fmt"
	"strings"

	cb "google.golang.org/api/cloudbuild/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanTriggers{})
}

// ScanTriggers lists Cloud Build triggers and their configuration.
type ScanTriggers struct{}

func (m *ScanTriggers) Info() module.Info {
	return module.Info{
		Name:         "recon.cloudbuild.scan-triggers",
		Tactic:       module.TacticRecon,
		Service:      "cloudbuild",
		Description:  "List Cloud Build triggers, repos, and flag default SA usage",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanTriggers) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := cb.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create cloud build client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Cloud Build triggers in project: %s", project)

		resp, err := svc.Projects.Triggers.List(project).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Triggers) == 0 {
			output.Info("No Cloud Build triggers found in %s", project)
			continue
		}

		headers := []string{"NAME", "ID", "EVENT", "REPO", "BRANCH", "SERVICE ACCOUNT", "DISABLED"}
		var rows [][]string

		for _, trigger := range resp.Triggers {
			name := trigger.Name
			if name == "" {
				name = trigger.Description
			}

			// Determine event type.
			eventType := "manual"
			if trigger.Github != nil {
				eventType = "github"
			} else if trigger.TriggerTemplate != nil {
				eventType = "push"
			} else if trigger.PubsubConfig != nil {
				eventType = "pubsub"
			} else if trigger.WebhookConfig != nil {
				eventType = "webhook"
			}

			// Determine repo.
			repo := ""
			branch := ""
			if trigger.Github != nil {
				repo = fmt.Sprintf("%s/%s", trigger.Github.Owner, trigger.Github.Name)
				if trigger.Github.Push != nil {
					branch = trigger.Github.Push.Branch
				} else if trigger.Github.PullRequest != nil {
					branch = trigger.Github.PullRequest.Branch
					eventType = "github-pr"
				}
			} else if trigger.TriggerTemplate != nil {
				repo = trigger.TriggerTemplate.RepoName
				branch = trigger.TriggerTemplate.BranchName
				if branch == "" {
					branch = trigger.TriggerTemplate.TagName
				}
			}

			// Check service account.
			sa := trigger.ServiceAccount
			isDefaultSA := false
			if sa == "" {
				sa = "(default Cloud Build SA)"
				isDefaultSA = true
			} else {
				// Extract email from full resource name if present.
				// Format: projects/{project}/serviceAccounts/{email}
				saParts := strings.Split(sa, "/")
				if len(saParts) > 0 {
					sa = saParts[len(saParts)-1]
				}
				// Check if it's the default Cloud Build SA pattern.
				if strings.Contains(sa, "@cloudbuild.gserviceaccount.com") {
					isDefaultSA = true
				}
			}

			disabled := "no"
			if trigger.Disabled {
				disabled = "yes"
			}

			rows = append(rows, []string{
				name, trigger.Id, eventType, repo, branch, sa, disabled,
			})

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "cloudbuild",
				ResourceType: "trigger",
				Project:      project,
				Name:         fmt.Sprintf("%s/%s", project, trigger.Id),
				Data: map[string]any{
					"name":            name,
					"id":              trigger.Id,
					"event_type":      eventType,
					"repo":            repo,
					"branch":          branch,
					"service_account": sa,
					"default_sa":      isDefaultSA,
					"disabled":        trigger.Disabled,
				},
			}); err != nil {
				output.Error("Save trigger %s: %v", trigger.Id, err)
			}

			// Flag triggers using default Cloud Build SA.
			if isDefaultSA && !trigger.Disabled && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.cloudbuild.scan-triggers",
					Severity:    module.SevHigh,
					Title:       "Cloud Build trigger uses default SA",
					Description: fmt.Sprintf("Trigger %s (%s) in %s uses the default Cloud Build SA which has broad permissions (editor role)", name, trigger.Id, project),
					Resource:    trigger.Id,
					Project:     project,
					Data: map[string]any{
						"trigger_name": name,
						"trigger_id":   trigger.Id,
						"event_type":   eventType,
						"repo":         repo,
					},
				}
			}
		}

		output.Success("Found %d triggers in %s", len(resp.Triggers), project)
		output.Table(headers, rows)
	}
	return nil
}
