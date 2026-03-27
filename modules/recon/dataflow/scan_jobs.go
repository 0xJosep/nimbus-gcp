package dataflow

import (
	"context"
	"fmt"
	"strings"

	dataflowv1b3 "google.golang.org/api/dataflow/v1b3"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanJobs{})
}

// ScanJobs lists Dataflow jobs per project with security-relevant metadata.
type ScanJobs struct{}

func (m *ScanJobs) Info() module.Info {
	return module.Info{
		Name:         "recon.dataflow.scan-jobs",
		Tactic:       module.TacticRecon,
		Service:      "dataflow",
		Description:  "List Dataflow jobs and flag default compute SA usage",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanJobs) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := dataflowv1b3.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create dataflow client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Dataflow jobs in project: %s", project)

		// Use location "-" to list jobs across all regions.
		resp, err := svc.Projects.Locations.Jobs.List(project, "-").Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Jobs) == 0 {
			output.Info("No Dataflow jobs found in %s", project)
			continue
		}

		headers := []string{"NAME", "TYPE", "STATE", "SERVICE ACCOUNT", "CREATED"}
		var rows [][]string

		for _, job := range resp.Jobs {
			jobType := job.Type
			if jobType == "" {
				jobType = "UNKNOWN"
			}

			saEmail := ""
			if job.Environment != nil {
				saEmail = job.Environment.ServiceAccountEmail
			}

			createTime := job.CreateTime

			rows = append(rows, []string{
				job.Name,
				jobType,
				job.CurrentState,
				saEmail,
				createTime,
			})

			// Save to DB.
			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "dataflow",
				ResourceType: "job",
				Project:      project,
				Name:         job.Name,
				Data: map[string]any{
					"name":            job.Name,
					"id":              job.Id,
					"type":            jobType,
					"state":           job.CurrentState,
					"service_account": saEmail,
					"create_time":     createTime,
					"location":        job.Location,
				},
			}); err != nil {
				output.Error("Save job %s: %v", job.Name, err)
			}

			// Flag jobs using default compute SA.
			if saEmail != "" && strings.HasSuffix(saEmail, "-compute@developer.gserviceaccount.com") && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:   "recon.dataflow.scan-jobs",
					Severity: module.SevHigh,
					Title:    "Dataflow job uses default compute SA",
					Description: fmt.Sprintf("Dataflow job %s uses default compute SA %s which has Editor role by default",
						job.Name, saEmail),
					Resource: job.Name,
					Project:  project,
				}
			}
		}

		output.Success("Found %d Dataflow job(s) in %s", len(resp.Jobs), project)
		output.Table(headers, rows)
	}
	return nil
}
