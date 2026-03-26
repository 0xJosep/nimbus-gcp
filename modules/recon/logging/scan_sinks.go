package logging

import (
	"context"
	"fmt"
	"strings"

	loggingv2 "google.golang.org/api/logging/v2"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanSinks{})
}

// ScanSinks discovers logging sinks and audit log configurations.
type ScanSinks struct{}

func (m *ScanSinks) Info() module.Info {
	return module.Info{
		Name:         "recon.logging.scan-sinks",
		Tactic:       module.TacticRecon,
		Service:      "logging",
		Description:  "Scan log sinks and audit logging configuration",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanSinks) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified.")
		return nil
	}

	svc, err := loggingv2.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create logging client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning log sinks in project: %s", project)

		resp, err := svc.Projects.Sinks.List(fmt.Sprintf("projects/%s", project)).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Sinks) == 0 {
			output.Info("No log sinks found in %s", project)

			if ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.logging.scan-sinks",
					Severity:    module.SevMedium,
					Title:       "No log sinks configured",
					Description: fmt.Sprintf("Project %s has no log export sinks, logs only exist in Cloud Logging", project),
					Project:     project,
				}
			}
			continue
		}

		headers := []string{"SINK", "DESTINATION", "FILTER", "DISABLED"}
		var rows [][]string

		for _, sink := range resp.Sinks {
			filter := sink.Filter
			if filter == "" {
				filter = "(all logs)"
			}
			if len(filter) > 50 {
				filter = filter[:50] + "..."
			}

			destType := "unknown"
			if strings.Contains(sink.Destination, "storage.googleapis.com") {
				destType = "GCS"
			} else if strings.Contains(sink.Destination, "bigquery.googleapis.com") {
				destType = "BigQuery"
			} else if strings.Contains(sink.Destination, "pubsub.googleapis.com") {
				destType = "Pub/Sub"
			} else if strings.Contains(sink.Destination, "logging.googleapis.com") {
				destType = "Log Bucket"
			}

			rows = append(rows, []string{
				sink.Name, fmt.Sprintf("%s (%s)", destType, lastPart(sink.Destination)),
				filter, fmt.Sprintf("%v", sink.Disabled),
			})

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "logging",
				ResourceType: "sink",
				Project:      project,
				Name:         sink.Name,
				Data: map[string]any{
					"name":            sink.Name,
					"destination":     sink.Destination,
					"destination_type": destType,
					"filter":          sink.Filter,
					"disabled":        sink.Disabled,
					"writer_identity": sink.WriterIdentity,
				},
			}); err != nil {
				output.Error("Save sink %s: %v", sink.Name, err)
			}

			// Flag disabled sinks.
			if sink.Disabled && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.logging.scan-sinks",
					Severity:    module.SevHigh,
					Title:       "Log sink is disabled",
					Description: fmt.Sprintf("Sink %s is disabled, logs are not being exported to %s", sink.Name, destType),
					Resource:    sink.Name,
					Project:     project,
				}
			}
		}

		output.Success("Found %d log sinks in %s", len(resp.Sinks), project)
		output.Table(headers, rows)
	}
	return nil
}

func lastPart(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}
