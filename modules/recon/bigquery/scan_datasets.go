package bigquery

import (
	"context"
	"fmt"

	bq "cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanDatasets{})
}

// ScanDatasets discovers BigQuery datasets and their tables.
type ScanDatasets struct{}

func (m *ScanDatasets) Info() module.Info {
	return module.Info{
		Name:         "recon.bigquery.scan-datasets",
		Tactic:       module.TacticRecon,
		Service:      "bigquery",
		Description:  "Scan BigQuery datasets, tables, and access controls",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanDatasets) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified.")
		return nil
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning BigQuery datasets in project: %s", project)

		client, err := bq.NewClient(context.Background(), project, ctx.Session.ClientOption())
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		it := client.Datasets(context.Background())
		headers := []string{"DATASET", "LOCATION", "TABLES", "DEFAULT EXPIRATION"}
		var rows [][]string
		count := 0

		for {
			ds, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				output.Error("Project %s: %v", project, err)
				break
			}
			count++

			meta, err := ds.Metadata(context.Background())
			if err != nil {
				output.Error("Dataset %s metadata: %v", ds.DatasetID, err)
				continue
			}

			// Count tables.
			tableCount := 0
			tableIt := ds.Tables(context.Background())
			for {
				_, err := tableIt.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					break
				}
				tableCount++
			}

			expiration := "none"
			if meta.DefaultTableExpiration > 0 {
				expiration = meta.DefaultTableExpiration.String()
			}

			rows = append(rows, []string{
				ds.DatasetID, meta.Location, fmt.Sprintf("%d", tableCount), expiration,
			})

			// Collect access entries.
			var accessEntries []map[string]string
			for _, entry := range meta.Access {
				ae := map[string]string{"role": string(entry.Role)}
				if entry.Entity != "" {
					ae["entity"] = entry.Entity
				}
				if entry.EntityType != 0 {
					ae["type"] = fmt.Sprintf("%d", entry.EntityType)
				}
				accessEntries = append(accessEntries, ae)
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "bigquery",
				ResourceType: "dataset",
				Project:      project,
				Name:         ds.DatasetID,
				Data: map[string]any{
					"dataset_id":   ds.DatasetID,
					"location":     meta.Location,
					"table_count":  tableCount,
					"description":  meta.Description,
					"labels":       meta.Labels,
					"access":       accessEntries,
					"created":      meta.CreationTime.String(),
				},
			}); err != nil {
				output.Error("Save dataset %s: %v", ds.DatasetID, err)
			}
		}

		client.Close()

		if count == 0 {
			output.Info("No BigQuery datasets found in %s", project)
		} else {
			output.Success("Found %d datasets in %s", count, project)
			output.Table(headers, rows)
		}
	}
	return nil
}
