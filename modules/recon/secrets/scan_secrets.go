package secrets

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanSecrets{})
}

// ScanSecrets discovers Secret Manager secrets and optionally reads their latest version.
type ScanSecrets struct{}

func (m *ScanSecrets) Info() module.Info {
	return module.Info{
		Name:         "recon.secrets.scan-secrets",
		Tactic:       module.TacticRecon,
		Service:      "secretmanager",
		Description:  "Discover secrets and optionally read their latest version values",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1552.004",
	}
}

func (m *ScanSecrets) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	client, err := secretmanager.NewClient(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create secretmanager client: %w", err)
	}
	defer client.Close()

	_, readValues := ctx.Flags["read-values"]

	for _, project := range ctx.Projects {
		output.Info("Scanning secrets in project: %s", project)

		it := client.ListSecrets(context.Background(), &secretmanagerpb.ListSecretsRequest{
			Parent: fmt.Sprintf("projects/%s", project),
		})

		headers := []string{"SECRET", "REPLICATION", "VERSIONS", "CREATED"}
		var rows [][]string
		count := 0

		for {
			secret, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				output.Error("Project %s: %v", project, err)
				break
			}
			count++

			replication := "automatic"
			if secret.Replication != nil {
				if secret.Replication.GetUserManaged() != nil {
					replication = "user-managed"
				}
			}

			created := ""
			if secret.CreateTime != nil {
				created = secret.CreateTime.AsTime().Format("2006-01-02")
			}

			versionCount := "-"

			rows = append(rows, []string{secret.Name, replication, versionCount, created})

			data := map[string]any{
				"name":        secret.Name,
				"replication": replication,
				"created":     created,
				"labels":      secret.Labels,
			}

			// Attempt to read latest version value if requested.
			if readValues {
				result, err := client.AccessSecretVersion(context.Background(), &secretmanagerpb.AccessSecretVersionRequest{
					Name: secret.Name + "/versions/latest",
				})
				if err == nil {
					data["value_preview"] = truncate(string(result.Payload.Data), 100)
					if ctx.Findings != nil {
						ctx.Findings <- module.Finding{
							Module:      "recon.secrets.scan-secrets",
							Severity:    module.SevHigh,
							Title:       "Secret value readable",
							Description: fmt.Sprintf("Successfully read latest version of secret %s", secret.Name),
							Resource:    secret.Name,
							Project:     project,
						}
					}
				}
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "secretmanager",
				ResourceType: "secret",
				Project:      project,
				Name:         secret.Name,
				Data:         data,
			}); err != nil {
				output.Error("Save secret: %v", err)
			}
		}

		if count == 0 {
			output.Info("No secrets found in %s", project)
		} else {
			output.Success("Found %d secrets in %s", count, project)
			output.Table(headers, rows)
		}
	}
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
