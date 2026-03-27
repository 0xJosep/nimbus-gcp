package storage

import (
	"context"
	"fmt"

	storagev1 "google.golang.org/api/storage/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&CreateHMACKeys{})
}

// CreateHMACKeys creates HMAC keys for a target service account.
type CreateHMACKeys struct{}

func (m *CreateHMACKeys) Info() module.Info {
	return module.Info{
		Name:         "credential.storage.create-hmac-keys",
		Tactic:       module.TacticCredential,
		Service:      "storage",
		Description:  "Create HMAC keys for a target SA for S3-compatible access to GCS",
		RequiresAuth: true,
		AttackID:     "T1098.001",
	}
}

func (m *CreateHMACKeys) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	if targetSA == "" {
		output.Warn("Usage: run credential.storage.create-hmac-keys --target-sa <email>")
		output.Info("Creates HMAC keys for the target SA, enabling S3-compatible access to GCS.")
		output.Info("Tip: run 'recon.iam.list-principals' to find service accounts.")
		return nil
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := storagev1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create storage client: %w", err)
	}

	output.Info("Creating HMAC key for SA: %s in project %s", targetSA, project)

	hmacKey, err := svc.Projects.HmacKeys.Create(project, targetSA).Do()
	if err != nil {
		return fmt.Errorf("create HMAC key: %w", err)
	}

	output.Success("HMAC key created successfully!")
	output.Warn("Access ID: %s", hmacKey.Metadata.AccessId)
	output.Warn("Secret:    %s", hmacKey.Secret)
	output.Info("State:     %s", hmacKey.Metadata.State)
	output.Info("SA:        %s", hmacKey.Metadata.ServiceAccountEmail)
	output.Warn("Save these credentials now -- the secret cannot be retrieved again.")

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "credential.storage.create-hmac-keys",
			Severity:    module.SevHigh,
			Title:       "HMAC key created for service account",
			Description: fmt.Sprintf("Created HMAC key (Access ID: %s) for SA %s in project %s", hmacKey.Metadata.AccessId, targetSA, project),
			Resource:    targetSA,
			Project:     project,
			Data: map[string]any{
				"access_id":  hmacKey.Metadata.AccessId,
				"target_sa":  targetSA,
			},
		}
	}

	return nil
}
