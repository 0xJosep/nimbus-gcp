package iam

import (
	"context"
	"fmt"

	iamv1 "google.golang.org/api/iam/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&StealSAKeys{})
}

// StealSAKeys enumerates service account keys to identify downloadable user-managed keys.
type StealSAKeys struct{}

func (m *StealSAKeys) Info() module.Info {
	return module.Info{
		Name:         "credential.iam.steal-sa-keys",
		Tactic:       module.TacticCredential,
		Service:      "iam",
		Description:  "List SA keys for target or all known service accounts, flag user-managed keys",
		RequiresAuth: true,
		AttackID:     "T1552.001",
	}
}

func (m *StealSAKeys) Run(ctx module.RunContext) error {
	svc, err := iamv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create IAM client: %w", err)
	}

	targetSA := ctx.Flags["target-sa"]

	var saEmails []string
	if targetSA != "" {
		saEmails = append(saEmails, targetSA)
	} else {
		// Pull all known service accounts from the DB.
		resources, err := ctx.Store.ListResources(ctx.Workspace, "iam", "service-account")
		if err != nil {
			return fmt.Errorf("list service accounts from DB: %w", err)
		}
		if len(resources) == 0 {
			output.Warn("No target specified and no service accounts in DB.")
			output.Info("Usage: run credential.iam.steal-sa-keys --target-sa <email>")
			output.Info("Tip: run 'recon.iam.list-principals' first to discover service accounts.")
			return nil
		}
		for _, r := range resources {
			if email, ok := r.Data["email"].(string); ok && email != "" {
				saEmails = append(saEmails, email)
			} else {
				saEmails = append(saEmails, r.Name)
			}
		}
		output.Info("Found %d service accounts in DB", len(saEmails))
	}

	for _, email := range saEmails {
		output.Info("Listing keys for SA: %s", email)

		resp, err := svc.Projects.ServiceAccounts.Keys.List(
			fmt.Sprintf("projects/-/serviceAccounts/%s", email),
		).Do()
		if err != nil {
			output.Warn("Failed to list keys for %s: %v", email, err)
			continue
		}

		if len(resp.Keys) == 0 {
			output.Info("  No keys found for %s", email)
			continue
		}

		for _, key := range resp.Keys {
			keyType := key.KeyType
			output.Info("  Key: %s", key.Name)
			output.Info("    Type:        %s", keyType)
			output.Info("    ValidAfter:  %s", key.ValidAfterTime)
			output.Info("    ValidBefore: %s", key.ValidBeforeTime)

			if keyType == "USER_MANAGED" {
				output.Warn("    ** USER_MANAGED key detected — potential for download/exfil **")

				if ctx.Findings != nil {
					ctx.Findings <- module.Finding{
						Module:      "credential.iam.steal-sa-keys",
						Severity:    module.SevHigh,
						Title:       "User-managed SA key found",
						Description: fmt.Sprintf("SA %s has user-managed key %s (valid until %s)", email, key.Name, key.ValidBeforeTime),
						Resource:    email,
					}
				}
			}
		}
	}

	return nil
}
