package kms

import (
	"context"
	"fmt"
	"strings"

	cloudkms "google.golang.org/api/cloudkms/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanKeyrings{})
}

// ScanKeyrings discovers Cloud KMS key rings and crypto keys with rotation and protection details.
type ScanKeyrings struct{}

func (m *ScanKeyrings) Info() module.Info {
	return module.Info{
		Name:         "recon.kms.scan-keyrings",
		Tactic:       module.TacticRecon,
		Service:      "cloudkms",
		Description:  "List KMS key rings and crypto keys, flag missing rotation and software protection",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1552",
	}
}

// kmsLocations is the set of common KMS locations to scan.
var kmsLocations = []string{
	"global",
	"us", "us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
	"europe", "europe-west1", "europe-west2", "europe-west4",
	"asia", "asia-east1", "asia-northeast1", "asia-southeast1",
	"australia-southeast1",
}

func (m *ScanKeyrings) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := cloudkms.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create cloudkms client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning KMS key rings in project: %s", project)

		headers := []string{"KEYRING", "KEY", "PURPOSE", "ROTATION", "PROTECTION"}
		var rows [][]string
		keyringCount := 0

		for _, location := range kmsLocations {
			parent := fmt.Sprintf("projects/%s/locations/%s", project, location)

			err := svc.Projects.Locations.KeyRings.List(parent).Pages(context.Background(),
				func(resp *cloudkms.ListKeyRingsResponse) error {
					for _, kr := range resp.KeyRings {
						keyringCount++

						if err := ctx.Store.SaveResource(&db.Resource{
							WorkspaceID:  ctx.Workspace,
							Service:      "cloudkms",
							ResourceType: "keyring",
							Project:      project,
							Name:         kr.Name,
							Data: map[string]any{
								"name":       kr.Name,
								"create_time": kr.CreateTime,
							},
						}); err != nil {
							output.Error("Save keyring %s: %v", kr.Name, err)
						}

						// List crypto keys in this key ring.
						err := svc.Projects.Locations.KeyRings.CryptoKeys.List(kr.Name).Pages(context.Background(),
							func(keyResp *cloudkms.ListCryptoKeysResponse) error {
								for _, key := range keyResp.CryptoKeys {
									purpose := key.Purpose
									rotationPeriod := key.RotationPeriod
									if rotationPeriod == "" {
										rotationPeriod = "none"
									}

									protectionLevel := "SOFTWARE"
									if key.VersionTemplate != nil {
										protectionLevel = key.VersionTemplate.ProtectionLevel
									}

									// Shorten names for display.
									shortKeyring := shortName(kr.Name)
									shortKey := shortName(key.Name)

									rows = append(rows, []string{
										shortKeyring, shortKey, purpose, rotationPeriod, protectionLevel,
									})

									data := map[string]any{
										"name":             key.Name,
										"purpose":          purpose,
										"rotation_period":  rotationPeriod,
										"protection_level": protectionLevel,
										"create_time":      key.CreateTime,
										"keyring":          kr.Name,
										"labels":           key.Labels,
									}

									if err := ctx.Store.SaveResource(&db.Resource{
										WorkspaceID:  ctx.Workspace,
										Service:      "cloudkms",
										ResourceType: "cryptokey",
										Project:      project,
										Name:         key.Name,
										Data:         data,
									}); err != nil {
										output.Error("Save key %s: %v", key.Name, err)
									}

									// Flag keys without rotation as MEDIUM.
									if key.RotationPeriod == "" && ctx.Findings != nil {
										ctx.Findings <- module.Finding{
											Module:      "recon.kms.scan-keyrings",
											Severity:    module.SevMedium,
											Title:       "KMS key without automatic rotation",
											Description: fmt.Sprintf("Key %s has no rotation period configured", key.Name),
											Resource:    key.Name,
											Project:     project,
										}
									}

									// Flag SOFTWARE protection as LOW.
									if strings.EqualFold(protectionLevel, "SOFTWARE") && ctx.Findings != nil {
										ctx.Findings <- module.Finding{
											Module:      "recon.kms.scan-keyrings",
											Severity:    module.SevLow,
											Title:       "KMS key using software protection",
											Description: fmt.Sprintf("Key %s uses SOFTWARE protection level instead of HSM", key.Name),
											Resource:    key.Name,
											Project:     project,
										}
									}
								}
								return nil
							},
						)
						if err != nil {
							output.Error("List keys in %s: %v", kr.Name, err)
						}
					}
					return nil
				},
			)
			if err != nil {
				// Silently skip locations with no KMS resources or permission errors.
				continue
			}
		}

		if keyringCount == 0 {
			output.Info("No key rings found in %s", project)
		} else {
			output.Success("Found %d key rings in %s", keyringCount, project)
			output.Table(headers, rows)
		}
	}
	return nil
}

// shortName extracts the last two path segments from a KMS resource name.
func shortName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return name
}
