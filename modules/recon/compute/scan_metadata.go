package compute

import (
	"context"
	"fmt"
	"strings"

	computev1 "google.golang.org/api/compute/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanMetadata{})
}

// ScanMetadata inspects project-level compute metadata for security misconfigurations.
type ScanMetadata struct{}

func (m *ScanMetadata) Info() module.Info {
	return module.Info{
		Name:         "recon.compute.scan-metadata",
		Tactic:       module.TacticRecon,
		Service:      "compute",
		Description:  "Check project-level metadata for SSH keys, serial port, and OS Login config",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1078.004",
	}
}

func (m *ScanMetadata) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := computev1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create compute client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning project metadata for: %s", project)

		proj, err := svc.Projects.Get(project).Context(context.Background()).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		headers := []string{"KEY", "VALUE"}
		var rows [][]string

		hasSSHKeys := false
		serialPortEnabled := false
		osLoginEnabled := false

		if proj.CommonInstanceMetadata != nil {
			for _, item := range proj.CommonInstanceMetadata.Items {
				if item == nil {
					continue
				}

				val := ""
				if item.Value != nil {
					val = *item.Value
				}

				switch item.Key {
				case "ssh-keys", "sshKeys":
					hasSSHKeys = true
					keyCount := len(strings.Split(strings.TrimSpace(val), "\n"))
					rows = append(rows, []string{item.Key, fmt.Sprintf("(%d keys configured)", keyCount)})

				case "serial-port-enable":
					if strings.EqualFold(val, "true") || val == "1" {
						serialPortEnabled = true
					}
					rows = append(rows, []string{item.Key, val})

				case "enable-oslogin":
					if strings.EqualFold(val, "true") || val == "1" {
						osLoginEnabled = true
					}
					rows = append(rows, []string{item.Key, val})

				default:
					displayVal := val
					if len(displayVal) > 80 {
						displayVal = displayVal[:80] + "..."
					}
					rows = append(rows, []string{item.Key, displayVal})
				}
			}
		}

		data := map[string]any{
			"project":              project,
			"has_ssh_keys":         hasSSHKeys,
			"serial_port_enabled":  serialPortEnabled,
			"os_login_enabled":     osLoginEnabled,
		}

		if err := ctx.Store.SaveResource(&db.Resource{
			WorkspaceID:  ctx.Workspace,
			Service:      "compute",
			ResourceType: "project-metadata",
			Project:      project,
			Name:         project + "/metadata",
			Data:         data,
		}); err != nil {
			output.Error("Save metadata: %v", err)
		}

		// Flag project-wide SSH keys as HIGH.
		if hasSSHKeys && ctx.Findings != nil {
			ctx.Findings <- module.Finding{
				Module:      "recon.compute.scan-metadata",
				Severity:    module.SevHigh,
				Title:       "Project-wide SSH keys configured",
				Description: fmt.Sprintf("Project %s has SSH keys in commonInstanceMetadata, granting access to all VMs without OS Login", project),
				Resource:    project + "/metadata",
				Project:     project,
			}
		}

		// Flag serial port enabled as MEDIUM.
		if serialPortEnabled && ctx.Findings != nil {
			ctx.Findings <- module.Finding{
				Module:      "recon.compute.scan-metadata",
				Severity:    module.SevMedium,
				Title:       "Serial port access enabled project-wide",
				Description: fmt.Sprintf("Project %s has serial-port-enable=true, allowing interactive serial console access to VMs", project),
				Resource:    project + "/metadata",
				Project:     project,
			}
		}

		// Flag OS Login disabled as MEDIUM.
		if !osLoginEnabled && ctx.Findings != nil {
			ctx.Findings <- module.Finding{
				Module:      "recon.compute.scan-metadata",
				Severity:    module.SevMedium,
				Title:       "OS Login not enabled project-wide",
				Description: fmt.Sprintf("Project %s does not have OS Login enabled; VM access relies on SSH key metadata instead of IAM", project),
				Resource:    project + "/metadata",
				Project:     project,
			}
		}

		if len(rows) == 0 {
			output.Info("No metadata items found in %s", project)
		} else {
			output.Success("Found %d metadata items in %s", len(rows), project)
			output.Table(headers, rows)
		}
	}
	return nil
}
