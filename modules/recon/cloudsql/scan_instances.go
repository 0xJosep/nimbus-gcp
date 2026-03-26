package cloudsql

import (
	"context"
	"fmt"
	"strings"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanInstances{})
}

// ScanInstances discovers Cloud SQL instances and their security settings.
type ScanInstances struct{}

func (m *ScanInstances) Info() module.Info {
	return module.Info{
		Name:         "recon.cloudsql.scan-instances",
		Tactic:       module.TacticRecon,
		Service:      "cloudsql",
		Description:  "Scan Cloud SQL instances for auth, network, and backup config",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanInstances) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified.")
		return nil
	}

	svc, err := sqladmin.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create sqladmin client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Cloud SQL instances in project: %s", project)

		resp, err := svc.Instances.List(project).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Items) == 0 {
			output.Info("No Cloud SQL instances found in %s", project)
			continue
		}

		headers := []string{"NAME", "TYPE", "VERSION", "REGION", "STATE", "PUBLIC IP", "SSL"}
		var rows [][]string

		for _, inst := range resp.Items {
			publicIP := ""
			for _, addr := range inst.IpAddresses {
				if addr.Type == "PRIMARY" {
					publicIP = addr.IpAddress
				}
			}

			sslRequired := "no"
			if inst.Settings != nil && inst.Settings.IpConfiguration != nil &&
				inst.Settings.IpConfiguration.RequireSsl {
				sslRequired = "yes"
			}

			rows = append(rows, []string{
				inst.Name, inst.InstanceType, inst.DatabaseVersion,
				inst.Region, inst.State, publicIP, sslRequired,
			})

			// Collect authorized networks.
			var authNetworks []string
			if inst.Settings != nil && inst.Settings.IpConfiguration != nil {
				for _, net := range inst.Settings.IpConfiguration.AuthorizedNetworks {
					authNetworks = append(authNetworks, net.Value)
				}
			}

			backupEnabled := false
			if inst.Settings != nil && inst.Settings.BackupConfiguration != nil {
				backupEnabled = inst.Settings.BackupConfiguration.Enabled
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "cloudsql",
				ResourceType: "instance",
				Project:      project,
				Name:         inst.Name,
				Data: map[string]any{
					"name":                inst.Name,
					"database_version":    inst.DatabaseVersion,
					"instance_type":       inst.InstanceType,
					"region":              inst.Region,
					"state":               inst.State,
					"public_ip":           publicIP,
					"ssl_required":        sslRequired == "yes",
					"authorized_networks": authNetworks,
					"backup_enabled":      backupEnabled,
					"service_account":     inst.ServiceAccountEmailAddress,
				},
			}); err != nil {
				output.Error("Save instance %s: %v", inst.Name, err)
			}

			// Flag public IPs without SSL.
			if publicIP != "" && sslRequired == "no" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.cloudsql.scan-instances",
					Severity:    module.SevCritical,
					Title:       "Cloud SQL public IP without SSL requirement",
					Description: fmt.Sprintf("Instance %s has public IP %s and does not require SSL connections", inst.Name, publicIP),
					Resource:    inst.Name,
					Project:     project,
				}
			}

			// Flag 0.0.0.0/0 authorized networks.
			for _, net := range authNetworks {
				if strings.Contains(net, "0.0.0.0/0") && ctx.Findings != nil {
					ctx.Findings <- module.Finding{
						Module:      "recon.cloudsql.scan-instances",
						Severity:    module.SevCritical,
						Title:       "Cloud SQL allows all IPs (0.0.0.0/0)",
						Description: fmt.Sprintf("Instance %s allows connections from any IP address", inst.Name),
						Resource:    inst.Name,
						Project:     project,
					}
					break
				}
			}
		}

		output.Success("Found %d Cloud SQL instances in %s", len(resp.Items), project)
		output.Table(headers, rows)
	}
	return nil
}
