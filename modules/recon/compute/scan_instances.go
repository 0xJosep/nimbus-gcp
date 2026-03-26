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
	module.Register(&ScanInstances{})
}

// ScanInstances discovers Compute Engine VMs across all zones with security-relevant metadata.
type ScanInstances struct{}

func (m *ScanInstances) Info() module.Info {
	return module.Info{
		Name:         "recon.compute.scan-instances",
		Tactic:       module.TacticRecon,
		Service:      "compute",
		Description:  "Scan VM instances across all zones with SA and network details",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1580",
	}
}

func (m *ScanInstances) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := computev1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create compute client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning compute instances in project: %s", project)

		var allInstances []*computev1.Instance
		err := svc.Instances.AggregatedList(project).Pages(context.Background(),
			func(page *computev1.InstanceAggregatedList) error {
				for _, scopedList := range page.Items {
					allInstances = append(allInstances, scopedList.Instances...)
				}
				return nil
			},
		)
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(allInstances) == 0 {
			output.Info("No instances found in %s", project)
			continue
		}

		headers := []string{"NAME", "ZONE", "STATUS", "MACHINE", "INTERNAL IP", "EXTERNAL IP", "SA"}
		var rows [][]string

		for _, inst := range allInstances {
			zone := lastSegment(inst.Zone)
			machineType := lastSegment(inst.MachineType)
			internalIP, externalIP := extractIPs(inst)

			var saEmail string
			if len(inst.ServiceAccounts) > 0 {
				saEmail = inst.ServiceAccounts[0].Email
			}

			rows = append(rows, []string{
				inst.Name, zone, inst.Status, machineType, internalIP, externalIP, saEmail,
			})

			var saEmails []string
			for _, sa := range inst.ServiceAccounts {
				saEmails = append(saEmails, sa.Email)
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "compute",
				ResourceType: "instance",
				Project:      project,
				Name:         inst.Name,
				Data: map[string]any{
					"name":              inst.Name,
					"zone":              zone,
					"status":            inst.Status,
					"machine_type":      machineType,
					"internal_ip":       internalIP,
					"external_ip":       externalIP,
					"service_accounts":  saEmails,
					"can_ip_forward":    inst.CanIpForward,
					"deletion_protect":  inst.DeletionProtection,
					"shielded_vm":       inst.ShieldedInstanceConfig != nil,
				},
			}); err != nil {
				output.Error("Save instance %s: %v", inst.Name, err)
			}

			// Flag instances with external IPs.
			if externalIP != "" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:   "recon.compute.scan-instances",
					Severity: module.SevMedium,
					Title:    "Instance with external IP",
					Description: fmt.Sprintf("VM %s has external IP %s in zone %s",
						inst.Name, externalIP, zone),
					Resource: inst.Name,
					Project:  project,
				}
			}

			// Flag default compute SA usage.
			if saEmail != "" && strings.HasSuffix(saEmail, "-compute@developer.gserviceaccount.com") && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.compute.scan-instances",
					Severity:    module.SevHigh,
					Title:       "Default compute SA in use",
					Description: fmt.Sprintf("VM %s uses default compute SA %s which has Editor role by default", inst.Name, saEmail),
					Resource:    inst.Name,
					Project:     project,
				}
			}
		}

		output.Success("Found %d instances in %s", len(allInstances), project)
		output.Table(headers, rows)
	}
	return nil
}

func lastSegment(url string) string {
	parts := strings.Split(url, "/")
	return parts[len(parts)-1]
}

func extractIPs(inst *computev1.Instance) (internal, external string) {
	for _, iface := range inst.NetworkInterfaces {
		if iface.NetworkIP != "" {
			internal = iface.NetworkIP
		}
		for _, ac := range iface.AccessConfigs {
			if ac.NatIP != "" {
				external = ac.NatIP
			}
		}
	}
	return
}
