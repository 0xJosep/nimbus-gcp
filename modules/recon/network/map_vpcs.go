package network

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
	module.Register(&MapVPCs{})
}

// MapVPCs maps VPC networks, subnets, and peering connections.
type MapVPCs struct{}

func (m *MapVPCs) Info() module.Info {
	return module.Info{
		Name:         "recon.network.map-vpcs",
		Tactic:       module.TacticRecon,
		Service:      "compute",
		Description:  "Map VPC networks, subnets, and peering connections",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *MapVPCs) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := computev1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create compute client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Mapping VPC networks in project: %s", project)

		networks, err := svc.Networks.List(project).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(networks.Items) == 0 {
			output.Info("No VPC networks found in %s", project)
			continue
		}

		headers := []string{"NETWORK", "SUBNETS", "PEERINGS", "AUTO SUBNETS", "MODE"}
		var rows [][]string

		for _, net := range networks.Items {
			subnetCount := len(net.Subnetworks)
			peeringCount := len(net.Peerings)
			autoCreate := fmt.Sprintf("%v", net.AutoCreateSubnetworks)
			mode := "custom"
			if net.AutoCreateSubnetworks {
				mode = "auto"
			}

			rows = append(rows, []string{
				net.Name, fmt.Sprintf("%d", subnetCount), fmt.Sprintf("%d", peeringCount),
				autoCreate, mode,
			})

			var peeringNames []string
			for _, p := range net.Peerings {
				peeringNames = append(peeringNames, p.Network)
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "compute",
				ResourceType: "network",
				Project:      project,
				Name:         net.Name,
				Data: map[string]any{
					"name":           net.Name,
					"auto_subnets":   net.AutoCreateSubnetworks,
					"subnet_count":   subnetCount,
					"peering_count":  peeringCount,
					"peerings":       peeringNames,
					"routing_mode":   net.RoutingConfig.RoutingMode,
				},
			}); err != nil {
				output.Error("Save network %s: %v", net.Name, err)
			}
		}

		output.Success("Found %d VPC networks in %s", len(networks.Items), project)
		output.Table(headers, rows)

		// Also scan firewall rules.
		m.scanFirewalls(svc, ctx, project)
	}
	return nil
}

func (m *MapVPCs) scanFirewalls(svc *computev1.Service, ctx module.RunContext, project string) {
	firewalls, err := svc.Firewalls.List(project).Do()
	if err != nil {
		output.Error("Firewalls for %s: %v", project, err)
		return
	}

	if len(firewalls.Items) == 0 {
		return
	}

	output.Info("Firewall rules in %s:", project)
	headers := []string{"NAME", "DIRECTION", "ACTION", "SOURCES", "PORTS", "PRIORITY"}
	var rows [][]string

	for _, fw := range firewalls.Items {
		action := "DENY"
		if len(fw.Allowed) > 0 {
			action = "ALLOW"
		}

		sources := strings.Join(fw.SourceRanges, ", ")
		if sources == "" {
			sources = strings.Join(fw.SourceTags, ", ")
		}

		var ports []string
		for _, a := range fw.Allowed {
			for _, p := range a.Ports {
				ports = append(ports, fmt.Sprintf("%s/%s", a.IPProtocol, p))
			}
			if len(a.Ports) == 0 {
				ports = append(ports, a.IPProtocol)
			}
		}
		for _, d := range fw.Denied {
			for _, p := range d.Ports {
				ports = append(ports, fmt.Sprintf("%s/%s", d.IPProtocol, p))
			}
		}

		rows = append(rows, []string{
			fw.Name, fw.Direction, action, sources,
			strings.Join(ports, ", "), fmt.Sprintf("%d", fw.Priority),
		})

		if err := ctx.Store.SaveResource(&db.Resource{
			WorkspaceID:  ctx.Workspace,
			Service:      "compute",
			ResourceType: "firewall",
			Project:      project,
			Name:         fw.Name,
			Data: map[string]any{
				"name":          fw.Name,
				"direction":     fw.Direction,
				"action":        action,
				"sources":       fw.SourceRanges,
				"source_tags":   fw.SourceTags,
				"target_tags":   fw.TargetTags,
				"priority":      fw.Priority,
				"network":       fw.Network,
				"disabled":      fw.Disabled,
			},
		}); err != nil {
			output.Error("Save firewall %s: %v", fw.Name, err)
		}

		// Flag overly permissive rules.
		for _, src := range fw.SourceRanges {
			if src == "0.0.0.0/0" && action == "ALLOW" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.network.map-vpcs",
					Severity:    module.SevHigh,
					Title:       "Firewall allows all inbound (0.0.0.0/0)",
					Description: fmt.Sprintf("Rule %s allows traffic from 0.0.0.0/0 on %s", fw.Name, strings.Join(ports, ", ")),
					Resource:    fw.Name,
					Project:     project,
				}
				break
			}
		}
	}

	output.Table(headers, rows)
}
