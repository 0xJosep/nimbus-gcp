package dns

import (
	"context"
	"fmt"
	"strings"

	dnsv1 "google.golang.org/api/dns/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanZones{})
}

// ScanZones discovers Cloud DNS zones and their record sets.
type ScanZones struct{}

func (m *ScanZones) Info() module.Info {
	return module.Info{
		Name:         "recon.dns.scan-zones",
		Tactic:       module.TacticRecon,
		Service:      "dns",
		Description:  "Scan Cloud DNS managed zones and enumerate record sets",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanZones) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := dnsv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create DNS client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning DNS zones in project: %s", project)

		resp, err := svc.ManagedZones.List(project).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.ManagedZones) == 0 {
			output.Info("No DNS zones found in %s", project)
			continue
		}

		headers := []string{"ZONE", "DNS NAME", "VISIBILITY", "RECORDS", "DNSSEC"}
		var rows [][]string

		for _, zone := range resp.ManagedZones {
			visibility := zone.Visibility
			if visibility == "" {
				visibility = "public"
			}

			dnssec := "off"
			if zone.DnssecConfig != nil && zone.DnssecConfig.State == "on" {
				dnssec = "on"
			}

			// Count records.
			recordCount := 0
			var records []map[string]any
			rrResp, err := svc.ResourceRecordSets.List(project, zone.Name).Do()
			if err == nil {
				recordCount = len(rrResp.Rrsets)
				if ctx.Verbose {
					for _, rr := range rrResp.Rrsets {
						records = append(records, map[string]any{
							"name":    rr.Name,
							"type":    rr.Type,
							"ttl":     rr.Ttl,
							"rrdatas": rr.Rrdatas,
						})
					}
				}
			}

			rows = append(rows, []string{
				zone.Name, zone.DnsName, visibility,
				fmt.Sprintf("%d", recordCount), dnssec,
			})

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "dns",
				ResourceType: "zone",
				Project:      project,
				Name:         zone.Name,
				Data: map[string]any{
					"name":         zone.Name,
					"dns_name":     zone.DnsName,
					"visibility":   visibility,
					"record_count": recordCount,
					"dnssec":       dnssec,
					"description":  zone.Description,
					"name_servers": zone.NameServers,
					"records":      records,
				},
			}); err != nil {
				output.Error("Save zone %s: %v", zone.Name, err)
			}

			// Flag public zones without DNSSEC.
			if visibility == "public" && dnssec == "off" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.dns.scan-zones",
					Severity:    module.SevMedium,
					Title:       "Public DNS zone without DNSSEC",
					Description: fmt.Sprintf("Zone %s (%s) is public with DNSSEC disabled — vulnerable to DNS spoofing", zone.Name, zone.DnsName),
					Resource:    zone.Name,
					Project:     project,
				}
			}

			// Print records in verbose mode.
			if ctx.Verbose && len(records) > 0 {
				output.Info("  Records for %s:", zone.Name)
				for _, rr := range rrResp.Rrsets {
					fmt.Printf("    %-40s %-6s %s\n", rr.Name, rr.Type, strings.Join(rr.Rrdatas, ", "))
				}
			}
		}

		output.Success("Found %d DNS zones in %s", len(resp.ManagedZones), project)
		output.Table(headers, rows)
	}
	return nil
}
