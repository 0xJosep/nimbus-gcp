package gke

import (
	"context"
	"fmt"

	container "google.golang.org/api/container/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanClusters{})
}

// ScanClusters discovers GKE clusters and their security configuration.
type ScanClusters struct{}

func (m *ScanClusters) Info() module.Info {
	return module.Info{
		Name:         "recon.gke.scan-clusters",
		Tactic:       module.TacticRecon,
		Service:      "gke",
		Description:  "Scan GKE clusters for RBAC, network policy, and node pool config",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanClusters) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified.")
		return nil
	}

	svc, err := container.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create container client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning GKE clusters in project: %s", project)

		resp, err := svc.Projects.Locations.Clusters.List(
			fmt.Sprintf("projects/%s/locations/-", project),
		).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Clusters) == 0 {
			output.Info("No GKE clusters found in %s", project)
			continue
		}

		headers := []string{"NAME", "LOCATION", "VERSION", "NODES", "STATUS", "PRIVATE", "SHIELDED"}
		var rows [][]string

		for _, cluster := range resp.Clusters {
			isPrivate := "no"
			if cluster.PrivateClusterConfig != nil && cluster.PrivateClusterConfig.EnablePrivateNodes {
				isPrivate = "yes"
			}

			shielded := "no"
			if cluster.ShieldedNodes != nil && cluster.ShieldedNodes.Enabled {
				shielded = "yes"
			}

			rows = append(rows, []string{
				cluster.Name, cluster.Location, cluster.CurrentMasterVersion,
				fmt.Sprintf("%d", cluster.CurrentNodeCount), cluster.Status,
				isPrivate, shielded,
			})

			// Collect node pool SAs.
			var nodeSAs []string
			for _, pool := range cluster.NodePools {
				if pool.Config != nil && pool.Config.ServiceAccount != "" {
					nodeSAs = append(nodeSAs, pool.Config.ServiceAccount)
				}
			}

			networkPolicy := false
			if cluster.NetworkPolicy != nil && cluster.NetworkPolicy.Enabled {
				networkPolicy = true
			}

			legacyAbac := false
			if cluster.LegacyAbac != nil && cluster.LegacyAbac.Enabled {
				legacyAbac = true
			}

			masterAuth := false
			if cluster.MasterAuth != nil && cluster.MasterAuth.Username != "" {
				masterAuth = true
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "gke",
				ResourceType: "cluster",
				Project:      project,
				Name:         cluster.Name,
				Data: map[string]any{
					"name":             cluster.Name,
					"location":         cluster.Location,
					"version":          cluster.CurrentMasterVersion,
					"node_count":       cluster.CurrentNodeCount,
					"status":           cluster.Status,
					"private_nodes":    isPrivate == "yes",
					"shielded_nodes":   shielded == "yes",
					"network_policy":   networkPolicy,
					"legacy_abac":      legacyAbac,
					"master_basic_auth": masterAuth,
					"node_pool_sas":    nodeSAs,
					"endpoint":         cluster.Endpoint,
				},
			}); err != nil {
				output.Error("Save cluster %s: %v", cluster.Name, err)
			}

			// Flag legacy ABAC.
			if legacyAbac && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.gke.scan-clusters",
					Severity:    module.SevCritical,
					Title:       "Legacy ABAC enabled on GKE cluster",
					Description: fmt.Sprintf("Cluster %s has legacy ABAC enabled, allowing any authenticated user to perform any action", cluster.Name),
					Resource:    cluster.Name,
					Project:     project,
				}
			}

			// Flag basic auth.
			if masterAuth && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.gke.scan-clusters",
					Severity:    module.SevHigh,
					Title:       "Basic authentication enabled on GKE master",
					Description: fmt.Sprintf("Cluster %s has basic auth enabled on the master API", cluster.Name),
					Resource:    cluster.Name,
					Project:     project,
				}
			}

			// Flag public clusters.
			if isPrivate == "no" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.gke.scan-clusters",
					Severity:    module.SevMedium,
					Title:       "GKE cluster has public nodes",
					Description: fmt.Sprintf("Cluster %s nodes have public IPs (not a private cluster)", cluster.Name),
					Resource:    cluster.Name,
					Project:     project,
				}
			}

			// Flag no network policy.
			if !networkPolicy && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.gke.scan-clusters",
					Severity:    module.SevMedium,
					Title:       "No network policy on GKE cluster",
					Description: fmt.Sprintf("Cluster %s has no network policy, pods can communicate freely", cluster.Name),
					Resource:    cluster.Name,
					Project:     project,
				}
			}
		}

		output.Success("Found %d clusters in %s", len(resp.Clusters), project)
		output.Table(headers, rows)
	}
	return nil
}
