package run

import (
	"context"
	"fmt"
	"strings"

	runv2 "google.golang.org/api/run/v2"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanServices{})
}

// ScanServices discovers Cloud Run services, their revisions, and security config.
type ScanServices struct{}

func (m *ScanServices) Info() module.Info {
	return module.Info{
		Name:         "recon.run.scan-services",
		Tactic:       module.TacticRecon,
		Service:      "run",
		Description:  "Scan Cloud Run services for ingress, auth, SA, and revision details",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanServices) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := runv2.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create Cloud Run client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Cloud Run services in project: %s", project)

		resp, err := svc.Projects.Locations.Services.List(
			fmt.Sprintf("projects/%s/locations/-", project),
		).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Services) == 0 {
			output.Info("No Cloud Run services found in %s", project)
			continue
		}

		headers := []string{"SERVICE", "REGION", "INGRESS", "AUTH", "SA", "URL"}
		var rows [][]string

		for _, service := range resp.Services {
			name := lastSegment(service.Name)
			region := extractRegion(service.Name)

			ingress := service.Ingress
			sa := ""
			if service.Template != nil {
				sa = service.Template.ServiceAccount
			}

			requiresAuth := "yes"
			// Check IAM for allUsers/allAuthenticatedUsers bindings.
			iamPolicy, err := svc.Projects.Locations.Services.GetIamPolicy(service.Name).Do()
			if err == nil {
				for _, binding := range iamPolicy.Bindings {
					if binding.Role == "roles/run.invoker" {
						for _, member := range binding.Members {
							if member == "allUsers" || member == "allAuthenticatedUsers" {
								requiresAuth = "NO"
								break
							}
						}
					}
				}
			}

			url := service.Uri
			if len(url) > 50 {
				url = url[:50] + "..."
			}

			rows = append(rows, []string{name, region, ingress, requiresAuth, sa, url})

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "run",
				ResourceType: "service",
				Project:      project,
				Name:         service.Name,
				Data: map[string]any{
					"name":           name,
					"full_name":      service.Name,
					"region":         region,
					"ingress":        ingress,
					"url":            service.Uri,
					"service_account": sa,
					"requires_auth":  requiresAuth == "yes",
					"creator":        service.Creator,
					"create_time":    service.CreateTime,
					"update_time":    service.UpdateTime,
				},
			}); err != nil {
				output.Error("Save service %s: %v", name, err)
			}

			// Flag unauthenticated services.
			if requiresAuth == "NO" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.run.scan-services",
					Severity:    module.SevHigh,
					Title:       "Cloud Run service allows unauthenticated access",
					Description: fmt.Sprintf("Service %s (%s) has allUsers as invoker — publicly accessible", name, service.Uri),
					Resource:    service.Name,
					Project:     project,
				}
			}

			// Flag services with INGRESS_TRAFFIC_ALL.
			if ingress == "INGRESS_TRAFFIC_ALL" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.run.scan-services",
					Severity:    module.SevMedium,
					Title:       "Cloud Run allows all ingress traffic",
					Description: fmt.Sprintf("Service %s allows traffic from any source (INGRESS_TRAFFIC_ALL)", name),
					Resource:    service.Name,
					Project:     project,
				}
			}

			// Flag default App Engine SA.
			if strings.HasSuffix(sa, "@appspot.gserviceaccount.com") && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.run.scan-services",
					Severity:    module.SevHigh,
					Title:       "Cloud Run uses default App Engine SA",
					Description: fmt.Sprintf("Service %s runs as default App Engine SA %s which has Editor role", name, sa),
					Resource:    service.Name,
					Project:     project,
				}
			}
		}

		output.Success("Found %d Cloud Run services in %s", len(resp.Services), project)
		output.Table(headers, rows)
	}
	return nil
}

func lastSegment(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

func extractRegion(name string) string {
	// Format: projects/*/locations/<region>/services/*
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
