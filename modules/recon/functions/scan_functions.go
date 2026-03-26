package functions

import (
	"context"
	"fmt"
	"strings"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanFunctions{})
}

// ScanFunctions discovers Cloud Functions and their security-relevant configuration.
type ScanFunctions struct{}

func (m *ScanFunctions) Info() module.Info {
	return module.Info{
		Name:         "recon.functions.scan-functions",
		Tactic:       module.TacticRecon,
		Service:      "cloudfunctions",
		Description:  "Scan Cloud Functions for triggers, SAs, and ingress settings",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanFunctions) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified.")
		return nil
	}

	svc, err := cloudfunctions.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create functions client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Cloud Functions in project: %s", project)

		resp, err := svc.Projects.Locations.Functions.List(
			fmt.Sprintf("projects/%s/locations/-", project),
		).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Functions) == 0 {
			output.Info("No functions found in %s", project)
			continue
		}

		headers := []string{"NAME", "RUNTIME", "STATUS", "TRIGGER", "SA", "INGRESS"}
		var rows [][]string

		for _, fn := range resp.Functions {
			name := lastSegment(fn.Name)
			trigger := "HTTP"
			if fn.EventTrigger != nil {
				trigger = fn.EventTrigger.EventType
			}
			sa := fn.ServiceAccountEmail
			ingress := fn.IngressSettings

			rows = append(rows, []string{name, fn.Runtime, fn.Status, trigger, sa, ingress})

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "cloudfunctions",
				ResourceType: "function",
				Project:      project,
				Name:         fn.Name,
				Data: map[string]any{
					"name":            fn.Name,
					"runtime":         fn.Runtime,
					"status":          fn.Status,
					"trigger":         trigger,
					"service_account": sa,
					"ingress":         ingress,
					"entry_point":     fn.EntryPoint,
					"timeout":         fn.Timeout,
					"memory_mb":       fn.AvailableMemoryMb,
					"vpc_connector":   fn.VpcConnector,
				},
			}); err != nil {
				output.Error("Save function %s: %v", name, err)
			}

			// Flag functions with ALLOW_ALL ingress.
			if ingress == "ALLOW_ALL" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.functions.scan-functions",
					Severity:    module.SevMedium,
					Title:       "Function allows all ingress",
					Description: fmt.Sprintf("Function %s accepts traffic from any source (ALLOW_ALL)", name),
					Resource:    fn.Name,
					Project:     project,
				}
			}

			// Flag functions using default SA.
			if strings.HasSuffix(sa, "@appspot.gserviceaccount.com") && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.functions.scan-functions",
					Severity:    module.SevHigh,
					Title:       "Function uses default App Engine SA",
					Description: fmt.Sprintf("Function %s runs as default App Engine SA %s which has Editor role", name, sa),
					Resource:    fn.Name,
					Project:     project,
				}
			}
		}

		output.Success("Found %d functions in %s", len(resp.Functions), project)
		output.Table(headers, rows)
	}
	return nil
}

func lastSegment(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}
