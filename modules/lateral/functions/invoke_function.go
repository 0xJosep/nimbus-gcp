package functions

import (
	"context"
	"fmt"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&InvokeFunction{})
}

// InvokeFunction invokes a Cloud Function to trigger its service account and capture the response.
type InvokeFunction struct{}

func (m *InvokeFunction) Info() module.Info {
	return module.Info{
		Name:         "lateral.functions.invoke-function",
		Tactic:       module.TacticLateral,
		Service:      "functions",
		Description:  "Invoke a Cloud Function to trigger its SA and get the response",
		RequiresAuth: true,
	}
}

func (m *InvokeFunction) Run(ctx module.RunContext) error {
	function := ctx.Flags["function"]
	region := ctx.Flags["region"]
	data := ctx.Flags["data"]

	if function == "" {
		output.Warn("Usage: run lateral.functions.invoke-function --function <name> [--region <region>] [--data <body>]")
		output.Info("The --function flag accepts a full resource name or a short name.")
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
		return fmt.Errorf("create cloudfunctions client: %w", err)
	}

	// Build the full resource name if a short name was provided.
	fullName := function
	if len(function) > 0 && function[0] != 'p' {
		// Short name: projects/<project>/locations/<region>/functions/<name>
		fullName = fmt.Sprintf("projects/%s/locations/%s/functions/%s", project, region, function)
	}

	output.Info("Invoking function: %s", fullName)

	callReq := &cloudfunctions.CallFunctionRequest{
		Data: data,
	}

	resp, err := svc.Projects.Locations.Functions.Call(fullName, callReq).Do()
	if err != nil {
		return fmt.Errorf("invoke function: %w", err)
	}

	if resp.Error != "" {
		output.Error("Function returned error: %s", resp.Error)
	}

	if resp.Result != "" {
		output.Success("Response:")
		output.Info("%s", resp.Result)
	}

	if resp.ExecutionId != "" {
		output.Info("Execution ID: %s", resp.ExecutionId)
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "lateral.functions.invoke-function",
			Severity:    module.SevHigh,
			Title:       "Cloud Function invoked",
			Description: fmt.Sprintf("Invoked function %s in project %s; triggered its service account", fullName, project),
			Resource:    fullName,
			Project:     project,
		}
	}

	return nil
}
