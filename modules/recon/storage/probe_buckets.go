package storage

import (
	"context"
	"fmt"

	gcs "cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ProbeBuckets{})
}

// ProbeBuckets discovers Cloud Storage buckets, their configuration, and access settings.
type ProbeBuckets struct{}

func (m *ProbeBuckets) Info() module.Info {
	return module.Info{
		Name:         "recon.storage.probe-buckets",
		Tactic:       module.TacticRecon,
		Service:      "storage",
		Description:  "Probe storage buckets for configuration and access settings",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1619",
	}
}

func (m *ProbeBuckets) Run(ctx module.RunContext) error {
	if len(ctx.Projects) == 0 {
		output.Warn("No projects specified.")
		return nil
	}

	client, err := gcs.NewClient(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create storage client: %w", err)
	}
	defer client.Close()

	_, countObjects := ctx.Flags["count-objects"]

	for _, project := range ctx.Projects {
		output.Info("Probing storage buckets in project: %s", project)

		it := client.Buckets(context.Background(), project)
		headers := []string{"BUCKET", "LOCATION", "CLASS", "UNIFORM ACL", "VERSIONING", "PUBLIC PREVENTION"}
		var rows [][]string
		bucketCount := 0

		for {
			attrs, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				output.Error("Project %s: %v", project, err)
				break
			}

			bucketCount++
			uniformACL := fmt.Sprintf("%v", attrs.UniformBucketLevelAccess.Enabled)
			versioning := fmt.Sprintf("%v", attrs.VersioningEnabled)
			publicPrevention := string(attrs.PublicAccessPrevention)

			rows = append(rows, []string{
				attrs.Name, attrs.Location, attrs.StorageClass,
				uniformACL, versioning, publicPrevention,
			})

			objectCount := 0
			if countObjects {
				objIt := client.Bucket(attrs.Name).Objects(context.Background(), nil)
				for {
					_, err := objIt.Next()
					if err == iterator.Done {
						break
					}
					if err != nil {
						break
					}
					objectCount++
				}
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "storage",
				ResourceType: "bucket",
				Project:      project,
				Name:         attrs.Name,
				Data: map[string]any{
					"name":              attrs.Name,
					"location":          attrs.Location,
					"storage_class":     attrs.StorageClass,
					"created":           attrs.Created.String(),
					"versioning":        attrs.VersioningEnabled,
					"uniform_acl":       attrs.UniformBucketLevelAccess.Enabled,
					"public_prevention": string(attrs.PublicAccessPrevention),
					"object_count":      objectCount,
				},
			}); err != nil {
				output.Error("Save bucket %s: %v", attrs.Name, err)
			}

			// Flag buckets without public access prevention.
			if publicPrevention != "enforced" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.storage.probe-buckets",
					Severity:    module.SevMedium,
					Title:       "Public access prevention not enforced",
					Description: fmt.Sprintf("Bucket %s does not enforce public access prevention (current: %s)", attrs.Name, publicPrevention),
					Resource:    attrs.Name,
					Project:     project,
				}
			}

			// Flag buckets without versioning.
			if !attrs.VersioningEnabled && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.storage.probe-buckets",
					Severity:    module.SevLow,
					Title:       "Bucket versioning disabled",
					Description: fmt.Sprintf("Bucket %s has versioning disabled — objects can be permanently deleted", attrs.Name),
					Resource:    attrs.Name,
					Project:     project,
				}
			}
		}

		if bucketCount == 0 {
			output.Info("No buckets found in %s", project)
		} else {
			output.Success("Found %d buckets in %s", bucketCount, project)
			output.Table(headers, rows)
		}
	}
	return nil
}
