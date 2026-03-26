package scheduler

import (
	"context"
	"fmt"
	"net"
	"strings"

	cloudscheduler "google.golang.org/api/cloudscheduler/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanJobs{})
}

// ScanJobs discovers Cloud Scheduler jobs and flags insecure configurations.
type ScanJobs struct{}

func (m *ScanJobs) Info() module.Info {
	return module.Info{
		Name:         "recon.scheduler.scan-jobs",
		Tactic:       module.TacticRecon,
		Service:      "cloudscheduler",
		Description:  "List Cloud Scheduler jobs, flag HTTP targets and internal IP targeting",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1053",
	}
}

// schedulerLocations is the set of common regions to scan for scheduler jobs.
var schedulerLocations = []string{
	"us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
	"europe-west1", "europe-west2", "europe-west4",
	"asia-east1", "asia-northeast1", "asia-southeast1",
	"australia-southeast1",
}

func (m *ScanJobs) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := cloudscheduler.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create cloudscheduler client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Cloud Scheduler jobs in project: %s", project)

		headers := []string{"NAME", "SCHEDULE", "TARGET TYPE", "STATE", "TARGET"}
		var rows [][]string
		jobCount := 0

		for _, location := range schedulerLocations {
			parent := fmt.Sprintf("projects/%s/locations/%s", project, location)

			err := svc.Projects.Locations.Jobs.List(parent).Pages(context.Background(),
				func(resp *cloudscheduler.ListJobsResponse) error {
					for _, job := range resp.Jobs {
						jobCount++

						targetType := "unknown"
						targetURI := ""

						if job.HttpTarget != nil {
							targetType = "HTTP"
							targetURI = job.HttpTarget.Uri
						} else if job.PubsubTarget != nil {
							targetType = "Pub/Sub"
							targetURI = job.PubsubTarget.TopicName
						} else if job.AppEngineHttpTarget != nil {
							targetType = "App Engine"
							targetURI = job.AppEngineHttpTarget.RelativeUri
						}

						shortJobName := lastPathSegment(job.Name)

						rows = append(rows, []string{
							shortJobName, job.Schedule, targetType, job.State, targetURI,
						})

						data := map[string]any{
							"name":        job.Name,
							"schedule":    job.Schedule,
							"target_type": targetType,
							"target_uri":  targetURI,
							"state":       job.State,
							"timezone":    job.TimeZone,
						}

						if err := ctx.Store.SaveResource(&db.Resource{
							WorkspaceID:  ctx.Workspace,
							Service:      "cloudscheduler",
							ResourceType: "job",
							Project:      project,
							Name:         job.Name,
							Data:         data,
						}); err != nil {
							output.Error("Save job %s: %v", job.Name, err)
						}

						// Flag HTTP targets as MEDIUM.
						if job.HttpTarget != nil && ctx.Findings != nil {
							ctx.Findings <- module.Finding{
								Module:      "recon.scheduler.scan-jobs",
								Severity:    module.SevMedium,
								Title:       "Scheduler job with HTTP target",
								Description: fmt.Sprintf("Job %s targets HTTP endpoint: %s", job.Name, job.HttpTarget.Uri),
								Resource:    job.Name,
								Project:     project,
							}

							// Flag jobs targeting internal IPs as HIGH.
							if isInternalTarget(job.HttpTarget.Uri) && ctx.Findings != nil {
								ctx.Findings <- module.Finding{
									Module:      "recon.scheduler.scan-jobs",
									Severity:    module.SevHigh,
									Title:       "Scheduler job targeting internal IP",
									Description: fmt.Sprintf("Job %s targets internal/private IP: %s", job.Name, job.HttpTarget.Uri),
									Resource:    job.Name,
									Project:     project,
								}
							}
						}
					}
					return nil
				},
			)
			if err != nil {
				// Silently skip locations with no scheduler resources or permission errors.
				continue
			}
		}

		if jobCount == 0 {
			output.Info("No scheduler jobs found in %s", project)
		} else {
			output.Success("Found %d scheduler jobs in %s", jobCount, project)
			output.Table(headers, rows)
		}
	}
	return nil
}

// lastPathSegment returns the last segment of a slash-separated path.
func lastPathSegment(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

// isInternalTarget checks if a URI targets an internal/private IP address.
func isInternalTarget(uri string) bool {
	// Extract host from URI.
	host := uri
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.IndexAny(host, ":/"); idx != -1 {
		host = host[:idx]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Check for metadata server or common internal hostnames.
		return strings.Contains(host, "metadata.google.internal") ||
			strings.Contains(host, "localhost") ||
			host == "127.0.0.1"
	}

	// RFC 1918 and link-local ranges.
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
