package storage

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&BruteforceBuckets{})
}

// BruteforceBuckets probes for publicly accessible GCS buckets via unauthenticated HTTP.
type BruteforceBuckets struct{}

func (m *BruteforceBuckets) Info() module.Info {
	return module.Info{
		Name:         "initial-access.storage.bruteforce-buckets",
		Tactic:       module.TacticInitialAccess,
		Service:      "storage",
		Description:  "Brute-force GCS bucket names to find publicly accessible buckets",
		RequiresAuth: false,
	}
}

func (m *BruteforceBuckets) Run(ctx module.RunContext) error {
	keyword := ctx.Flags["keyword"]
	if keyword == "" {
		output.Warn("Usage: run initial-access.storage.bruteforce-buckets --keyword <company-name>")
		output.Info("Will try variations like: <keyword>, <keyword>-dev, <keyword>-prod, <keyword>-backup, etc.")
		return nil
	}

	suffixes := []string{
		"", "-dev", "-staging", "-prod", "-production", "-backup", "-backups",
		"-data", "-logs", "-assets", "-static", "-uploads", "-files",
		"-public", "-private", "-internal", "-test", "-testing",
		"-config", "-configs", "-secrets", "-keys", "-certs",
		"-db", "-database", "-dumps", "-export", "-imports",
		"-media", "-images", "-documents", "-archive",
	}

	prefixes := []string{"", "gcp-", "gcs-", "gs-"}

	var candidates []string
	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			candidates = append(candidates, prefix+keyword+suffix)
		}
	}

	output.Info("Probing %d bucket name variations for '%s'...", len(candidates), keyword)

	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Max 10 concurrent requests.

	for _, name := range candidates {
		wg.Add(1)
		sem <- struct{}{}

		go func(bucketName string) {
			defer wg.Done()
			defer func() { <-sem }()

			status := probeBucket(ctx.Ctx, bucketName)
			if status != "" {
				mu.Lock()
				found = append(found, bucketName)
				mu.Unlock()

				output.Success("Found: gs://%s (%s)", bucketName, status)

				if ctx.Store != nil {
					ctx.Store.SaveResource(&db.Resource{
						WorkspaceID:  ctx.Workspace,
						Service:      "storage",
						ResourceType: "bucket_public",
						Name:         bucketName,
						Data: map[string]any{
							"name":   bucketName,
							"status": status,
							"method": "bruteforce",
						},
					})
				}

				if ctx.Findings != nil {
					sev := module.SevMedium
					if strings.Contains(status, "listable") {
						sev = module.SevHigh
					}
					ctx.Findings <- module.Finding{
						Module:      "initial-access.storage.bruteforce-buckets",
						Severity:    sev,
						Title:       "Publicly accessible bucket found",
						Description: fmt.Sprintf("Bucket gs://%s is %s", bucketName, status),
						Resource:    bucketName,
					}
				}
			}
		}(name)
	}

	wg.Wait()

	if len(found) == 0 {
		output.Info("No publicly accessible buckets found for '%s'", keyword)
	} else {
		output.Success("Found %d accessible buckets", len(found))
	}

	return nil
}

func probeBucket(ctx context.Context, name string) string {
	// Check if bucket exists and is listable.
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o?maxResults=1", name)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return "exists, listable"
	}

	// Check if bucket exists (even if not listable).
	url2 := fmt.Sprintf("https://storage.googleapis.com/%s", name)
	req2, _ := http.NewRequestWithContext(ctx, "HEAD", url2, nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		return ""
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 403 {
		return "exists, not public"
	}
	if resp2.StatusCode == 200 {
		return "exists, accessible"
	}

	return ""
}
