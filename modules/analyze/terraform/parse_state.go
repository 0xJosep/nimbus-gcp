package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"cloud.google.com/go/storage"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ParseState{})
}

// ParseState parses Terraform state files to extract secrets, service accounts,
// and infrastructure layout from .tfstate JSON.
type ParseState struct{}

func (m *ParseState) Info() module.Info {
	return module.Info{
		Name:         "analyze.terraform.parse-state",
		Tactic:       module.TacticAnalyze,
		Service:      "terraform",
		Description:  "Parse Terraform state files to extract secrets and infrastructure layout",
		RequiresAuth: false,
	}
}

// tfState represents the top-level Terraform state file structure.
type tfState struct {
	Version   int          `json:"version"`
	Serial    int          `json:"serial"`
	Lineage   string       `json:"lineage"`
	Resources []tfResource `json:"resources"`
}

// tfResource represents a single resource block in Terraform state.
type tfResource struct {
	Mode      string       `json:"mode"`
	Type      string       `json:"type"`
	Name      string       `json:"name"`
	Provider  string       `json:"provider"`
	Instances []tfInstance `json:"instances"`
}

// tfInstance represents an instance of a resource.
type tfInstance struct {
	Attributes map[string]any `json:"attributes"`
}

// secretHit tracks a discovered secret or sensitive value.
type secretHit struct {
	ResourceType string
	ResourceName string
	AttrPath     string
	Severity     module.Severity
}

// resourceCount tracks per-type resource counts and secret counts for the summary.
type resourceCount struct {
	Count   int
	Secrets int
}

func (m *ParseState) Run(ctx module.RunContext) error {
	filePath := ctx.Flags["file"]
	bucket := ctx.Flags["bucket"]
	object := ctx.Flags["object"]

	if filePath == "" && bucket == "" {
		return fmt.Errorf("provide --file (local path) or --bucket + --object (GCS location)")
	}

	var data []byte
	var err error

	if bucket != "" {
		// Download from GCS.
		if object == "" {
			return fmt.Errorf("--object is required when using --bucket")
		}
		if ctx.Session == nil || !ctx.Session.IsAuthenticated() {
			return fmt.Errorf("authentication required to download from GCS")
		}
		output.Info("Downloading gs://%s/%s ...", bucket, object)
		data, err = downloadFromGCS(ctx, bucket, object)
		if err != nil {
			return fmt.Errorf("download from GCS: %w", err)
		}
		output.Success("Downloaded %d bytes from GCS", len(data))
	} else {
		// Read local file.
		output.Info("Reading local file: %s", filePath)
		data, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
	}

	// Parse the tfstate JSON.
	var state tfState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse tfstate JSON: %w", err)
	}

	output.Info("Terraform state version %d, serial %d, %d resource(s)", state.Version, state.Serial, len(state.Resources))

	if len(state.Resources) == 0 {
		output.Warn("No resources found in state file.")
		return nil
	}

	var secrets []secretHit
	counts := make(map[string]*resourceCount)

	for _, res := range state.Resources {
		// Track count per resource type.
		if counts[res.Type] == nil {
			counts[res.Type] = &resourceCount{}
		}
		counts[res.Type].Count++

		for _, inst := range res.Instances {
			attrs := inst.Attributes
			if attrs == nil {
				continue
			}

			// Check for critical secret patterns.
			hits := checkSecrets(res.Type, res.Name, attrs)
			secrets = append(secrets, hits...)
			counts[res.Type].Secrets += len(hits)

			// Save recognized resource types to the DB.
			switch res.Type {
			case "google_compute_instance":
				saveComputeInstance(ctx, res, attrs)
			case "google_storage_bucket":
				saveStorageBucket(ctx, res, attrs)
			case "google_project_iam_member", "google_project_iam_binding":
				saveIAMBinding(ctx, res, attrs)
			case "google_service_account":
				saveServiceAccount(ctx, res, attrs)
			}
		}
	}

	// Print secrets found.
	if len(secrets) > 0 {
		output.Warn("Found %d sensitive value(s) in state!", len(secrets))
		fmt.Println()
		for _, s := range secrets {
			color := output.Yellow
			if s.Severity == module.SevCritical {
				color = output.Red + output.Bold
			} else if s.Severity == module.SevHigh {
				color = output.Red
			}
			fmt.Printf("  %s[%s]%s %s.%s -> %s\n",
				color, string(s.Severity), output.Reset,
				s.ResourceType, s.ResourceName, s.AttrPath)

			// Emit finding.
			if ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:   "analyze.terraform.parse-state",
					Severity: s.Severity,
					Title:    fmt.Sprintf("Secret in tfstate: %s", s.AttrPath),
					Description: fmt.Sprintf("Terraform state contains sensitive value at %s.%s attribute %s",
						s.ResourceType, s.ResourceName, s.AttrPath),
					Resource: fmt.Sprintf("%s.%s", s.ResourceType, s.ResourceName),
				}
			}
		}
		fmt.Println()
	} else {
		output.Success("No embedded secrets detected in state file.")
	}

	// Print summary table.
	headers := []string{"RESOURCE TYPE", "COUNT", "SECRETS FOUND"}
	var rows [][]string
	for rtype, rc := range counts {
		secretStr := fmt.Sprintf("%d", rc.Secrets)
		if rc.Secrets > 0 {
			secretStr = fmt.Sprintf("%s%d%s", output.Red, rc.Secrets, output.Reset)
		}
		rows = append(rows, []string{rtype, fmt.Sprintf("%d", rc.Count), secretStr})
	}
	output.Table(headers, rows)

	output.Success("Parsed %d resource type(s), %d total resource(s), %d secret(s) flagged",
		len(counts), len(state.Resources), len(secrets))

	return nil
}

// downloadFromGCS fetches an object from Google Cloud Storage.
func downloadFromGCS(ctx module.RunContext, bucket, object string) ([]byte, error) {
	client, err := storage.NewClient(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	defer client.Close()

	reader, err := client.Bucket(bucket).Object(object).NewReader(context.Background())
	if err != nil {
		return nil, fmt.Errorf("read object gs://%s/%s: %w", bucket, object, err)
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// checkSecrets inspects resource attributes for sensitive values.
func checkSecrets(resType, resName string, attrs map[string]any) []secretHit {
	var hits []secretHit

	// Critical: known secret-bearing resource types.
	if resType == "google_service_account_key" {
		if _, ok := attrs["private_key"]; ok {
			hits = append(hits, secretHit{
				ResourceType: resType,
				ResourceName: resName,
				AttrPath:     "private_key",
				Severity:     module.SevCritical,
			})
		}
	}

	if resType == "google_secret_manager_secret_version" {
		if _, ok := attrs["secret_data"]; ok {
			hits = append(hits, secretHit{
				ResourceType: resType,
				ResourceName: resName,
				AttrPath:     "secret_data",
				Severity:     module.SevCritical,
			})
		}
	}

	// High: scan all attributes for sensitive-looking keys.
	sensitiveKeys := []string{"password", "secret", "api_key", "private_key", "token"}
	for attrKey, attrVal := range attrs {
		// Skip the ones we already flagged as critical.
		if resType == "google_service_account_key" && attrKey == "private_key" {
			continue
		}
		if resType == "google_secret_manager_secret_version" && attrKey == "secret_data" {
			continue
		}

		lower := strings.ToLower(attrKey)
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(lower, sensitive) {
				// Only flag if the value is non-empty.
				if valStr, ok := attrVal.(string); ok && valStr != "" {
					hits = append(hits, secretHit{
						ResourceType: resType,
						ResourceName: resName,
						AttrPath:     attrKey,
						Severity:     module.SevHigh,
					})
					break
				}
			}
		}
	}

	return hits
}

// saveComputeInstance saves a google_compute_instance to the DB.
func saveComputeInstance(ctx module.RunContext, res tfResource, attrs map[string]any) {
	name := attrString(attrs, "name")
	if name == "" {
		name = res.Name
	}

	project := attrString(attrs, "project")
	zone := attrString(attrs, "zone")

	// Extract service account email from nested structure.
	var saEmail string
	if saList, ok := attrs["service_account"].([]any); ok && len(saList) > 0 {
		if saMap, ok := saList[0].(map[string]any); ok {
			saEmail = attrString(saMap, "email")
		}
	}

	// Extract network IPs.
	var externalIP string
	if niList, ok := attrs["network_interface"].([]any); ok && len(niList) > 0 {
		if niMap, ok := niList[0].(map[string]any); ok {
			if acList, ok := niMap["access_config"].([]any); ok && len(acList) > 0 {
				if acMap, ok := acList[0].(map[string]any); ok {
					externalIP = attrString(acMap, "nat_ip")
				}
			}
		}
	}

	_ = ctx.Store.SaveResource(&db.Resource{
		WorkspaceID:  ctx.Workspace,
		Service:      "compute",
		ResourceType: "instance",
		Project:      project,
		Name:         name,
		Data: map[string]any{
			"name":            name,
			"zone":            zone,
			"service_account": saEmail,
			"external_ip":     externalIP,
			"source":          "terraform",
		},
	})
}

// saveStorageBucket saves a google_storage_bucket to the DB.
func saveStorageBucket(ctx module.RunContext, res tfResource, attrs map[string]any) {
	name := attrString(attrs, "name")
	if name == "" {
		name = res.Name
	}
	project := attrString(attrs, "project")
	location := attrString(attrs, "location")

	_ = ctx.Store.SaveResource(&db.Resource{
		WorkspaceID:  ctx.Workspace,
		Service:      "storage",
		ResourceType: "bucket",
		Project:      project,
		Name:         name,
		Data: map[string]any{
			"name":     name,
			"location": location,
			"source":   "terraform",
		},
	})
}

// saveIAMBinding saves a google_project_iam_member or binding to the DB.
func saveIAMBinding(ctx module.RunContext, res tfResource, attrs map[string]any) {
	role := attrString(attrs, "role")
	project := attrString(attrs, "project")
	member := attrString(attrs, "member")

	name := fmt.Sprintf("%s/%s/%s", project, role, member)
	if member == "" {
		// For bindings, members is a list.
		name = fmt.Sprintf("%s/%s/%s", project, role, res.Name)
	}

	data := map[string]any{
		"role":    role,
		"project": project,
		"source":  "terraform",
	}
	if member != "" {
		data["member"] = member
	}
	if members, ok := attrs["members"].([]any); ok {
		var memberStrs []string
		for _, m := range members {
			if s, ok := m.(string); ok {
				memberStrs = append(memberStrs, s)
			}
		}
		data["members"] = memberStrs
	}

	_ = ctx.Store.SaveResource(&db.Resource{
		WorkspaceID:  ctx.Workspace,
		Service:      "iam",
		ResourceType: "role_binding",
		Project:      project,
		Name:         name,
		Data:         data,
	})
}

// saveServiceAccount saves a google_service_account to the DB.
func saveServiceAccount(ctx module.RunContext, res tfResource, attrs map[string]any) {
	email := attrString(attrs, "email")
	if email == "" {
		email = attrString(attrs, "account_id")
	}
	project := attrString(attrs, "project")
	displayName := attrString(attrs, "display_name")

	name := email
	if name == "" {
		name = res.Name
	}

	_ = ctx.Store.SaveResource(&db.Resource{
		WorkspaceID:  ctx.Workspace,
		Service:      "iam",
		ResourceType: "service_account",
		Project:      project,
		Name:         name,
		Data: map[string]any{
			"email":        email,
			"display_name": displayName,
			"project":      project,
			"source":       "terraform",
		},
	})
}

// attrString safely extracts a string value from an attributes map.
func attrString(attrs map[string]any, key string) string {
	if v, ok := attrs[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
