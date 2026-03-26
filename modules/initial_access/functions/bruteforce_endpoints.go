package functions

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
	module.Register(&BruteforceEndpoints{})
}

// BruteforceEndpoints probes for publicly accessible Cloud Function HTTP endpoints.
type BruteforceEndpoints struct{}

func (m *BruteforceEndpoints) Info() module.Info {
	return module.Info{
		Name:         "initial-access.functions.bruteforce-endpoints",
		Tactic:       module.TacticInitialAccess,
		Service:      "cloudfunctions",
		Description:  "Brute-force Cloud Function HTTP endpoints to find unauthenticated functions",
		RequiresAuth: false,
	}
}

func (m *BruteforceEndpoints) Run(ctx module.RunContext) error {
	project := ctx.Flags["project"]
	region := ctx.Flags["region"]
	wordlist := ctx.Flags["wordlist"]

	if project == "" {
		if len(ctx.Projects) > 0 {
			project = ctx.Projects[0]
		} else {
			output.Warn("Usage: run initial-access.functions.bruteforce-endpoints --project <project-id> [--region <region>] [--wordlist <comma-separated>]")
			return nil
		}
	}

	regions := []string{"us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1"}
	if region != "" {
		regions = []string{region}
	}

	// Default function name candidates.
	names := []string{
		"api", "webhook", "handler", "process", "function",
		"auth", "login", "callback", "hook", "notify",
		"upload", "download", "export", "import", "sync",
		"health", "healthcheck", "status", "ping", "test",
		"admin", "debug", "internal", "proxy", "gateway",
		"create", "update", "delete", "get", "list",
		"data", "fetch", "submit", "validate", "verify",
		"email", "send", "receive", "push", "pull",
		"cron", "scheduler", "trigger", "event", "worker",
	}

	if wordlist != "" {
		names = strings.Split(wordlist, ",")
		for i, n := range names {
			names[i] = strings.TrimSpace(n)
		}
	}

	totalProbes := len(regions) * len(names)
	output.Info("Probing %d endpoints (%d regions x %d names) for project '%s'...", totalProbes, len(regions), len(names), project)

	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 15)

	for _, r := range regions {
		for _, name := range names {
			wg.Add(1)
			sem <- struct{}{}

			go func(region, funcName string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Gen 1 URL format.
				url := fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", region, project, funcName)
				status, body := probeEndpoint(ctx.Ctx, url)

				if status > 0 && status != 404 && status != 403 {
					mu.Lock()
					found = append(found, url)
					mu.Unlock()

					statusColor := output.Green
					if status >= 400 {
						statusColor = output.Yellow
					}
					fmt.Printf("  %s[%d]%s %s", statusColor, status, output.Reset, url)
					if status == 200 && len(body) > 0 {
						preview := body
						if len(preview) > 80 {
							preview = preview[:80] + "..."
						}
						fmt.Printf(" -> %s", preview)
					}
					fmt.Println()

					if ctx.Store != nil {
						ctx.Store.SaveResource(&db.Resource{
							WorkspaceID:  ctx.Workspace,
							Service:      "cloudfunctions",
							ResourceType: "endpoint_public",
							Project:      project,
							Name:         funcName,
							Data: map[string]any{
								"url":        url,
								"status":     status,
								"region":     region,
								"project":    project,
								"function":   funcName,
								"accessible": status == 200,
							},
						})
					}

					if ctx.Findings != nil {
						sev := module.SevMedium
						if status == 200 {
							sev = module.SevHigh
						}
						ctx.Findings <- module.Finding{
							Module:      "initial-access.functions.bruteforce-endpoints",
							Severity:    sev,
							Title:       fmt.Sprintf("Cloud Function endpoint responds (HTTP %d)", status),
							Description: fmt.Sprintf("Function %s at %s returned HTTP %d", funcName, url, status),
							Resource:    url,
							Project:     project,
						}
					}
				}
			}(r, name)
		}
	}

	wg.Wait()

	if len(found) == 0 {
		output.Info("No accessible endpoints found for project '%s'", project)
	} else {
		output.Success("Found %d accessible endpoint(s)", len(found))
	}

	return nil
}

func probeEndpoint(ctx context.Context, url string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, ""
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()

	// Read a small preview of the body.
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	return resp.StatusCode, body
}
