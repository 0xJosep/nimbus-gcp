package workloadidentity

import (
	"context"
	"fmt"
	"strings"

	iam "google.golang.org/api/iam/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanBindings{})
}

// ScanBindings scans IAM bindings on service accounts to find Workload Identity
// Federation and GKE Workload Identity bindings.
type ScanBindings struct{}

func (m *ScanBindings) Info() module.Info {
	return module.Info{
		Name:         "recon.workloadidentity.scan-bindings",
		Tactic:       module.TacticRecon,
		Service:      "workloadidentity",
		Description:  "Scan SA IAM bindings for Workload Identity Federation and GKE Workload Identity",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

// knownExternalProviders maps provider substrings to friendly names.
var knownExternalProviders = map[string]string{
	"aws":    "AWS",
	"azure":  "Azure",
	"github": "GitHub",
	"gitlab": "GitLab",
}

func (m *ScanBindings) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := iam.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create IAM client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Workload Identity bindings in project: %s", project)

		// List all service accounts in the project.
		saResp, err := svc.Projects.ServiceAccounts.List(
			fmt.Sprintf("projects/%s", project),
		).PageSize(100).Do()
		if err != nil {
			output.Error("Project %s: list SAs: %v", project, err)
			continue
		}

		if len(saResp.Accounts) == 0 {
			output.Info("No service accounts found in %s", project)
			continue
		}

		headers := []string{"SA EMAIL", "MEMBER", "ROLE", "TYPE", "PROVIDER"}
		var rows [][]string
		bindingCount := 0

		for _, sa := range saResp.Accounts {
			// Get IAM policy for each SA.
			policy, err := svc.Projects.ServiceAccounts.GetIamPolicy(
				fmt.Sprintf("projects/%s/serviceAccounts/%s", project, sa.UniqueId),
			).Do()
			if err != nil {
				// Try with email format.
				policy, err = svc.Projects.ServiceAccounts.GetIamPolicy(
					fmt.Sprintf("projects/%s/serviceAccounts/%s", project, sa.Email),
				).Do()
				if err != nil {
					if ctx.Verbose {
						output.Error("SA %s: get IAM policy: %v", sa.Email, err)
					}
					continue
				}
			}

			if policy.Bindings == nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					bindingType := ""
					provider := ""

					// Check for Workload Identity Federation (principal:// or principalSet://).
					if strings.HasPrefix(member, "principal://") || strings.HasPrefix(member, "principalSet://") {
						bindingType = "WIF"
						provider = identifyProvider(member)
					} else if isGKEWorkloadIdentity(member) {
						// Check for GKE Workload Identity (serviceAccount:*.svc.id.goog[ns/sa]).
						bindingType = "GKE-WI"
						provider = "GKE"
					} else {
						continue
					}

					bindingCount++
					rows = append(rows, []string{
						sa.Email, member, binding.Role, bindingType, provider,
					})

					if err := ctx.Store.SaveResource(&db.Resource{
						WorkspaceID:  ctx.Workspace,
						Service:      "workloadidentity",
						ResourceType: "binding",
						Project:      project,
						Name:         fmt.Sprintf("%s:%s", sa.Email, member),
						Data: map[string]any{
							"sa_email":     sa.Email,
							"member":       member,
							"role":         binding.Role,
							"binding_type": bindingType,
							"provider":     provider,
						},
					}); err != nil {
						output.Error("Save binding for %s: %v", sa.Email, err)
					}

					// Flag external identity providers as HIGH.
					if bindingType == "WIF" && provider != "" && provider != "Unknown" {
						if ctx.Findings != nil {
							ctx.Findings <- module.Finding{
								Module:      "recon.workloadidentity.scan-bindings",
								Severity:    module.SevHigh,
								Title:       fmt.Sprintf("External %s identity bound to GCP SA", provider),
								Description: fmt.Sprintf("SA %s has WIF binding to external %s identity: %s (role: %s)", sa.Email, provider, member, binding.Role),
								Resource:    sa.Email,
								Project:     project,
								Data: map[string]any{
									"sa_email": sa.Email,
									"member":   member,
									"role":     binding.Role,
									"provider": provider,
								},
							}
						}
					}
				}
			}
		}

		if bindingCount == 0 {
			output.Info("No Workload Identity bindings found in %s", project)
			continue
		}

		output.Success("Found %d Workload Identity bindings in %s", bindingCount, project)
		output.Table(headers, rows)
	}
	return nil
}

// identifyProvider attempts to identify the external identity provider from a
// principal:// or principalSet:// member string.
func identifyProvider(member string) string {
	lower := strings.ToLower(member)
	for substring, name := range knownExternalProviders {
		if strings.Contains(lower, substring) {
			return name
		}
	}
	if strings.Contains(lower, "oidc") || strings.Contains(lower, "provider") {
		return "Unknown"
	}
	return "Unknown"
}

// isGKEWorkloadIdentity checks if a member matches the GKE Workload Identity
// pattern: serviceAccount:<project>.svc.id.goog[<namespace>/<sa>]
func isGKEWorkloadIdentity(member string) bool {
	if !strings.HasPrefix(member, "serviceAccount:") {
		return false
	}
	return strings.Contains(member, ".svc.id.goog[")
}
