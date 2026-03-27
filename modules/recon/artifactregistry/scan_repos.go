package artifactregistry

import (
	"context"
	"fmt"
	"strings"

	ar "google.golang.org/api/artifactregistry/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanRepos{})
}

// ScanRepos lists Artifact Registry repositories and their packages/images.
type ScanRepos struct{}

func (m *ScanRepos) Info() module.Info {
	return module.Info{
		Name:         "recon.artifactregistry.scan-repos",
		Tactic:       module.TacticRecon,
		Service:      "artifactregistry",
		Description:  "List Artifact Registry repos, packages, and flag public repos",
		RequiresAuth: true,
		Concurrent:   true,
	}
}

func (m *ScanRepos) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := ar.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create artifact registry client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Artifact Registry repositories in project: %s", project)

		// List repos across all locations.
		parent := fmt.Sprintf("projects/%s/locations/-", project)
		resp, err := svc.Projects.Locations.Repositories.List(parent).Do()
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		if len(resp.Repositories) == 0 {
			output.Info("No Artifact Registry repositories found in %s", project)
			continue
		}

		headers := []string{"NAME", "FORMAT", "LOCATION", "MODE", "SIZE", "PUBLIC"}
		var rows [][]string

		for _, repo := range resp.Repositories {
			// Extract short name and location from the full resource name.
			// Format: projects/{project}/locations/{location}/repositories/{repo}
			shortName := repo.Name
			location := ""
			parts := strings.Split(repo.Name, "/")
			if len(parts) >= 6 {
				shortName = parts[5]
				location = parts[3]
			}

			isPublic := "no"
			// Check IAM policy for allUsers / allAuthenticatedUsers.
			policy, err := svc.Projects.Locations.Repositories.GetIamPolicy(repo.Name).Do()
			if err == nil && policy.Bindings != nil {
				for _, binding := range policy.Bindings {
					for _, member := range binding.Members {
						if member == "allUsers" || member == "allAuthenticatedUsers" {
							isPublic = "yes"
							break
						}
					}
					if isPublic == "yes" {
						break
					}
				}
			}

			sizeBytes := fmt.Sprintf("%d", repo.SizeBytes)

			rows = append(rows, []string{
				shortName, repo.Format, location, repo.Mode, sizeBytes, isPublic,
			})

			repoData := map[string]any{
				"name":       shortName,
				"full_name":  repo.Name,
				"format":     repo.Format,
				"location":   location,
				"mode":       repo.Mode,
				"size_bytes": repo.SizeBytes,
				"public":     isPublic == "yes",
			}

			// For DOCKER repos, list packages (images).
			if repo.Format == "DOCKER" {
				packages, err := svc.Projects.Locations.Repositories.Packages.List(repo.Name).Do()
				if err == nil && len(packages.Packages) > 0 {
					var images []map[string]any
					for _, pkg := range packages.Packages {
						pkgName := pkg.Name
						pkgParts := strings.Split(pkg.Name, "/")
						if len(pkgParts) > 0 {
							pkgName = pkgParts[len(pkgParts)-1]
						}

						// List tags for this package.
						var tagNames []string
						tags, err := svc.Projects.Locations.Repositories.Packages.Tags.List(pkg.Name).Do()
						if err == nil {
							for _, tag := range tags.Tags {
								tagName := tag.Name
								tagParts := strings.Split(tag.Name, "/")
								if len(tagParts) > 0 {
									tagName = tagParts[len(tagParts)-1]
								}
								tagNames = append(tagNames, tagName)
							}
						}

						images = append(images, map[string]any{
							"name": pkgName,
							"tags": tagNames,
						})
					}
					repoData["images"] = images

					if ctx.Verbose {
						output.Info("  %s: %d Docker images", shortName, len(images))
						for _, img := range images {
							tags := img["tags"]
							output.Info("    - %s (tags: %v)", img["name"], tags)
						}
					}
				}
			}

			if err := ctx.Store.SaveResource(&db.Resource{
				WorkspaceID:  ctx.Workspace,
				Service:      "artifactregistry",
				ResourceType: "repository",
				Project:      project,
				Name:         shortName,
				Data:         repoData,
			}); err != nil {
				output.Error("Save repo %s: %v", shortName, err)
			}

			// Flag public repos.
			if isPublic == "yes" && ctx.Findings != nil {
				ctx.Findings <- module.Finding{
					Module:      "recon.artifactregistry.scan-repos",
					Severity:    module.SevHigh,
					Title:       "Public Artifact Registry repository",
					Description: fmt.Sprintf("Repository %s in %s is publicly accessible (allUsers or allAuthenticatedUsers)", shortName, project),
					Resource:    shortName,
					Project:     project,
					Data: map[string]any{
						"repo_name": shortName,
						"format":    repo.Format,
						"location":  location,
					},
				}
			}
		}

		output.Success("Found %d repositories in %s", len(resp.Repositories), project)
		output.Table(headers, rows)
	}
	return nil
}
