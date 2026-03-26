package resourcemanager

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ListProjects{})
}

// ListProjects discovers all accessible GCP projects.
type ListProjects struct{}

func (m *ListProjects) Info() module.Info {
	return module.Info{
		Name:         "recon.resourcemanager.list-projects",
		Tactic:       module.TacticRecon,
		Service:      "resourcemanager",
		Description:  "Discover all accessible GCP projects in the organization",
		RequiresAuth: true,
	}
}

func (m *ListProjects) Run(ctx module.RunContext) error {
	svc, err := cloudresourcemanager.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create resource manager client: %w", err)
	}

	output.Info("Discovering accessible projects...")

	var allProjects []*cloudresourcemanager.Project
	err = svc.Projects.List().Pages(context.Background(),
		func(page *cloudresourcemanager.ListProjectsResponse) error {
			allProjects = append(allProjects, page.Projects...)
			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("list projects: %w", err)
	}

	if len(allProjects) == 0 {
		output.Info("No accessible projects found.")
		return nil
	}

	headers := []string{"PROJECT ID", "NAME", "STATE", "NUMBER", "PARENT"}
	var rows [][]string

	for _, proj := range allProjects {
		parent := ""
		if proj.Parent != nil {
			parent = fmt.Sprintf("%s/%s", proj.Parent.Type, proj.Parent.Id)
		}

		rows = append(rows, []string{
			proj.ProjectId, proj.Name, proj.LifecycleState,
			fmt.Sprintf("%d", proj.ProjectNumber), parent,
		})

		if err := ctx.Store.SaveResource(&db.Resource{
			WorkspaceID:  ctx.Workspace,
			Service:      "resourcemanager",
			ResourceType: "project",
			Project:      proj.ProjectId,
			Name:         proj.ProjectId,
			Data: map[string]any{
				"project_id":     proj.ProjectId,
				"name":           proj.Name,
				"state":          proj.LifecycleState,
				"project_number": proj.ProjectNumber,
				"parent":         parent,
				"labels":         proj.Labels,
				"create_time":    proj.CreateTime,
			},
		}); err != nil {
			output.Error("Save project %s: %v", proj.ProjectId, err)
		}
	}

	output.Success("Discovered %d accessible projects", len(allProjects))
	output.Table(headers, rows)
	return nil
}
