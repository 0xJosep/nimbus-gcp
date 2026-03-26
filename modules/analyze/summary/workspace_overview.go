package summary

import (
	"fmt"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&WorkspaceOverview{})
}

// WorkspaceOverview generates a summary of all collected data and findings.
type WorkspaceOverview struct{}

func (m *WorkspaceOverview) Info() module.Info {
	return module.Info{
		Name:         "analyze.summary.workspace-overview",
		Tactic:       module.TacticAnalyze,
		Service:      "analysis",
		Description:  "Generate a summary of all collected data and security findings",
		RequiresAuth: false,
	}
}

func (m *WorkspaceOverview) Run(ctx module.RunContext) error {
	output.Info("Generating workspace overview...")
	fmt.Println()

	// Resource counts.
	counts, err := ctx.Store.CountResources(ctx.Workspace)
	if err != nil {
		return fmt.Errorf("count resources: %w", err)
	}

	if len(counts) == 0 {
		output.Warn("No data collected yet. Run recon modules first.")
		return nil
	}

	fmt.Printf("  %s%sResource Inventory%s\n", output.Bold, output.Cyan, output.Reset)
	totalResources := 0
	headers := []string{"SERVICE", "COUNT"}
	var rows [][]string
	for svc, count := range counts {
		rows = append(rows, []string{svc, fmt.Sprintf("%d", count)})
		totalResources += count
	}
	output.Table(headers, rows)
	fmt.Printf("  Total resources: %d\n\n", totalResources)

	// Finding counts by severity.
	sevCounts, err := ctx.Store.CountFindingsBySeverity(ctx.Workspace)
	if err != nil {
		return fmt.Errorf("count findings: %w", err)
	}

	if len(sevCounts) > 0 {
		fmt.Printf("  %s%sSecurity Findings%s\n\n", output.Bold, output.Cyan, output.Reset)
		totalFindings := 0
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if c, ok := sevCounts[sev]; ok {
				color := output.Dim
				switch sev {
				case "CRITICAL":
					color = output.Red + output.Bold
				case "HIGH":
					color = output.Red
				case "MEDIUM":
					color = output.Yellow
				case "LOW":
					color = output.Blue
				}
				fmt.Printf("  %s%-10s%s %d\n", color, sev, output.Reset, c)
				totalFindings += c
			}
		}
		fmt.Printf("\n  Total findings: %d\n\n", totalFindings)
	} else {
		output.Info("No findings recorded. Run some modules to generate findings.")
	}

	// Granted permissions.
	if ctx.Session != nil {
		perms, err := ctx.Store.ListGrantedPermissions(ctx.Session.ID)
		if err == nil && len(perms) > 0 {
			fmt.Printf("  %s%sGranted Permissions%s\n\n", output.Bold, output.Cyan, output.Reset)
			fmt.Printf("  %d permissions confirmed for current session\n\n", len(perms))
		}
	}

	return nil
}
