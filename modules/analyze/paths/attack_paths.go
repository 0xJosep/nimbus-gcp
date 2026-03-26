package paths

import (
	"fmt"
	"strings"

	"github.com/user/nimbus/internal/graph"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&AttackPaths{})
}

// AttackPaths builds an attack graph and finds privilege escalation chains.
type AttackPaths struct{}

func (m *AttackPaths) Info() module.Info {
	return module.Info{
		Name:         "analyze.paths.attack-paths",
		Tactic:       module.TacticAnalyze,
		Service:      "analysis",
		Description:  "Build attack graph and discover privilege escalation chains",
		RequiresAuth: false,
	}
}

func (m *AttackPaths) Run(ctx module.RunContext) error {
	output.Info("Building attack graph from collected data...")

	builder := graph.NewBuilder(ctx.Store, ctx.Workspace)
	g, err := builder.Build()
	if err != nil {
		return fmt.Errorf("build graph: %w", err)
	}

	stats := g.Stats()
	output.Info("Graph constructed: %d nodes, %d edges", stats["nodes"], stats["edges"])

	if stats["nodes"] == 0 {
		output.Warn("No data to analyze. Run recon modules first.")
		output.Info("Recommended: recon.iam.list-principals, recon.iam.list-bindings, recon.compute.scan-instances")
		return nil
	}

	// Show node breakdown.
	fmt.Println()
	for _, ntype := range []string{"identity", "role", "resource"} {
		key := fmt.Sprintf("nodes_%s", ntype)
		if c, ok := stats[key]; ok {
			output.Info("  %s nodes: %d", ntype, c)
		}
	}
	fmt.Println()

	// Annotate with privesc techniques.
	analyzer := graph.NewAnalyzer(g)
	matches := analyzer.AnnotateEscalations()

	if len(matches) == 0 {
		output.Success("No known privilege escalation paths detected.")
		if ctx.Findings != nil {
			ctx.Findings <- module.Finding{
				Module:      "analyze.paths.attack-paths",
				Severity:    module.SevInfo,
				Title:       "No escalation paths found",
				Description: "Analysis of collected IAM data found no known privilege escalation techniques available",
			}
		}
		return nil
	}

	output.Warn("Discovered %d potential escalation technique(s)!", len(matches))
	fmt.Println()

	for _, match := range matches {
		color := output.Yellow
		sev := module.SevMedium
		switch match.Technique.Severity {
		case "CRITICAL":
			color = output.Red + output.Bold
			sev = module.SevCritical
		case "HIGH":
			color = output.Red
			sev = module.SevHigh
		}

		fmt.Printf("  %s[%s] %s (%s)%s\n",
			color, match.Technique.ID, match.Technique.Name, match.Technique.Severity, output.Reset)
		fmt.Printf("    %s\n", match.Technique.Description)
		fmt.Printf("    Permissions: %s\n", strings.Join(match.MatchedPerms, ", "))
		if match.Technique.Reference != "" {
			fmt.Printf("    Reference: %s\n", match.Technique.Reference)
		}
		fmt.Println()

		if ctx.Findings != nil {
			ctx.Findings <- module.Finding{
				Module:      "analyze.paths.attack-paths",
				Severity:    sev,
				Title:       fmt.Sprintf("Escalation: %s", match.Technique.Name),
				Description: match.Technique.Description,
				Data: map[string]any{
					"technique_id": match.Technique.ID,
					"permissions":  match.MatchedPerms,
					"reference":    match.Technique.Reference,
				},
			}
		}
	}

	// Find and display escalation paths.
	escalationPaths := g.FindEscalationPaths(6)
	if len(escalationPaths) > 0 {
		output.Warn("Escalation paths:")
		for i, p := range escalationPaths {
			if i >= 20 {
				output.Info("  ... and %d more paths (use --verbose to show all)", len(escalationPaths)-20)
				break
			}
			fmt.Printf("  [%d] %s\n", i+1, p.String())
		}
		fmt.Println()
	}

	return nil
}
