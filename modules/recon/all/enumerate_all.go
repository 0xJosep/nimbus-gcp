package all

import (
	"fmt"
	"strings"
	"time"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EnumerateAll{})
}

// reconModules is the ordered list of recon modules to execute.
var reconModules = []string{
	"recon.resourcemanager.list-projects",
	"recon.iam.list-principals",
	"recon.iam.list-roles",
	"recon.iam.list-bindings",
	"recon.compute.scan-instances",
	"recon.network.map-vpcs",
	"recon.storage.probe-buckets",
	"recon.functions.scan-functions",
	"recon.run.scan-services",
	"recon.gke.scan-clusters",
	"recon.secrets.scan-secrets",
	"recon.bigquery.scan-datasets",
	"recon.cloudsql.scan-instances",
	"recon.logging.scan-sinks",
	"recon.dns.scan-zones",
}

// EnumerateAll runs every recon module sequentially against target projects.
type EnumerateAll struct{}

func (m *EnumerateAll) Info() module.Info {
	return module.Info{
		Name:         "recon.all",
		Tactic:       module.TacticRecon,
		Service:      "all",
		Description:  "Run all recon modules against target projects (full enumeration)",
		RequiresAuth: true,
		Concurrent:   false,
	}
}

func (m *EnumerateAll) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	registry := module.DefaultRegistry()
	total := len(reconModules)
	succeeded := 0
	failed := 0
	skipped := 0
	var allFindings []module.Finding
	start := time.Now()

	output.Info("Starting full enumeration across %d modules on %d project(s)",
		total, len(ctx.Projects))
	output.Info("Projects: %s", strings.Join(ctx.Projects, ", "))
	fmt.Println()

	for i, modName := range reconModules {
		mod, ok := registry.Get(modName)
		if !ok {
			output.Warn("[%d/%d] Module not found: %s (skipping)", i+1, total, modName)
			skipped++
			continue
		}

		info := mod.Info()
		fmt.Printf("  %s[%d/%d]%s %s%s%s — %s\n",
			output.Cyan, i+1, total, output.Reset,
			output.Bold, info.Name, output.Reset,
			info.Description)

		// Collect findings via channel.
		findingsCh := make(chan module.Finding, 100)
		var stepFindings []module.Finding
		done := make(chan struct{})
		go func() {
			for f := range findingsCh {
				stepFindings = append(stepFindings, f)
			}
			close(done)
		}()

		stepCtx := module.RunContext{
			Ctx:         ctx.Ctx,
			Session:     ctx.Session,
			Store:       ctx.Store,
			Workspace:   ctx.Workspace,
			Projects:    ctx.Projects,
			Flags:       ctx.Flags,
			Verbose:     ctx.Verbose,
			Concurrency: ctx.Concurrency,
			Findings:    findingsCh,
		}

		err := mod.Run(stepCtx)
		close(findingsCh)
		<-done

		allFindings = append(allFindings, stepFindings...)

		if err != nil {
			output.Error("    %v", err)
			failed++
		} else {
			succeeded++
			if len(stepFindings) > 0 {
				output.Success("    %d finding(s)", len(stepFindings))
			}
		}
		fmt.Println()
	}

	elapsed := time.Since(start)

	// Forward all findings to the parent context.
	if ctx.Findings != nil {
		for _, f := range allFindings {
			ctx.Findings <- f
		}
	}

	// Print summary.
	fmt.Println(strings.Repeat("-", 60))
	output.Success("Full enumeration complete in %s", elapsed.Round(time.Second))
	fmt.Printf("  Modules:  %s%d succeeded%s", output.Green, succeeded, output.Reset)
	if failed > 0 {
		fmt.Printf(", %s%d failed%s", output.Red, failed, output.Reset)
	}
	if skipped > 0 {
		fmt.Printf(", %s%d skipped%s", output.Yellow, skipped, output.Reset)
	}
	fmt.Println()
	fmt.Printf("  Findings: %d total\n", len(allFindings))
	fmt.Printf("  Projects: %s\n", strings.Join(ctx.Projects, ", "))

	// Severity breakdown.
	sevCounts := map[string]int{}
	for _, f := range allFindings {
		sevCounts[string(f.Severity)]++
	}
	if len(sevCounts) > 0 {
		fmt.Print("  Severity: ")
		first := true
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if c, ok := sevCounts[sev]; ok {
				if !first {
					fmt.Print(", ")
				}
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
				fmt.Printf("%s%d %s%s", color, c, sev, output.Reset)
				first = false
			}
		}
		fmt.Println()
	}
	fmt.Println()

	output.Info("Run 'findings' to see all findings, 'paths' to analyze attack paths.")

	return nil
}
