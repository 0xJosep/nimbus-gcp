package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/graph"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
	"github.com/user/nimbus/internal/privesc"
)

func init() {
	module.Register(&FullAudit{})
}

const auditBanner = `
%s╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███╗   ██╗██╗███╗   ███╗██████╗ ██╗   ██╗███████╗         ║
║   ████╗  ██║██║████╗ ████║██╔══██╗██║   ██║██╔════╝         ║
║   ██╔██╗ ██║██║██╔████╔██║██████╔╝██║   ██║███████╗         ║
║   ██║╚██╗██║██║██║╚██╔╝██║██╔══██╗██║   ██║╚════██║         ║
║   ██║ ╚████║██║██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║         ║
║   ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝         ║
║                                                              ║
║              GCP Infrastructure Audit                        ║
║              Like linpeas, but for the cloud                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝%s
`

// Phases of the audit.
var auditPhases = []auditPhase{
	{
		name: "PROJECT DISCOVERY",
		icon: "🔍",
		modules: []string{
			"recon.resourcemanager.list-projects",
		},
	},
	{
		name: "IDENTITY & ACCESS",
		icon: "👤",
		modules: []string{
			"recon.iam.list-principals",
			"recon.iam.list-roles",
			"recon.iam.list-bindings",
			"recon.iam.bruteforce-permissions",
		},
	},
	{
		name: "COMPUTE & CONTAINERS",
		icon: "🖥️",
		modules: []string{
			"recon.compute.scan-instances",
			"recon.compute.scan-metadata",
			"recon.gke.scan-clusters",
			"recon.functions.scan-functions",
			"recon.run.scan-services",
		},
	},
	{
		name: "DATA STORES",
		icon: "💾",
		modules: []string{
			"recon.storage.probe-buckets",
			"recon.secrets.scan-secrets",
			"recon.bigquery.scan-datasets",
			"recon.cloudsql.scan-instances",
		},
	},
	{
		name: "NETWORKING & DNS",
		icon: "🌐",
		modules: []string{
			"recon.network.map-vpcs",
			"recon.dns.scan-zones",
		},
	},
	{
		name: "SECURITY CONTROLS",
		icon: "🛡️",
		modules: []string{
			"recon.logging.scan-sinks",
			"recon.kms.scan-keyrings",
			"recon.orgpolicy.scan-constraints",
		},
	},
	{
		name: "MESSAGING & SCHEDULING",
		icon: "📡",
		modules: []string{
			"recon.pubsub.scan-topics",
			"recon.scheduler.scan-jobs",
		},
	},
	{
		name: "PRIVILEGE ESCALATION ANALYSIS",
		icon: "⚡",
		modules: []string{
			"analyze.paths.attack-paths",
			"analyze.iam.delegation-chains",
		},
	},
	{
		name: "COMPLIANCE CHECK",
		icon: "📋",
		modules: []string{
			"analyze.compliance.cis-benchmark",
		},
	},
}

type auditPhase struct {
	name    string
	icon    string
	modules []string
}

// FullAudit runs a complete GCP infrastructure audit — like linpeas for the cloud.
type FullAudit struct{}

func (m *FullAudit) Info() module.Info {
	return module.Info{
		Name:         "analyze.audit.full-audit",
		Tactic:       module.TacticAnalyze,
		Service:      "all",
		Description:  "Full GCP infrastructure audit (linpeas-style) — enumerate, analyze, report",
		RequiresAuth: true,
		Concurrent:   false,
	}
}

func (m *FullAudit) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	fmt.Printf(auditBanner, output.Cyan+output.Bold, output.Reset)
	fmt.Println()

	start := time.Now()
	registry := module.DefaultRegistry()

	output.Info("Target project(s): %s", strings.Join(ctx.Projects, ", "))
	if ctx.Session != nil && ctx.Session.Email != "" {
		output.Info("Identity: %s", ctx.Session.Email)
	}
	fmt.Println()

	// Track stats.
	totalModules := 0
	succeededModules := 0
	failedModules := 0
	skippedModules := 0
	var allFindings []module.Finding

	for phaseIdx, phase := range auditPhases {
		printPhaseHeader(phaseIdx+1, len(auditPhases), phase)

		for _, modName := range phase.modules {
			totalModules++
			mod, ok := registry.Get(modName)
			if !ok {
				skippedModules++
				printModuleStatus(modName, "SKIP", output.Yellow, "not found")
				continue
			}

			info := mod.Info()
			if info.RequiresAuth && !ctx.Session.IsAuthenticated() {
				skippedModules++
				printModuleStatus(modName, "SKIP", output.Yellow, "no auth")
				continue
			}

			modStart := time.Now()

			// Collect findings.
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

			elapsed := time.Since(modStart)
			allFindings = append(allFindings, stepFindings...)

			if err != nil {
				failedModules++
				printModuleStatus(modName, "FAIL", output.Red, fmt.Sprintf("%v (%s)", err, elapsed.Round(time.Millisecond)))
			} else {
				succeededModules++
				findingSummary := ""
				if len(stepFindings) > 0 {
					findingSummary = fmt.Sprintf("%d finding(s)", len(stepFindings))
				}
				printModuleStatus(modName, "OK", output.Green, fmt.Sprintf("%s %s", elapsed.Round(time.Millisecond), findingSummary))
			}
		}
		fmt.Println()
	}

	// Forward all findings to parent.
	if ctx.Findings != nil {
		for _, f := range allFindings {
			ctx.Findings <- f
		}
	}

	// Save findings to DB.
	for _, f := range allFindings {
		ctx.Store.SaveFinding(&db.Finding{
			WorkspaceID: ctx.Workspace,
			Module:      f.Module,
			Severity:    string(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Resource:    f.Resource,
			Project:     f.Project,
			Data:        f.Data,
		})
	}

	elapsed := time.Since(start)

	// ═══════════════════════════════════════════════
	// RESULTS SUMMARY
	// ═══════════════════════════════════════════════
	printSectionDivider("AUDIT RESULTS")

	// Severity breakdown.
	sevCounts := map[string]int{}
	for _, f := range allFindings {
		sevCounts[string(f.Severity)]++
	}

	// Resource counts.
	resourceCounts, _ := ctx.Store.CountResources(ctx.Workspace)
	totalResources := 0
	for _, c := range resourceCounts {
		totalResources += c
	}

	fmt.Printf("  %sAudit Duration:%s  %s\n", output.Bold, output.Reset, elapsed.Round(time.Second))
	fmt.Printf("  %sModules Run:%s     %d (%s%d OK%s, %s%d failed%s, %s%d skipped%s)\n",
		output.Bold, output.Reset, totalModules,
		output.Green, succeededModules, output.Reset,
		output.Red, failedModules, output.Reset,
		output.Yellow, skippedModules, output.Reset)
	fmt.Printf("  %sResources:%s       %d across %d services\n", output.Bold, output.Reset, totalResources, len(resourceCounts))
	fmt.Printf("  %sFindings:%s        %d total\n", output.Bold, output.Reset, len(allFindings))
	fmt.Println()

	// ═══════════════════════════════════════════════
	// CRITICAL & HIGH FINDINGS
	// ═══════════════════════════════════════════════
	if sevCounts["CRITICAL"] > 0 || sevCounts["HIGH"] > 0 {
		printSectionDivider("CRITICAL & HIGH FINDINGS")
		printFindingsByProject(allFindings, "CRITICAL", "HIGH")
	}

	// ═══════════════════════════════════════════════
	// MEDIUM & LOW FINDINGS
	// ═══════════════════════════════════════════════
	if sevCounts["MEDIUM"] > 0 || sevCounts["LOW"] > 0 {
		printSectionDivider("MEDIUM & LOW FINDINGS")
		printFindingsByProject(allFindings, "MEDIUM", "LOW")
	}

	// ═══════════════════════════════════════════════
	// PRIVILEGE ESCALATION PATHS
	// ═══════════════════════════════════════════════
	builder := graph.NewBuilder(ctx.Store, ctx.Workspace)
	g, err := builder.Build()
	if err == nil && g.Stats()["nodes"] > 0 {
		analyzer := graph.NewAnalyzer(g)
		matches := analyzer.AnnotateEscalations()

		if len(matches) > 0 {
			printSectionDivider("PRIVILEGE ESCALATION VECTORS")
			for _, match := range matches {
				color := output.Yellow
				if match.Technique.Severity == "CRITICAL" {
					color = output.Red + output.Bold
				} else if match.Technique.Severity == "HIGH" {
					color = output.Red
				}
				fmt.Printf("  %s[%s] %s (%s)%s\n", color, match.Technique.ID, match.Technique.Name, match.Technique.Severity, output.Reset)
				fmt.Printf("       %s\n", match.Technique.Description)
				fmt.Printf("       Permissions: %s%s%s\n", output.Dim, strings.Join(match.MatchedPerms, ", "), output.Reset)
				fmt.Println()
			}
		}
	}

	// ═══════════════════════════════════════════════
	// PERMISSION SUMMARY
	// ═══════════════════════════════════════════════
	if ctx.Session != nil {
		perms, err := ctx.Store.ListGrantedPermissions(ctx.Session.ID)
		if err == nil && len(perms) > 0 {
			printSectionDivider("GRANTED PERMISSIONS")
			fmt.Printf("  %d permission(s) confirmed for current identity\n\n", len(perms))

			// Check which match known privesc techniques.
			var permStrings []string
			for _, p := range perms {
				permStrings = append(permStrings, p.Permission)
			}
			privescMatches := privesc.FindFullMatches(permStrings)
			if len(privescMatches) > 0 {
				fmt.Printf("  %s%sWARNING: %d known privilege escalation technique(s) available!%s\n\n",
					output.Red, output.Bold, len(privescMatches), output.Reset)
				for _, m := range privescMatches {
					fmt.Printf("    %s%s[%s] %s%s — %s\n",
						output.Red, output.Bold, m.Technique.ID, m.Technique.Name, output.Reset,
						m.Technique.Description)
				}
				fmt.Println()
			}
		}
	}

	// ═══════════════════════════════════════════════
	// RESOURCE INVENTORY
	// ═══════════════════════════════════════════════
	if len(resourceCounts) > 0 {
		printSectionDivider("RESOURCE INVENTORY")
		for svc, count := range resourceCounts {
			fmt.Printf("  %-25s %d\n", svc, count)
		}
		fmt.Println()
	}

	// ═══════════════════════════════════════════════
	// SEVERITY SCOREBOARD
	// ═══════════════════════════════════════════════
	printSectionDivider("SEVERITY SCOREBOARD")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		c := sevCounts[sev]
		bar := ""
		color := output.Dim
		switch sev {
		case "CRITICAL":
			color = output.Red + output.Bold
			bar = strings.Repeat("█", min(c, 50))
		case "HIGH":
			color = output.Red
			bar = strings.Repeat("█", min(c, 50))
		case "MEDIUM":
			color = output.Yellow
			bar = strings.Repeat("▓", min(c, 50))
		case "LOW":
			color = output.Blue
			bar = strings.Repeat("░", min(c, 50))
		case "INFO":
			color = output.Dim
			bar = strings.Repeat("·", min(c, 50))
		}
		fmt.Printf("  %s%-10s %3d %s%s\n", color, sev, c, bar, output.Reset)
	}
	fmt.Println()

	// Final verdict.
	printSectionDivider("VERDICT")
	if sevCounts["CRITICAL"] > 0 {
		fmt.Printf("  %s%s⚠  CRITICAL ISSUES FOUND — immediate remediation required%s\n",
			output.Red, output.Bold, output.Reset)
	} else if sevCounts["HIGH"] > 0 {
		fmt.Printf("  %s⚠  HIGH-risk issues found — review and prioritize remediation%s\n",
			output.Red, output.Reset)
	} else if sevCounts["MEDIUM"] > 0 {
		fmt.Printf("  %s⚠  Medium-risk issues found — plan remediation%s\n",
			output.Yellow, output.Reset)
	} else {
		fmt.Printf("  %s✓  No critical or high-risk issues detected%s\n",
			output.Green, output.Reset)
	}
	fmt.Println()

	output.Info("Full results: 'findings' | Export: 'report audit.md' | Attack graph: 'paths'")
	fmt.Println()

	return nil
}

func printPhaseHeader(num, total int, phase auditPhase) {
	fmt.Printf("%s%s══════════════════════════════════════════════════════════════%s\n",
		output.Cyan, output.Bold, output.Reset)
	fmt.Printf("%s%s  %s  Phase %d/%d: %s%s\n",
		output.Cyan, output.Bold, phase.icon, num, total, phase.name, output.Reset)
	fmt.Printf("%s%s══════════════════════════════════════════════════════════════%s\n",
		output.Cyan, output.Bold, output.Reset)
}

func printModuleStatus(name, status, color, detail string) {
	fmt.Printf("  %s[%s]%s %-45s %s%s%s\n",
		color, status, output.Reset, name, output.Dim, detail, output.Reset)
}

func printSectionDivider(title string) {
	width := 62
	padding := (width - len(title) - 4) / 2
	if padding < 1 {
		padding = 1
	}
	fmt.Printf("\n%s%s%s %s %s%s\n\n",
		output.Bold, output.Cyan,
		strings.Repeat("═", padding),
		title,
		strings.Repeat("═", padding),
		output.Reset)
}

func printFindingsByProject(findings []module.Finding, severities ...string) {
	sevSet := make(map[string]bool)
	for _, s := range severities {
		sevSet[s] = true
	}

	// Group by project.
	projectFindings := make(map[string][]module.Finding)
	var projectOrder []string
	seen := make(map[string]bool)

	for _, f := range findings {
		if !sevSet[string(f.Severity)] {
			continue
		}
		proj := f.Project
		if proj == "" {
			proj = "(global)"
		}
		if !seen[proj] {
			seen[proj] = true
			projectOrder = append(projectOrder, proj)
		}
		projectFindings[proj] = append(projectFindings[proj], f)
	}

	for _, proj := range projectOrder {
		pFindings := projectFindings[proj]
		fmt.Printf("  %s%s%s%s (%d)\n", output.Bold, output.Yellow, proj, output.Reset, len(pFindings))

		for _, f := range pFindings {
			color := output.Dim
			marker := "·"
			switch f.Severity {
			case module.SevCritical:
				color = output.Red + output.Bold
				marker = "✗"
			case module.SevHigh:
				color = output.Red
				marker = "✗"
			case module.SevMedium:
				color = output.Yellow
				marker = "!"
			case module.SevLow:
				color = output.Blue
				marker = "-"
			}
			resource := f.Resource
			if len(resource) > 40 {
				resource = resource[:37] + "..."
			}
			fmt.Printf("    %s%s [%s] %s%s", color, marker, f.Severity, f.Title, output.Reset)
			if resource != "" {
				fmt.Printf(" %s(%s)%s", output.Dim, resource, output.Reset)
			}
			fmt.Println()
		}
		fmt.Println()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
