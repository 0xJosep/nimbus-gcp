package diff

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&AuditDiff{})
}

// AuditDiff compares findings between two audit runs to show what changed.
type AuditDiff struct{}

func (m *AuditDiff) Info() module.Info {
	return module.Info{
		Name:         "analyze.diff.audit-diff",
		Tactic:       module.TacticAnalyze,
		Service:      "analysis",
		Description:  "Compare findings between two audit runs to show new, fixed, and unchanged items",
		RequiresAuth: false,
	}
}

// findingKey builds a composite key from module + title + resource for comparison.
func findingKey(mod, title, resource string) string {
	return mod + "|" + title + "|" + resource
}

func (m *AuditDiff) Run(ctx module.RunContext) error {
	baselinePath := ctx.Flags["baseline"]
	if baselinePath == "" {
		return fmt.Errorf("--baseline is required (path to a JSON report from `report <file.json>`)")
	}

	// Load baseline findings from JSON report file.
	output.Info("Loading baseline from: %s", baselinePath)
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		return fmt.Errorf("read baseline file: %w", err)
	}

	var baseline output.ReportData
	if err := json.Unmarshal(baselineData, &baseline); err != nil {
		return fmt.Errorf("parse baseline JSON: %w", err)
	}

	output.Info("Baseline: %d finding(s) from %s", len(baseline.Findings), baseline.GeneratedAt.Format("2006-01-02 15:04:05"))

	// Build a set of baseline finding keys.
	baselineSet := make(map[string]output.ReportFinding, len(baseline.Findings))
	for _, f := range baseline.Findings {
		key := findingKey(f.Module, f.Title, f.Resource)
		baselineSet[key] = f
	}

	// Load current findings from the DB.
	currentFindings, err := ctx.Store.ListFindings(ctx.Workspace, "", "")
	if err != nil {
		return fmt.Errorf("load current findings: %w", err)
	}

	output.Info("Current: %d finding(s) in workspace", len(currentFindings))

	// Build a set of current finding keys.
	type currentEntry struct {
		Key      string
		Module   string
		Severity string
		Title    string
		Resource string
		Project  string
		Desc     string
	}

	currentSet := make(map[string]currentEntry, len(currentFindings))
	for _, f := range currentFindings {
		key := findingKey(f.Module, f.Title, f.Resource)
		currentSet[key] = currentEntry{
			Key:      key,
			Module:   f.Module,
			Severity: f.Severity,
			Title:    f.Title,
			Resource: f.Resource,
			Project:  f.Project,
			Desc:     f.Description,
		}
	}

	// Compute diff.
	var newFindings []currentEntry
	var fixedFindings []output.ReportFinding
	var unchangedCount int

	// New: in current but not in baseline.
	for key, entry := range currentSet {
		if _, exists := baselineSet[key]; !exists {
			newFindings = append(newFindings, entry)
		} else {
			unchangedCount++
		}
	}

	// Fixed: in baseline but not in current.
	for key, entry := range baselineSet {
		if _, exists := currentSet[key]; !exists {
			fixedFindings = append(fixedFindings, entry)
		}
	}

	// Display results.
	fmt.Println()

	// NEW findings (red).
	if len(newFindings) > 0 {
		fmt.Printf("  %s%s=== NEW FINDINGS (%d) ===%s\n", output.Red, output.Bold, len(newFindings), output.Reset)
		fmt.Println()
		for _, f := range newFindings {
			fmt.Printf("  %s+ [%s] %s%s\n", output.Red, f.Severity, f.Title, output.Reset)
			fmt.Printf("    Module: %s  Resource: %s\n", f.Module, f.Resource)
			if f.Desc != "" {
				fmt.Printf("    %s\n", f.Desc)
			}
			fmt.Println()

			// Emit findings for new items.
			if ctx.Findings != nil {
				sev := module.SevInfo
				switch f.Severity {
				case "CRITICAL":
					sev = module.SevCritical
				case "HIGH":
					sev = module.SevHigh
				case "MEDIUM":
					sev = module.SevMedium
				case "LOW":
					sev = module.SevLow
				}
				ctx.Findings <- module.Finding{
					Module:      "analyze.diff.audit-diff",
					Severity:    sev,
					Title:       fmt.Sprintf("New finding: %s", f.Title),
					Description: fmt.Sprintf("Finding not present in baseline: %s (from module %s)", f.Title, f.Module),
					Resource:    f.Resource,
					Project:     f.Project,
				}
			}
		}
	} else {
		fmt.Printf("  %s=== NEW FINDINGS (0) ===%s\n", output.Dim, output.Reset)
		fmt.Println()
	}

	// FIXED findings (green).
	if len(fixedFindings) > 0 {
		fmt.Printf("  %s%s=== FIXED FINDINGS (%d) ===%s\n", output.Green, output.Bold, len(fixedFindings), output.Reset)
		fmt.Println()
		for _, f := range fixedFindings {
			fmt.Printf("  %s- [%s] %s%s\n", output.Green, f.Severity, f.Title, output.Reset)
			fmt.Printf("    Module: %s  Resource: %s\n", f.Module, f.Resource)
			fmt.Println()
		}
	} else {
		fmt.Printf("  %s=== FIXED FINDINGS (0) ===%s\n", output.Dim, output.Reset)
		fmt.Println()
	}

	// UNCHANGED (dim).
	fmt.Printf("  %s=== UNCHANGED (%d) ===%s\n", output.Dim, unchangedCount, output.Reset)
	fmt.Println()

	// Summary line.
	fmt.Printf("  %s%d new finding(s), %d fixed, %d unchanged%s\n",
		output.Bold, len(newFindings), len(fixedFindings), unchangedCount, output.Reset)
	fmt.Println()

	return nil
}
