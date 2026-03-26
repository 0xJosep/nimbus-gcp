package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// OutputConfig controls how output is rendered.
type OutputConfig struct {
	JSONMode bool
}

// PrintJSON prints any value as formatted JSON to stdout.
func PrintJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// PrintFindingsJSON prints findings as a JSON array to stdout.
func PrintFindingsJSON(findings []ReportFinding) {
	if findings == nil {
		findings = []ReportFinding{}
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal findings: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// PrintResourcesJSON prints resources as a JSON array to stdout.
func PrintResourcesJSON(resources []map[string]any) {
	if resources == nil {
		resources = []map[string]any{}
	}
	data, err := json.MarshalIndent(resources, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal resources: %v\n", err)
		return
	}
	fmt.Println(string(data))
}
