package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// SARIF types for the 2.1.0 specification.

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	DefaultConfig    sarifDefaultConfig  `json:"defaultConfiguration"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// severityToLevel maps nimbus severity strings to SARIF result levels.
func severityToLevel(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "note"
	}
}

// ruleKey returns a unique key for a module+title combination.
func ruleKey(module, title string) string {
	return fmt.Sprintf("%s/%s", module, title)
}

// GenerateSARIF writes a SARIF 2.1.0 report to the given path.
func GenerateSARIF(data *ReportData, path string) error {
	// Build unique rules from findings.
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, f := range data.Findings {
		key := ruleKey(f.Module, f.Title)
		if _, exists := ruleIndex[key]; !exists {
			ruleIndex[key] = len(rules)
			rules = append(rules, sarifRule{
				ID:               key,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				DefaultConfig:    sarifDefaultConfig{Level: severityToLevel(f.Severity)},
			})
		}
	}

	// Build results from findings.
	var results []sarifResult
	for _, f := range data.Findings {
		key := ruleKey(f.Module, f.Title)
		resourceURI := f.Resource
		if resourceURI == "" {
			resourceURI = "unknown"
		}
		results = append(results, sarifResult{
			RuleID:  key,
			Level:   severityToLevel(f.Severity),
			Message: sarifMessage{Text: f.Description},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: resourceURI,
						},
					},
				},
			},
		})
	}

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "nimbus",
						Version: "0.1.0",
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
