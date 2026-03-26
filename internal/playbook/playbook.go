package playbook

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Playbook defines a sequence of module executions.
type Playbook struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Steps       []Step `yaml:"steps"`
}

// Step defines a single module execution within a playbook.
type Step struct {
	Module      string            `yaml:"module"`
	Projects    []string          `yaml:"projects,omitempty"`
	Flags       map[string]string `yaml:"flags,omitempty"`
	Parallel    bool              `yaml:"parallel,omitempty"`
	StopOnError bool              `yaml:"stop_on_error,omitempty"`
}

// Load reads and parses a playbook YAML file.
func Load(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read playbook: %w", err)
	}

	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parse playbook: %w", err)
	}

	if pb.Name == "" {
		return nil, fmt.Errorf("playbook must have a name")
	}
	if len(pb.Steps) == 0 {
		return nil, fmt.Errorf("playbook must have at least one step")
	}

	return &pb, nil
}

// Validate checks that all module names in the playbook exist in the given set.
func (pb *Playbook) Validate(moduleExists func(string) bool) []string {
	var missing []string
	for _, step := range pb.Steps {
		if !moduleExists(step.Module) {
			missing = append(missing, step.Module)
		}
	}
	return missing
}
