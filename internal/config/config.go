package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds nimbus configuration options.
type Config struct {
	DefaultConcurrency int      `yaml:"default_concurrency"`
	OutputFormat       string   `yaml:"output_format"`
	DefaultProjects    []string `yaml:"default_projects"`
	HistorySize        int      `yaml:"history_size"`
}

// Load reads a Config from a YAML file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes the Config to a YAML file at the given path.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// DefaultPath returns the default configuration file path (~/.nimbus/config.yaml).
func DefaultPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".nimbus", "config.yaml")
	}
	return filepath.Join(homeDir, ".nimbus", "config.yaml")
}
