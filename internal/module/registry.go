package module

import (
	"fmt"
	"sort"
	"strings"
)

// Registry holds all registered modules.
type Registry struct {
	modules map[string]Module
}

var defaultRegistry = &Registry{modules: make(map[string]Module)}

// DefaultRegistry returns the global module registry.
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Register adds a module to the global registry. Called from module init() functions.
func Register(m Module) {
	info := m.Info()
	defaultRegistry.modules[info.Name] = m
}

// Get returns a module by exact name, or by partial prefix match.
// e.g. "recon.iam.list-principals" (exact) or "recon.iam" (returns first match).
func (r *Registry) Get(name string) (Module, bool) {
	// Exact match first.
	if m, ok := r.modules[name]; ok {
		return m, true
	}
	// Try prefix match — return exact if only one matches.
	var matches []Module
	for key, m := range r.modules {
		if strings.HasPrefix(key, name) {
			matches = append(matches, m)
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	return nil, false
}

// List returns all registered modules sorted by name.
func (r *Registry) List() []Module {
	mods := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Info().Name < mods[j].Info().Name
	})
	return mods
}

// ListByTactic returns modules matching a specific tactic.
func (r *Registry) ListByTactic(tactic Tactic) []Module {
	var matches []Module
	for _, m := range r.modules {
		if m.Info().Tactic == tactic {
			matches = append(matches, m)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Info().Name < matches[j].Info().Name
	})
	return matches
}

// ListByService returns modules targeting a specific GCP service.
func (r *Registry) ListByService(service string) []Module {
	service = strings.ToLower(service)
	var matches []Module
	for _, m := range r.modules {
		if strings.ToLower(m.Info().Service) == service {
			matches = append(matches, m)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Info().Name < matches[j].Info().Name
	})
	return matches
}

// Search returns modules matching a search term (name, service, tactic, or description).
func (r *Registry) Search(term string) []Module {
	term = strings.ToLower(term)
	var matches []Module
	for _, m := range r.modules {
		info := m.Info()
		if strings.Contains(strings.ToLower(info.Name), term) ||
			strings.Contains(strings.ToLower(info.Service), term) ||
			strings.Contains(strings.ToLower(string(info.Tactic)), term) ||
			strings.Contains(strings.ToLower(info.Description), term) {
			matches = append(matches, m)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Info().Name < matches[j].Info().Name
	})
	return matches
}

// PrintModules displays a formatted table of modules.
func (r *Registry) PrintModules(mods []Module) {
	if len(mods) == 0 {
		fmt.Println("  No modules found.")
		return
	}
	fmt.Printf("\n  %-40s %-16s %-12s %s\n", "MODULE", "TACTIC", "SERVICE", "DESCRIPTION")
	fmt.Printf("  %-40s %-16s %-12s %s\n",
		strings.Repeat("-", 40), strings.Repeat("-", 16),
		strings.Repeat("-", 12), strings.Repeat("-", 40))
	for _, m := range mods {
		info := m.Info()
		fmt.Printf("  %-40s %-16s %-12s %s\n", info.Name, info.Tactic, info.Service, info.Description)
	}
	fmt.Println()
}
