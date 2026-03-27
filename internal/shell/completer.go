package shell

import (
	"sort"
	"strings"

	"github.com/user/nimbus/internal/module"
)

// nimbusCompleter implements readline.AutoCompleter for section-by-section
// dotted module name completion.
type nimbusCompleter struct {
	registry *module.Registry
}

func newCompleter(registry *module.Registry) *nimbusCompleter {
	return &nimbusCompleter{registry: registry}
}

// Do implements readline.AutoCompleter.
// It returns candidates and the length of the text to replace.
func (c *nimbusCompleter) Do(line []rune, pos int) ([][]rune, int) {
	lineStr := string(line[:pos])
	fields := strings.Fields(lineStr)

	// If the line is empty or we're completing the first word, complete commands.
	if len(fields) == 0 || (len(fields) == 1 && !strings.HasSuffix(lineStr, " ")) {
		prefix := ""
		if len(fields) == 1 {
			prefix = fields[0]
		}
		return c.completeCommands(prefix)
	}

	cmd := strings.ToLower(fields[0])

	// After "run" or "modules", complete module names.
	if cmd == "run" || cmd == "use" || cmd == "modules" || cmd == "mods" {
		modPrefix := ""
		if len(fields) >= 2 && !strings.HasSuffix(lineStr, " ") {
			modPrefix = fields[len(fields)-1]
		}
		// If we already have a complete module name and there's a space, complete flags.
		if len(fields) >= 2 && strings.HasSuffix(lineStr, " ") {
			if _, ok := c.registry.Get(fields[1]); ok {
				return c.completeFlags(fields[len(fields)-1])
			}
			// Maybe the module name is still being typed.
			modPrefix = ""
		}
		return c.completeModuleName(modPrefix)
	}

	// If the first word looks like a module name (contains dots), complete it.
	if strings.Contains(cmd, ".") && !strings.HasSuffix(lineStr, " ") {
		return c.completeModuleName(cmd)
	}

	// After a known module name, complete subcommands/flags.
	if _, ok := c.registry.Get(cmd); ok {
		lastWord := ""
		if !strings.HasSuffix(lineStr, " ") {
			lastWord = fields[len(fields)-1]
		}
		// Complete "run" as subcommand, or flags.
		flagCandidates, flagLen := c.completeFlags(lastWord)
		runCandidates := filterPrefix([]string{"run"}, lastWord)
		all := append(runCandidates, flagCandidates...)
		return all, flagLen
	}

	return nil, 0
}

func (c *nimbusCompleter) completeCommands(prefix string) ([][]rune, int) {
	commands := []string{
		"audit", "modules", "run", "creds", "data", "findings",
		"paths", "playbook", "report", "workspace", "help", "exit",
	}

	// Also add all module names as direct commands.
	for _, m := range c.registry.List() {
		commands = append(commands, m.Info().Name)
	}

	return toRuneCandidates(filterPrefix(commands, prefix)), len(prefix)
}

// completeModuleName completes dotted module names section by section.
// Given prefix "recon.i", it returns ["recon.iam."] (with trailing dot for non-leaf).
// Given prefix "recon.iam.", it returns ["recon.iam.list-bindings", "recon.iam.list-principals", "recon.iam.list-roles"].
func (c *nimbusCompleter) completeModuleName(prefix string) ([][]rune, int) {
	allNames := make([]string, 0)
	for _, m := range c.registry.List() {
		allNames = append(allNames, m.Info().Name)
	}

	// Find all names matching the prefix.
	var matching []string
	for _, name := range allNames {
		if strings.HasPrefix(name, prefix) {
			matching = append(matching, name)
		}
	}

	if len(matching) == 0 {
		return nil, 0
	}

	// Determine the current depth (number of dots in prefix).
	prefixDepth := strings.Count(prefix, ".")

	// Build candidates: complete to the next section boundary.
	candidateSet := make(map[string]bool)
	for _, name := range matching {
		parts := strings.SplitN(name, ".", prefixDepth+2)
		if len(parts) > prefixDepth+1 {
			// There are more sections — complete to next dot.
			candidate := strings.Join(parts[:prefixDepth+2], ".") + "."
			candidateSet[candidate] = true
		} else {
			// This is a leaf (full module name).
			candidateSet[name+" "] = true
		}
	}

	// If there's only one candidate and it ends with ".", strip the trailing dot
	// only if it's a full match prefix (allows further tabbing).
	candidates := make([]string, 0, len(candidateSet))
	for c := range candidateSet {
		candidates = append(candidates, c)
	}
	sort.Strings(candidates)

	// Return the suffix after the prefix.
	var result [][]rune
	for _, c := range candidates {
		suffix := strings.TrimPrefix(c, prefix)
		result = append(result, []rune(suffix))
	}

	return result, 0
}

func (c *nimbusCompleter) completeFlags(prefix string) ([][]rune, int) {
	flags := []string{
		"--project-ids", "-p", "--verbose", "-v",
		"--concurrency", "--output", "--target-sa",
		"--bucket", "--instance", "--zone", "--region",
		"--ssh-key", "--username", "--keyword",
		"--count-objects", "--read-values", "--list-objects",
		"--source-url", "--function-name", "--member", "--role",
		"--sink", "--prefix", "--delegates", "--scope",
	}

	return toRuneCandidates(filterPrefix(flags, prefix)), len(prefix)
}

func filterPrefix(items []string, prefix string) [][]rune {
	prefix = strings.ToLower(prefix)
	var result [][]rune
	for _, item := range items {
		if strings.HasPrefix(strings.ToLower(item), prefix) {
			suffix := item[len(prefix):]
			result = append(result, []rune(suffix+" "))
		}
	}
	return result
}

func toRuneCandidates(items [][]rune) [][]rune {
	return items
}
