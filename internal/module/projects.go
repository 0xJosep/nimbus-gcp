package module

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/user/nimbus/internal/db"
)

// PromptForProjects asks the user to select projects interactively.
// It checks the DB for previously discovered projects first.
func PromptForProjects(store *db.Store, workspaceID int64) []string {
	reader := bufio.NewReader(os.Stdin)

	discovered, _ := store.ListResources(workspaceID, "resourcemanager", "project")

	if len(discovered) > 0 {
		fmt.Println("\n  Discovered projects:")
		for i, r := range discovered {
			fmt.Printf("    [%d] %s\n", i+1, r.Name)
		}
		fmt.Printf("    [a] All of the above\n")
		fmt.Printf("    [m] Enter project IDs manually\n")
		fmt.Print("\n  Select: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "a" {
			var projects []string
			for _, r := range discovered {
				projects = append(projects, r.Name)
			}
			return projects
		}

		if input != "m" {
			var projects []string
			for _, part := range strings.Split(input, ",") {
				idx, err := strconv.Atoi(strings.TrimSpace(part))
				if err == nil && idx >= 1 && idx <= len(discovered) {
					projects = append(projects, discovered[idx-1].Name)
				}
			}
			if len(projects) > 0 {
				return projects
			}
		}
	}

	fmt.Print("\n  Enter project ID(s) (comma-separated): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var projects []string
	for _, p := range strings.Split(input, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			projects = append(projects, p)
		}
	}
	return projects
}

// EnsureProjects checks if projects are set, and prompts interactively if not.
// Returns the projects list (may be empty if user cancels).
func EnsureProjects(ctx *RunContext) []string {
	if len(ctx.Projects) > 0 {
		return ctx.Projects
	}
	if ctx.Session != nil && ctx.Session.Project != "" {
		return []string{ctx.Session.Project}
	}
	projects := PromptForProjects(ctx.Store, ctx.Workspace)
	ctx.Projects = projects
	return projects
}
