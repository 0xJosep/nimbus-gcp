package shell

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chzyer/readline"

	"github.com/user/nimbus/internal/auth"
	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/graph"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
	"github.com/user/nimbus/internal/playbook"
	"github.com/user/nimbus/internal/workspace"
)

// Shell is the interactive REPL for nimbus.
type Shell struct {
	ws        *workspace.Workspace
	session   *auth.Session
	credStore *auth.CredentialStore
	store     *db.Store
	registry  *module.Registry
	runner    *module.Runner
}

// New creates a new shell instance.
func New(
	ws *workspace.Workspace,
	session *auth.Session,
	credStore *auth.CredentialStore,
	store *db.Store,
	registry *module.Registry,
) *Shell {
	return &Shell{
		ws:        ws,
		session:   session,
		credStore: credStore,
		store:     store,
		registry:  registry,
		runner:    module.NewRunner(registry, 5),
	}
}

// Run starts the interactive shell loop.
func (s *Shell) Run() {
	completer := newCompleter(s.registry)

	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".nimbus")
	os.MkdirAll(dataDir, 0o755)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            s.buildPrompt(),
		AutoComplete:      completer,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistoryFile:       filepath.Join(dataDir, "history"),
		HistorySearchFold: true,
	})
	if err != nil {
		// Fallback to basic reader if readline fails.
		s.runBasic()
		return
	}
	defer rl.Close()

	for {
		rl.SetPrompt(s.buildPrompt())
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		}
		if err == io.EOF {
			fmt.Println("Goodbye.")
			return
		}
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if s.dispatch(line) {
			return
		}
	}
}

// dispatch handles a single command line. Returns true if the shell should exit.
func (s *Shell) dispatch(line string) bool {
	parts := strings.Fields(line)
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "?":
		s.cmdHelp()
	case "modules", "mods":
		s.cmdModules(args)
	case "run", "use":
		s.cmdRun(args)
	case "creds":
		s.cmdCreds(args)
	case "data":
		s.cmdData(args)
	case "findings":
		s.cmdFindings(args)
	case "paths":
		s.cmdPaths(args)
	case "playbook":
		s.cmdPlaybook(args)
	case "report":
		s.cmdReport(args)
	case "workspace", "ws":
		s.cmdWorkspace()
	case "exit", "quit":
		fmt.Println("Goodbye.")
		return true
	default:
		runArgs := args
		if len(runArgs) > 0 && strings.ToLower(runArgs[0]) == "run" {
			runArgs = runArgs[1:]
		}
		if _, ok := s.registry.Get(cmd); ok {
			s.cmdRun(append([]string{cmd}, runArgs...))
		} else {
			output.Error("Unknown command: %s. Type 'help' for available commands.", cmd)
		}
	}
	return false
}

func (s *Shell) buildPrompt() string {
	return fmt.Sprintf(
		output.Bold+output.Cyan+"nimbus"+output.Reset+
			"("+output.Yellow+"%s"+output.Reset+
			"/"+output.Green+"%s"+output.Reset+") > ",
		s.ws.Name, s.session.Name,
	)
}

// runBasic is a fallback REPL without tab completion (used if readline init fails).
func (s *Shell) runBasic() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(s.buildPrompt())
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		s.dispatch(line)
	}
}

func (s *Shell) cmdHelp() {
	fmt.Println(`
  Commands:
    modules [search]         List or search modules (by name, tactic, or service)
    run <module> [flags]     Execute a module
    creds [swap|info]        Manage credentials
    data [service]           View enumerated resources
    findings [severity]      View security findings
    paths [from <identity>]  Analyze attack paths from collected data
    playbook <file.yaml>     Run a playbook
    report <output.md>       Generate a pentest report
    workspace                Show current workspace info
    help                     Show this help
    exit                     Exit nimbus

  Module Flags:
    --project-ids, -p <p1,p2>   Target projects
    --verbose, -v                Verbose output
    --concurrency <N>            Parallel project scanning (default: 5)
    --<flag> <value>             Module-specific flags
	`)
}

func (s *Shell) cmdModules(args []string) {
	if len(args) > 0 {
		// If the last arg is "run", treat as: run <module> [remaining flags].
		// e.g. "modules recon.storage.probe-buckets run" -> run recon.storage.probe-buckets
		if len(args) >= 2 && strings.ToLower(args[len(args)-1]) == "run" {
			s.cmdRun(args[:len(args)-1])
			return
		}
		// If the single arg is an exact module match, show info and hint to run.
		if len(args) == 1 {
			if mod, ok := s.registry.Get(args[0]); ok {
				s.registry.PrintModules([]module.Module{mod})
				output.Info("To run: run %s -p <project>", mod.Info().Name)
				return
			}
		}

		term := strings.Join(args, " ")
		// Check if searching by tactic.
		tactic := module.Tactic(term)
		mods := s.registry.ListByTactic(tactic)
		if len(mods) > 0 {
			s.registry.PrintModules(mods)
			return
		}
		// General search.
		mods = s.registry.Search(term)
		s.registry.PrintModules(mods)
	} else {
		s.registry.PrintModules(s.registry.List())
	}
}

func (s *Shell) cmdRun(args []string) {
	if len(args) == 0 {
		output.Warn("Usage: run <module> [--project-ids p1,p2] [--verbose]")
		return
	}

	modName := args[0]
	mod, ok := s.registry.Get(modName)
	if !ok {
		output.Error("Module not found: %s", modName)
		output.Info("Try 'modules %s' to search.", modName)
		return
	}

	info := mod.Info()
	if info.RequiresAuth && !s.session.IsAuthenticated() {
		output.Error("Module %s requires authentication. Use 'creds swap' to load credentials.", modName)
		return
	}

	flags, projects, verbose, concurrency := parseRunArgs(args[1:])

	if len(projects) == 0 && s.session.Project != "" {
		projects = []string{s.session.Project}
	}

	// If still no projects, prompt the user.
	if len(projects) == 0 && info.RequiresAuth {
		projects = module.PromptForProjects(s.store, s.ws.ID)
		if len(projects) == 0 {
			output.Warn("No projects selected. Aborting.")
			return
		}
	}

	ctx := module.RunContext{
		Ctx:         context.Background(),
		Session:     s.session,
		Store:       s.store,
		Workspace:   s.ws.ID,
		Projects:    projects,
		Flags:       flags,
		Verbose:     verbose,
		Concurrency: concurrency,
	}

	output.Info("Running: %s [%s/%s]", info.Name, info.Tactic, info.Service)
	start := time.Now()

	findings, err := s.runner.Execute(mod, ctx)
	elapsed := time.Since(start)

	if err != nil {
		output.Error("Module %s failed: %v", info.Name, err)
	}

	// Save findings to DB.
	for _, f := range findings {
		s.store.SaveFinding(&db.Finding{
			WorkspaceID: s.ws.ID,
			Module:      f.Module,
			Severity:    string(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Resource:    f.Resource,
			Project:     f.Project,
			Data:        f.Data,
		})
	}

	if len(findings) > 0 {
		output.Success("Generated %d findings in %s", len(findings), elapsed.Round(time.Millisecond))
	} else {
		output.Info("Completed in %s", elapsed.Round(time.Millisecond))
	}
}

func (s *Shell) cmdCreds(args []string) {
	if len(args) == 0 {
		fmt.Printf("\n  Session:  %s\n  Type:     %s\n  Email:    %s\n  Project:  %s\n  Auth:     %v\n\n",
			s.session.Name, s.session.CredType, s.session.Email, s.session.Project, s.session.IsAuthenticated())
		return
	}
	switch args[0] {
	case "swap":
		sess, err := s.credStore.SwapSession()
		if err != nil {
			output.Error("swap: %v", err)
			return
		}
		s.session = sess
		output.Success("Switched to session: %s", sess.Name)
	case "info":
		fmt.Printf("\n  Session:  %s\n  Type:     %s\n  Email:    %s\n  Project:  %s\n  Auth:     %v\n\n",
			s.session.Name, s.session.CredType, s.session.Email, s.session.Project, s.session.IsAuthenticated())
	default:
		output.Warn("Usage: creds [swap|info]")
	}
}

func (s *Shell) cmdData(args []string) {
	service := ""
	if len(args) > 0 {
		service = args[0]
	}

	if service == "" {
		counts, err := s.store.CountResources(s.ws.ID)
		if err != nil {
			output.Error("data: %v", err)
			return
		}
		if len(counts) == 0 {
			output.Info("No data collected yet. Run some recon modules first.")
			return
		}
		headers := []string{"SERVICE", "RESOURCES"}
		var rows [][]string
		for svc, count := range counts {
			rows = append(rows, []string{svc, fmt.Sprintf("%d", count)})
		}
		output.Table(headers, rows)
		return
	}

	resources, err := s.store.ListResources(s.ws.ID, service, "")
	if err != nil {
		output.Error("data: %v", err)
		return
	}
	if len(resources) == 0 {
		output.Info("No %s resources found.", service)
		return
	}
	headers := []string{"TYPE", "PROJECT", "NAME"}
	var rows [][]string
	for _, r := range resources {
		rows = append(rows, []string{r.ResourceType, r.Project, r.Name})
	}
	output.Table(headers, rows)
}

func (s *Shell) cmdFindings(args []string) {
	severity := ""
	if len(args) > 0 {
		severity = strings.ToUpper(args[0])
	}

	findings, err := s.store.ListFindings(s.ws.ID, severity, "")
	if err != nil {
		output.Error("findings: %v", err)
		return
	}
	if len(findings) == 0 {
		output.Info("No findings yet. Run some modules first.")
		return
	}

	// Show summary.
	counts, _ := s.store.CountFindingsBySeverity(s.ws.ID)
	fmt.Println()
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if c, ok := counts[sev]; ok {
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
			fmt.Printf("  %s%-10s%s %d\n", color, sev, output.Reset, c)
		}
	}
	fmt.Println()

	headers := []string{"SEVERITY", "MODULE", "TITLE", "RESOURCE", "PROJECT"}
	var rows [][]string
	for _, f := range findings {
		rows = append(rows, []string{f.Severity, f.Module, f.Title, f.Resource, f.Project})
	}
	output.Table(headers, rows)
}

func (s *Shell) cmdPaths(args []string) {
	output.Info("Building attack graph from collected data...")

	builder := graph.NewBuilder(s.store, s.ws.ID)
	g, err := builder.Build()
	if err != nil {
		output.Error("Build graph: %v", err)
		return
	}

	stats := g.Stats()
	output.Info("Graph: %d nodes, %d edges", stats["nodes"], stats["edges"])

	if stats["nodes"] == 0 {
		output.Warn("No data to analyze. Run recon modules first (recon.iam.list-bindings is recommended).")
		return
	}

	// Annotate with privesc techniques.
	analyzer := graph.NewAnalyzer(g)
	matches := analyzer.AnnotateEscalations()

	if len(matches) == 0 {
		output.Success("No known privilege escalation paths detected.")
		return
	}

	output.Warn("Found %d potential escalation technique(s)!", len(matches))
	fmt.Println()

	for _, match := range matches {
		color := output.Yellow
		if match.Technique.Severity == "CRITICAL" {
			color = output.Red + output.Bold
		} else if match.Technique.Severity == "HIGH" {
			color = output.Red
		}
		fmt.Printf("  %s[%s] %s (%s)%s\n", color, match.Technique.ID, match.Technique.Name, match.Technique.Severity, output.Reset)
		fmt.Printf("    %s\n", match.Technique.Description)
		fmt.Printf("    Permissions: %s\n", strings.Join(match.MatchedPerms, ", "))
		if match.Technique.Reference != "" {
			fmt.Printf("    Reference: %s\n", match.Technique.Reference)
		}
		fmt.Println()
	}

	// Find escalation paths.
	if len(args) > 1 && args[0] == "from" {
		identity := args[1]
		paths := g.FindPaths(identity, 6)
		if len(paths) == 0 {
			output.Info("No escalation paths from %s", identity)
		} else {
			output.Warn("Escalation paths from %s:", identity)
			for i, p := range paths {
				fmt.Printf("  [%d] %s\n", i+1, p.String())
			}
		}
	}
}

func (s *Shell) cmdPlaybook(args []string) {
	if len(args) == 0 {
		output.Warn("Usage: playbook <file.yaml>")
		return
	}

	pb, err := playbook.Load(args[0])
	if err != nil {
		output.Error("Load playbook: %v", err)
		return
	}

	// Validate modules exist.
	missing := pb.Validate(func(name string) bool {
		_, ok := s.registry.Get(name)
		return ok
	})
	if len(missing) > 0 {
		output.Error("Unknown modules in playbook: %s", strings.Join(missing, ", "))
		return
	}

	output.Info("Running playbook: %s (%d steps)", pb.Name, len(pb.Steps))

	// Convert playbook steps to runner steps.
	var steps []module.PlaybookStep
	for _, step := range pb.Steps {
		flags := step.Flags
		if flags == nil {
			flags = make(map[string]string)
		}
		steps = append(steps, module.PlaybookStep{
			Module:      step.Module,
			Projects:    step.Projects,
			Flags:       flags,
			StopOnError: step.StopOnError,
		})
	}

	baseCtx := module.RunContext{
		Ctx:         context.Background(),
		Session:     s.session,
		Store:       s.store,
		Workspace:   s.ws.ID,
		Projects:    []string{s.session.Project},
		Flags:       make(map[string]string),
		Concurrency: 5,
	}

	start := time.Now()
	findings, err := s.runner.RunPlaybook(context.Background(), baseCtx, steps)
	elapsed := time.Since(start)

	// Save findings.
	for _, f := range findings {
		s.store.SaveFinding(&db.Finding{
			WorkspaceID: s.ws.ID,
			Module:      f.Module,
			Severity:    string(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Resource:    f.Resource,
			Project:     f.Project,
			Data:        f.Data,
		})
	}

	if err != nil {
		output.Error("Playbook error: %v", err)
	}
	output.Success("Playbook complete: %d findings in %s", len(findings), elapsed.Round(time.Millisecond))
}

func (s *Shell) cmdReport(args []string) {
	if len(args) == 0 {
		output.Warn("Usage: report <output.md|output.json>")
		return
	}
	outPath := args[0]

	findings, err := s.store.ListFindings(s.ws.ID, "", "")
	if err != nil {
		output.Error("Load findings: %v", err)
		return
	}

	resources, _ := s.store.CountResources(s.ws.ID)

	// Build graph stats.
	builder := graph.NewBuilder(s.store, s.ws.ID)
	g, _ := builder.Build()
	var graphStats map[string]int
	if g != nil {
		graphStats = g.Stats()
	}

	var reportFindings []output.ReportFinding
	for _, f := range findings {
		reportFindings = append(reportFindings, output.ReportFinding{
			Module:      f.Module,
			Severity:    f.Severity,
			Title:       f.Title,
			Description: f.Description,
			Resource:    f.Resource,
			Project:     f.Project,
		})
	}

	data := &output.ReportData{
		Title:       "Nimbus GCP Security Assessment",
		Workspace:   s.ws.Name,
		GeneratedAt: time.Now(),
		Findings:    reportFindings,
		Resources:   resources,
		GraphStats:  graphStats,
	}

	if strings.HasSuffix(outPath, ".json") {
		err = output.GenerateJSON(data, outPath)
	} else {
		err = output.GenerateMarkdown(data, outPath)
	}

	if err != nil {
		output.Error("Generate report: %v", err)
		return
	}
	output.Success("Report written to: %s", outPath)
}

func (s *Shell) cmdWorkspace() {
	fmt.Printf("\n  Workspace: %s (ID: %d)\n  Session:   %s\n\n", s.ws.Name, s.ws.ID, s.session.Name)
}

func parseRunArgs(args []string) (flags map[string]string, projects []string, verbose bool, concurrency int) {
	flags = make(map[string]string)
	concurrency = 5
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--project-ids", "-p":
			if i+1 < len(args) {
				i++
				projects = strings.Split(args[i], ",")
			}
		case "--verbose", "-v":
			verbose = true
		case "--concurrency":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &concurrency)
			}
		default:
			if strings.HasPrefix(args[i], "--") {
				key := strings.TrimPrefix(args[i], "--")
				val := "true"
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
					i++
					val = args[i]
				}
				flags[key] = val
			}
		}
	}
	return
}
