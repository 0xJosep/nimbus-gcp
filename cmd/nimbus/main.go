package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/user/nimbus/internal/auth"
	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
	"github.com/user/nimbus/internal/playbook"
	"github.com/user/nimbus/internal/shell"
	"github.com/user/nimbus/internal/workspace"

	// Register modules -- recon.
	_ "github.com/user/nimbus/modules/recon/all"
	_ "github.com/user/nimbus/modules/recon/bigquery"
	_ "github.com/user/nimbus/modules/recon/cloudsql"
	_ "github.com/user/nimbus/modules/recon/compute"
	_ "github.com/user/nimbus/modules/recon/dns"
	_ "github.com/user/nimbus/modules/recon/functions"
	_ "github.com/user/nimbus/modules/recon/gke"
	_ "github.com/user/nimbus/modules/recon/iam"
	_ "github.com/user/nimbus/modules/recon/kms"
	_ "github.com/user/nimbus/modules/recon/logging"
	_ "github.com/user/nimbus/modules/recon/network"
	_ "github.com/user/nimbus/modules/recon/orgpolicy"
	_ "github.com/user/nimbus/modules/recon/pubsub"
	_ "github.com/user/nimbus/modules/recon/resourcemanager"
	_ "github.com/user/nimbus/modules/recon/run"
	_ "github.com/user/nimbus/modules/recon/scheduler"
	_ "github.com/user/nimbus/modules/recon/secrets"
	_ "github.com/user/nimbus/modules/recon/storage"

	// Register modules -- privesc.
	_ "github.com/user/nimbus/modules/privesc/cloudbuild"
	_ "github.com/user/nimbus/modules/privesc/compute"
	_ "github.com/user/nimbus/modules/privesc/functions"
	_ "github.com/user/nimbus/modules/privesc/iam"
	_ "github.com/user/nimbus/modules/privesc/orgpolicy"
	_ "github.com/user/nimbus/modules/privesc/run"

	// Register modules -- other tactics.
	_ "github.com/user/nimbus/modules/credential/compute"
	_ "github.com/user/nimbus/modules/credential/iam"
	_ "github.com/user/nimbus/modules/credential/storage"
	_ "github.com/user/nimbus/modules/defense_evasion/iam"
	_ "github.com/user/nimbus/modules/defense_evasion/logging"
	_ "github.com/user/nimbus/modules/exfil/bigquery"
	_ "github.com/user/nimbus/modules/exfil/secrets"
	_ "github.com/user/nimbus/modules/exfil/storage"
	_ "github.com/user/nimbus/modules/initial_access/functions"
	_ "github.com/user/nimbus/modules/initial_access/storage"
	_ "github.com/user/nimbus/modules/lateral/compute"
	_ "github.com/user/nimbus/modules/persist/iam"

	// Register modules -- analyze.
	_ "github.com/user/nimbus/modules/analyze/compliance"
	_ "github.com/user/nimbus/modules/analyze/iam"
	_ "github.com/user/nimbus/modules/analyze/paths"
	_ "github.com/user/nimbus/modules/analyze/summary"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "run":
			cliRun(os.Args[2:])
			return
		case "playbook":
			cliPlaybook(os.Args[2:])
			return
		case "modules":
			cliModules(os.Args[2:])
			return
		case "version":
			fmt.Println("nimbus v0.1.0")
			return
		case "help", "--help", "-h":
			cliHelp()
			return
		}
	}

	// Default: interactive REPL.
	fmt.Println(banner)
	store, ws, credStore, sess := bootstrap()
	defer store.Close()

	registry := module.DefaultRegistry()
	sh := shell.New(ws, sess, credStore, store, registry)
	sh.Run()
}

func cliHelp() {
	fmt.Println(banner)
	fmt.Println(`Usage:
  nimbus                              Launch interactive shell
  nimbus run <module> [flags]         Execute a module directly
  nimbus playbook <file.yaml>         Run a playbook
  nimbus modules [search]             List available modules
  nimbus version                      Show version
  nimbus help                         Show this help

Flags:
  -p, --project-ids <p1,p2>          Target GCP projects
  -v, --verbose                       Verbose output
  --concurrency <N>                   Parallel project scanning (default: 5)
  --workspace <name>                  Workspace name (default: "default")
  --output <json|table>               Output format`)
}

func cliModules(args []string) {
	registry := module.DefaultRegistry()
	if len(args) > 0 {
		term := strings.Join(args, " ")
		mods := registry.Search(term)
		registry.PrintModules(mods)
	} else {
		registry.PrintModules(registry.List())
	}
}

func cliRun(args []string) {
	if len(args) == 0 {
		output.Error("Usage: nimbus run <module> [--project-ids p1,p2]")
		os.Exit(1)
	}

	registry := module.DefaultRegistry()
	modName := args[0]
	mod, ok := registry.Get(modName)
	if !ok {
		output.Error("Module not found: %s", modName)
		os.Exit(1)
	}

	store, ws, _, sess := bootstrap()
	defer store.Close()

	flags, projects, verbose, concurrency := parseArgs(args[1:])

	if len(projects) == 0 && sess.Project != "" {
		projects = []string{sess.Project}
	}

	ctx := module.RunContext{
		Ctx:         context.Background(),
		Session:     sess,
		Store:       store,
		Workspace:   ws.ID,
		Projects:    projects,
		Flags:       flags,
		Verbose:     verbose,
		Concurrency: concurrency,
	}

	runner := module.NewRunner(registry, concurrency)
	info := mod.Info()
	output.Info("Running: %s [%s/%s]", info.Name, info.Tactic, info.Service)

	start := time.Now()
	findings, err := runner.Execute(mod, ctx)

	for _, f := range findings {
		store.SaveFinding(&db.Finding{
			WorkspaceID: ws.ID,
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
	if err != nil {
		output.Error("%v", err)
		os.Exit(1)
	}
	output.Success("Done: %d findings in %s", len(findings), elapsed.Round(time.Millisecond))
}

func cliPlaybook(args []string) {
	if len(args) == 0 {
		output.Error("Usage: nimbus playbook <file.yaml>")
		os.Exit(1)
	}

	pb, err := playbook.Load(args[0])
	if err != nil {
		output.Error("%v", err)
		os.Exit(1)
	}

	registry := module.DefaultRegistry()
	store, ws, _, sess := bootstrap()
	defer store.Close()

	output.Info("Running playbook: %s (%d steps)", pb.Name, len(pb.Steps))

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
		Session:     sess,
		Store:       store,
		Workspace:   ws.ID,
		Projects:    []string{sess.Project},
		Flags:       make(map[string]string),
		Concurrency: 5,
	}

	runner := module.NewRunner(registry, 5)
	findings, err := runner.RunPlaybook(context.Background(), baseCtx, steps)

	for _, f := range findings {
		store.SaveFinding(&db.Finding{
			WorkspaceID: ws.ID,
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
		output.Error("%v", err)
		os.Exit(1)
	}
	output.Success("Playbook complete: %d findings", len(findings))
}

func bootstrap() (*db.Store, *workspace.Workspace, *auth.CredentialStore, *auth.Session) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	dataDir := home + "/.nimbus"
	os.MkdirAll(dataDir, 0o700)

	store, err := db.Open(dataDir + "/nimbus.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "database error: %v\n", err)
		os.Exit(1)
	}

	wm := workspace.NewManager(store)
	ws, err := wm.SelectOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "workspace error: %v\n", err)
		os.Exit(1)
	}

	credStore := auth.NewCredentialStore(store, ws.ID)
	sess, err := credStore.SelectOrCreateSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "session error: %v\n", err)
		os.Exit(1)
	}

	return store, ws, credStore, sess
}

func parseArgs(args []string) (flags map[string]string, projects []string, verbose bool, concurrency int) {
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

const banner = `
  ███╗   ██╗██╗███╗   ███╗██████╗ ██╗   ██╗███████╗
  ████╗  ██║██║████╗ ████║██╔══██╗██║   ██║██╔════╝
  ██╔██╗ ██║██║██╔████╔██║██████╔╝██║   ██║███████╗
  ██║╚██╗██║██║██║╚██╔╝██║██╔══██╗██║   ██║╚════██║
  ██║ ╚████║██║██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║
  ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝
  GCP Pentesting Framework v0.1.0
`
