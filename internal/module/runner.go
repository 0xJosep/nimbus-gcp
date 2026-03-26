package module

import (
	"context"
	"fmt"
	"sync"

	"github.com/user/nimbus/internal/output"
)

// Runner executes modules with optional concurrency across projects.
type Runner struct {
	Registry    *Registry
	Concurrency int
}

// NewRunner creates a runner with the given concurrency limit.
func NewRunner(registry *Registry, concurrency int) *Runner {
	if concurrency < 1 {
		concurrency = 5
	}
	return &Runner{Registry: registry, Concurrency: concurrency}
}

// Execute runs a module, parallelizing across projects if supported.
func (r *Runner) Execute(mod Module, ctx RunContext) ([]Finding, error) {
	info := mod.Info()

	if info.RequiresAuth && !ctx.Session.IsAuthenticated() {
		return nil, fmt.Errorf("module %s requires authentication", info.Name)
	}

	// Collect findings from the module.
	findings := make([]Finding, 0)
	var mu sync.Mutex
	findingsCh := make(chan Finding, 100)

	// Drain findings channel into slice.
	done := make(chan struct{})
	go func() {
		for f := range findingsCh {
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
		}
		close(done)
	}()

	ctx.Findings = findingsCh

	// If module supports concurrency and has multiple projects, fan out.
	if info.Concurrent && len(ctx.Projects) > 1 {
		err := r.runParallel(mod, ctx)
		close(findingsCh)
		<-done
		return findings, err
	}

	// Sequential execution.
	err := mod.Run(ctx)
	close(findingsCh)
	<-done
	return findings, err
}

// runParallel splits projects across goroutines.
func (r *Runner) runParallel(mod Module, ctx RunContext) error {
	sem := make(chan struct{}, r.Concurrency)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var errs []error

	for _, project := range ctx.Projects {
		wg.Add(1)
		sem <- struct{}{}

		go func(proj string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Create a per-project context.
			projCtx := RunContext{
				Ctx:         ctx.Ctx,
				Session:     ctx.Session,
				Store:       ctx.Store,
				Workspace:   ctx.Workspace,
				Projects:    []string{proj},
				Flags:       ctx.Flags,
				Verbose:     ctx.Verbose,
				Concurrency: ctx.Concurrency,
				Findings:    ctx.Findings,
			}

			if err := mod.Run(projCtx); err != nil {
				output.Error("Project %s: %v", proj, err)
				errMu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", proj, err))
				errMu.Unlock()
			}
		}(project)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("%d project(s) failed", len(errs))
	}
	return nil
}

// RunPlaybook executes a sequence of modules.
func (r *Runner) RunPlaybook(ctx context.Context, baseCtx RunContext, steps []PlaybookStep) ([]Finding, error) {
	var allFindings []Finding

	for _, step := range steps {
		if ctx.Err() != nil {
			return allFindings, ctx.Err()
		}

		mod, ok := r.Registry.Get(step.Module)
		if !ok {
			output.Error("Module not found: %s", step.Module)
			continue
		}

		output.Info("Running: %s", step.Module)

		stepCtx := baseCtx
		stepCtx.Ctx = ctx
		if len(step.Projects) > 0 {
			stepCtx.Projects = step.Projects
		}
		// Merge step flags with base flags.
		for k, v := range step.Flags {
			stepCtx.Flags[k] = v
		}

		findings, err := r.Execute(mod, stepCtx)
		allFindings = append(allFindings, findings...)
		if err != nil {
			output.Error("Module %s: %v", step.Module, err)
			if step.StopOnError {
				return allFindings, err
			}
		}
	}
	return allFindings, nil
}

// PlaybookStep defines a single step in a playbook.
type PlaybookStep struct {
	Module      string
	Projects    []string
	Flags       map[string]string
	StopOnError bool
}
