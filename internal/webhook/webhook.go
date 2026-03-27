package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/user/nimbus/internal/output"
)

// ReportFinding mirrors output.ReportFinding for use by the webhook package.
type ReportFinding = output.ReportFinding

// Notifier sends webhook notifications to Slack, Discord, or a generic endpoint.
type Notifier struct {
	URL      string
	Platform string // "slack", "discord", or "generic"
}

// Send posts a notification to the configured webhook URL.
func (n *Notifier) Send(title, message, severity string) error {
	var payload any

	switch n.Platform {
	case "slack":
		payload = map[string]any{
			"text": title,
			"blocks": []map[string]any{
				{
					"type": "section",
					"text": map[string]any{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*%s*\n%s", title, message),
					},
				},
			},
		}
	case "discord":
		payload = map[string]any{
			"content": fmt.Sprintf("**%s**\n%s", title, message),
		}
	default:
		payload = map[string]any{
			"title":    title,
			"message":  message,
			"severity": severity,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	resp, err := http.Post(n.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// NotifyCritical sends one notification for each CRITICAL finding.
func (n *Notifier) NotifyCritical(findings []ReportFinding) error {
	var lastErr error
	for _, f := range findings {
		if f.Severity != "CRITICAL" {
			continue
		}
		msg := fmt.Sprintf("Module: %s\nResource: %s\nProject: %s\n%s", f.Module, f.Resource, f.Project, f.Description)
		if err := n.Send(f.Title, msg, f.Severity); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
