package pubsub

import (
	"context"
	"fmt"
	"strings"

	pubsubv1 "google.golang.org/api/pubsub/v1"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&ScanTopics{})
}

// ScanTopics discovers Pub/Sub topics and subscriptions with security-relevant details.
type ScanTopics struct{}

func (m *ScanTopics) Info() module.Info {
	return module.Info{
		Name:         "recon.pubsub.scan-topics",
		Tactic:       module.TacticRecon,
		Service:      "pubsub",
		Description:  "List Pub/Sub topics and subscriptions, flag insecure push endpoints",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1530",
	}
}

func (m *ScanTopics) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := pubsubv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create pubsub client: %w", err)
	}

	for _, project := range ctx.Projects {
		output.Info("Scanning Pub/Sub in project: %s", project)

		parent := fmt.Sprintf("projects/%s", project)

		// List all subscriptions first to build a per-topic count.
		subsByTopic := make(map[string][]*pubsubv1.Subscription)
		err := svc.Projects.Subscriptions.List(parent).Pages(context.Background(),
			func(resp *pubsubv1.ListSubscriptionsResponse) error {
				for _, sub := range resp.Subscriptions {
					subsByTopic[sub.Topic] = append(subsByTopic[sub.Topic], sub)
				}
				return nil
			},
		)
		if err != nil {
			output.Error("Project %s list subscriptions: %v", project, err)
		}

		// Save subscriptions and flag insecure push endpoints.
		for _, subs := range subsByTopic {
			for _, sub := range subs {
				pushEndpoint := ""
				if sub.PushConfig != nil {
					pushEndpoint = sub.PushConfig.PushEndpoint
				}

				data := map[string]any{
					"name":          sub.Name,
					"topic":         sub.Topic,
					"ack_deadline":  sub.AckDeadlineSeconds,
					"push_endpoint": pushEndpoint,
					"state":         sub.State,
				}

				if err := ctx.Store.SaveResource(&db.Resource{
					WorkspaceID:  ctx.Workspace,
					Service:      "pubsub",
					ResourceType: "subscription",
					Project:      project,
					Name:         sub.Name,
					Data:         data,
				}); err != nil {
					output.Error("Save subscription %s: %v", sub.Name, err)
				}

				// Flag HTTP (non-HTTPS) push endpoints as HIGH.
				if pushEndpoint != "" && strings.HasPrefix(pushEndpoint, "http://") && ctx.Findings != nil {
					ctx.Findings <- module.Finding{
						Module:      "recon.pubsub.scan-topics",
						Severity:    module.SevHigh,
						Title:       "Push subscription using HTTP",
						Description: fmt.Sprintf("Subscription %s pushes to insecure HTTP endpoint: %s", sub.Name, pushEndpoint),
						Resource:    sub.Name,
						Project:     project,
					}
				}
			}
		}

		// List topics.
		topicHeaders := []string{"TOPIC", "SUBSCRIPTIONS", "PUSH ENDPOINTS"}
		var topicRows [][]string
		topicCount := 0

		err = svc.Projects.Topics.List(parent).Pages(context.Background(),
			func(resp *pubsubv1.ListTopicsResponse) error {
				for _, topic := range resp.Topics {
					topicCount++

					subs := subsByTopic[topic.Name]
					subCount := len(subs)

					var pushEndpoints []string
					for _, sub := range subs {
						if sub.PushConfig != nil && sub.PushConfig.PushEndpoint != "" {
							pushEndpoints = append(pushEndpoints, sub.PushConfig.PushEndpoint)
						}
					}
					endpointsStr := strings.Join(pushEndpoints, ", ")
					if endpointsStr == "" {
						endpointsStr = "-"
					}

					topicRows = append(topicRows, []string{
						topic.Name,
						fmt.Sprintf("%d", subCount),
						endpointsStr,
					})

					data := map[string]any{
						"name":              topic.Name,
						"subscription_count": subCount,
						"push_endpoints":    pushEndpoints,
						"labels":            topic.Labels,
					}

					if err := ctx.Store.SaveResource(&db.Resource{
						WorkspaceID:  ctx.Workspace,
						Service:      "pubsub",
						ResourceType: "topic",
						Project:      project,
						Name:         topic.Name,
						Data:         data,
					}); err != nil {
						output.Error("Save topic %s: %v", topic.Name, err)
					}
				}
				return nil
			},
		)
		if err != nil {
			output.Error("Project %s list topics: %v", project, err)
			continue
		}

		if topicCount == 0 {
			output.Info("No topics found in %s", project)
		} else {
			output.Success("Found %d topics in %s", topicCount, project)
			output.Table(topicHeaders, topicRows)
		}
	}
	return nil
}
