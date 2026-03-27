package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apikeys "google.golang.org/api/apikeys/v2"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&CreateAPIKey{})
}

// CreateAPIKey creates an unrestricted API key for the project.
type CreateAPIKey struct{}

func (m *CreateAPIKey) Info() module.Info {
	return module.Info{
		Name:         "credential.iam.create-api-key",
		Tactic:       module.TacticCredential,
		Service:      "apikeys",
		Description:  "Create an unrestricted API key for the project",
		RequiresAuth: true,
	}
}

func (m *CreateAPIKey) Run(ctx module.RunContext) error {
	projects := module.EnsureProjects(&ctx)
	if len(projects) == 0 {
		output.Warn("No project specified.")
		return nil
	}
	project := projects[0]

	svc, err := apikeys.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create apikeys client: %w", err)
	}

	parent := fmt.Sprintf("projects/%s/locations/global", project)

	key := &apikeys.V2Key{
		DisplayName:  "nimbus-generated-key",
		Restrictions: nil, // No restrictions -- unrestricted key.
	}

	output.Info("Creating unrestricted API key in project %s", project)

	op, err := svc.Projects.Locations.Keys.Create(parent, key).Do()
	if err != nil {
		return fmt.Errorf("create API key: %w", err)
	}

	output.Info("Waiting for API key creation to complete...")

	// Poll the operation until it completes.
	var keyName string
	for i := 0; i < 30; i++ {
		opStatus, err := svc.Operations.Get(op.Name).Do()
		if err != nil {
			return fmt.Errorf("poll operation: %w", err)
		}
		if opStatus.Done {
			if opStatus.Error != nil {
				return fmt.Errorf("API key creation failed: %s", opStatus.Error.Message)
			}
			// Extract the key name from the response.
			// The response metadata contains the created key resource.
			output.Success("API key creation complete.")
			if opStatus.Response != nil {
				var respMap map[string]any
				if json.Unmarshal(opStatus.Response, &respMap) == nil {
					if name, ok := respMap["name"].(string); ok {
						keyName = name
					}
					if uid, ok := respMap["uid"].(string); ok {
						output.Info("Key UID: %s", uid)
					}
				}
			}
			break
		}
		time.Sleep(2 * time.Second)
	}

	if keyName == "" {
		output.Warn("Could not determine key name from operation response.")
		output.Info("Operation: %s", op.Name)
		return nil
	}

	// Retrieve the key string value.
	keyString, err := svc.Projects.Locations.Keys.GetKeyString(keyName).Do()
	if err != nil {
		return fmt.Errorf("get key string: %w", err)
	}

	output.Success("API Key created!")
	output.Warn("Key Name:   %s", keyName)
	output.Warn("Key String: %s", keyString.KeyString)
	output.Warn("This key is unrestricted and can be used to access any enabled API.")

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "credential.iam.create-api-key",
			Severity:    module.SevHigh,
			Title:       "Unrestricted API key created",
			Description: fmt.Sprintf("Created unrestricted API key %s in project %s", keyName, project),
			Resource:    keyName,
			Project:     project,
			Data: map[string]any{
				"key_name":   keyName,
				"key_string": keyString.KeyString,
			},
		}
	}

	return nil
}
