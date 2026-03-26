package graph

import (
	"encoding/json"
	"fmt"

	"github.com/user/nimbus/internal/db"
)

// Builder constructs a Graph from data collected in the database.
type Builder struct {
	store       *db.Store
	workspaceID int64
}

// NewBuilder creates a graph builder for a workspace.
func NewBuilder(store *db.Store, workspaceID int64) *Builder {
	return &Builder{store: store, workspaceID: workspaceID}
}

// Build constructs the full access graph from collected data.
func (b *Builder) Build() (*Graph, error) {
	g := New()

	if err := b.addServiceAccounts(g); err != nil {
		return nil, fmt.Errorf("add service accounts: %w", err)
	}
	if err := b.addRoleBindings(g); err != nil {
		return nil, fmt.Errorf("add role bindings: %w", err)
	}
	if err := b.addResources(g); err != nil {
		return nil, fmt.Errorf("add resources: %w", err)
	}
	if err := b.addSAAttachments(g); err != nil {
		return nil, fmt.Errorf("add SA attachments: %w", err)
	}

	return g, nil
}

func (b *Builder) addServiceAccounts(g *Graph) error {
	resources, err := b.store.ListResources(b.workspaceID, "iam", "service_account")
	if err != nil {
		return err
	}
	for _, r := range resources {
		g.AddNode(&Node{
			ID:       r.Name,
			Type:     NodeIdentity,
			Label:    r.Name,
			Project:  r.Project,
			Metadata: r.Data,
		})
	}
	return nil
}

func (b *Builder) addRoleBindings(g *Graph) error {
	rows, err := b.store.DB.Query(
		`SELECT identity, role, scope, project FROM role_bindings WHERE workspace_id = ?`,
		b.workspaceID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var identity, role, scope, project string
		if err := rows.Scan(&identity, &role, &scope, &project); err != nil {
			return err
		}

		// Ensure identity node exists.
		g.AddNode(&Node{
			ID:    identity,
			Type:  NodeIdentity,
			Label: identity,
		})

		// Add role node.
		roleID := fmt.Sprintf("role:%s@%s", role, scope)
		g.AddNode(&Node{
			ID:      roleID,
			Type:    NodeRole,
			Label:   role,
			Project: project,
		})

		// Identity -> Role binding edge.
		g.AddEdge(&Edge{
			From:  identity,
			To:    roleID,
			Type:  EdgeHasBinding,
			Label: fmt.Sprintf("bound on %s", scope),
		})
	}
	return rows.Err()
}

func (b *Builder) addResources(g *Graph) error {
	resources, err := b.store.ListResources(b.workspaceID, "", "")
	if err != nil {
		return err
	}
	for _, r := range resources {
		if r.ResourceType == "service_account" {
			continue // Already added as identity nodes.
		}
		nodeID := fmt.Sprintf("%s:%s/%s", r.Service, r.ResourceType, r.Name)
		g.AddNode(&Node{
			ID:       nodeID,
			Type:     NodeResource,
			Label:    r.Name,
			Project:  r.Project,
			Metadata: r.Data,
		})
	}
	return nil
}

// addSAAttachments links compute instances (and other resources) to their attached SAs.
func (b *Builder) addSAAttachments(g *Graph) error {
	resources, err := b.store.ListResources(b.workspaceID, "compute", "instance")
	if err != nil {
		return err
	}
	for _, r := range resources {
		saRaw, ok := r.Data["service_accounts"]
		if !ok {
			continue
		}
		// service_accounts is stored as a JSON array of strings.
		saBytes, _ := json.Marshal(saRaw)
		var saEmails []string
		if err := json.Unmarshal(saBytes, &saEmails); err != nil {
			// Try as a single-element interface slice.
			if arr, ok := saRaw.([]any); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						saEmails = append(saEmails, s)
					}
				}
			}
		}

		instanceID := fmt.Sprintf("compute:instance/%s", r.Name)
		for _, sa := range saEmails {
			g.AddEdge(&Edge{
				From:  instanceID,
				To:    sa,
				Type:  EdgeAttachedTo,
				Label: "runs as",
			})
		}
	}
	return nil
}
