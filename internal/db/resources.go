package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// Resource represents a discovered GCP resource.
type Resource struct {
	ID           int64
	WorkspaceID  int64
	Service      string
	ResourceType string
	Project      string
	Name         string
	Data         map[string]any
}

// SaveResource inserts or updates a discovered resource.
func (s *Store) SaveResource(r *Resource) error {
	dataBytes, err := json.Marshal(r.Data)
	if err != nil {
		return fmt.Errorf("marshal resource data: %w", err)
	}
	_, err = s.DB.Exec(
		`INSERT INTO resources (workspace_id, service, resource_type, project, name, data)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT DO UPDATE SET data = excluded.data, discovered_at = CURRENT_TIMESTAMP`,
		r.WorkspaceID, r.Service, r.ResourceType, r.Project, r.Name, string(dataBytes),
	)
	return err
}

// ListResources returns resources filtered by service and type.
func (s *Store) ListResources(workspaceID int64, service, resourceType string) ([]Resource, error) {
	query := `SELECT id, workspace_id, service, resource_type, project, name, data
	          FROM resources WHERE workspace_id = ?`
	args := []any{workspaceID}

	if service != "" {
		query += " AND service = ?"
		args = append(args, service)
	}
	if resourceType != "" {
		query += " AND resource_type = ?"
		args = append(args, resourceType)
	}
	query += " ORDER BY service, resource_type, name"

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var resources []Resource
	for rows.Next() {
		var r Resource
		var dataStr string
		if err := rows.Scan(&r.ID, &r.WorkspaceID, &r.Service, &r.ResourceType, &r.Project, &r.Name, &dataStr); err != nil {
			return nil, err
		}
		r.Data = make(map[string]any)
		_ = json.Unmarshal([]byte(dataStr), &r.Data)
		resources = append(resources, r)
	}
	return resources, rows.Err()
}

// CountResources returns the count of resources by service.
func (s *Store) CountResources(workspaceID int64) (map[string]int, error) {
	rows, err := s.DB.Query(
		`SELECT service, COUNT(*) FROM resources WHERE workspace_id = ? GROUP BY service`,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var svc string
		var count int
		if err := rows.Scan(&svc, &count); err != nil {
			return nil, err
		}
		counts[svc] = count
	}
	return counts, rows.Err()
}

// ResourceExists checks if a resource with the given name already exists.
func (s *Store) ResourceExists(workspaceID int64, service, resourceType, name string) (bool, error) {
	var count int
	err := s.DB.QueryRow(
		`SELECT COUNT(*) FROM resources WHERE workspace_id = ? AND service = ? AND resource_type = ? AND name = ?`,
		workspaceID, service, resourceType, name,
	).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	return count > 0, nil
}
