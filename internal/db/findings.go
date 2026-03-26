package db

import (
	"encoding/json"
	"fmt"
)

// Finding represents a structured result stored in the database.
type Finding struct {
	ID          int64
	WorkspaceID int64
	Module      string
	Severity    string
	Title       string
	Description string
	Resource    string
	Project     string
	Data        map[string]any
}

// SaveFinding stores a finding in the database.
func (s *Store) SaveFinding(f *Finding) error {
	dataBytes, err := json.Marshal(f.Data)
	if err != nil {
		return fmt.Errorf("marshal finding data: %w", err)
	}
	res, err := s.DB.Exec(
		`INSERT INTO findings (workspace_id, module, severity, title, description, resource, project, data)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.WorkspaceID, f.Module, f.Severity, f.Title, f.Description, f.Resource, f.Project, string(dataBytes),
	)
	if err != nil {
		return err
	}
	f.ID, _ = res.LastInsertId()
	return nil
}

// ListFindings returns findings filtered by optional severity and module.
func (s *Store) ListFindings(workspaceID int64, severity, module string) ([]Finding, error) {
	query := `SELECT id, workspace_id, module, severity, title, description, resource, project, data
	          FROM findings WHERE workspace_id = ?`
	args := []any{workspaceID}

	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}
	if module != "" {
		query += " AND module = ?"
		args = append(args, module)
	}
	query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, id"

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		var dataStr string
		if err := rows.Scan(&f.ID, &f.WorkspaceID, &f.Module, &f.Severity, &f.Title, &f.Description, &f.Resource, &f.Project, &dataStr); err != nil {
			return nil, err
		}
		f.Data = make(map[string]any)
		_ = json.Unmarshal([]byte(dataStr), &f.Data)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// CountFindingsBySeverity returns finding counts grouped by severity.
func (s *Store) CountFindingsBySeverity(workspaceID int64) (map[string]int, error) {
	rows, err := s.DB.Query(
		`SELECT severity, COUNT(*) FROM findings WHERE workspace_id = ? GROUP BY severity`,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		counts[sev] = count
	}
	return counts, rows.Err()
}
