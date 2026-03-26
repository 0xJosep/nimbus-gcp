package db

// PermissionRecord represents a tracked permission check result.
type PermissionRecord struct {
	ID           int64
	SessionID    int64
	ResourceType string
	ResourceName string
	Permission   string
	Granted      bool
}

// SavePermission records whether a permission is granted for a session on a resource.
func (s *Store) SavePermission(sessionID int64, resourceType, resourceName, permission string, granted bool) error {
	grantedInt := 0
	if granted {
		grantedInt = 1
	}
	_, err := s.DB.Exec(
		`INSERT INTO permissions (session_id, resource_type, resource_name, permission, granted)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(session_id, resource_type, resource_name, permission)
		 DO UPDATE SET granted = excluded.granted, checked_at = CURRENT_TIMESTAMP`,
		sessionID, resourceType, resourceName, permission, grantedInt,
	)
	return err
}

// ListGrantedPermissions returns all granted permissions for a session.
func (s *Store) ListGrantedPermissions(sessionID int64) ([]PermissionRecord, error) {
	rows, err := s.DB.Query(
		`SELECT id, session_id, resource_type, resource_name, permission
		 FROM permissions WHERE session_id = ? AND granted = 1
		 ORDER BY resource_type, resource_name, permission`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []PermissionRecord
	for rows.Next() {
		var p PermissionRecord
		if err := rows.Scan(&p.ID, &p.SessionID, &p.ResourceType, &p.ResourceName, &p.Permission); err != nil {
			return nil, err
		}
		p.Granted = true
		perms = append(perms, p)
	}
	return perms, rows.Err()
}
