package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // Pure-Go SQLite — no CGO, cross-compiles everywhere.
)

// Store wraps a SQLite database connection and provides schema migrations.
type Store struct {
	DB *sql.DB
}

// Open creates or opens a SQLite database at the given path and runs migrations.
func Open(path string) (*Store, error) {
	conn, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	s := &Store{DB: conn}
	if err := s.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.DB.Close()
}

func (s *Store) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS workspaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
			name TEXT NOT NULL,
			cred_type TEXT NOT NULL,
			email TEXT DEFAULT '',
			project TEXT DEFAULT '',
			scopes TEXT DEFAULT '',
			cred_data TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(workspace_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id INTEGER NOT NULL REFERENCES sessions(id),
			resource_type TEXT NOT NULL,
			resource_name TEXT NOT NULL,
			permission TEXT NOT NULL,
			granted INTEGER NOT NULL DEFAULT 0,
			checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(session_id, resource_type, resource_name, permission)
		)`,
		`CREATE TABLE IF NOT EXISTS resources (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
			service TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			project TEXT DEFAULT '',
			name TEXT NOT NULL,
			data TEXT DEFAULT '{}',
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_resources_service ON resources(workspace_id, service, resource_type)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
			module TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'INFO',
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			resource TEXT DEFAULT '',
			project TEXT DEFAULT '',
			data TEXT DEFAULT '{}',
			found_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(workspace_id, severity)`,
		`CREATE TABLE IF NOT EXISTS role_bindings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
			identity TEXT NOT NULL,
			role TEXT NOT NULL,
			scope TEXT NOT NULL,
			project TEXT DEFAULT '',
			condition TEXT DEFAULT '',
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_role_bindings_identity ON role_bindings(workspace_id, identity)`,
	}
	for _, m := range migrations {
		if _, err := s.DB.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}
	return nil
}
