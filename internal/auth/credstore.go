package auth

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/user/nimbus/internal/db"
)

// CredentialStore manages session credentials within a workspace.
type CredentialStore struct {
	store       *db.Store
	workspaceID int64
}

// NewCredentialStore creates a new credential store scoped to a workspace.
func NewCredentialStore(store *db.Store, workspaceID int64) *CredentialStore {
	return &CredentialStore{store: store, workspaceID: workspaceID}
}

// SelectOrCreateSession prompts the user to pick existing credentials or add new ones.
func (cs *CredentialStore) SelectOrCreateSession() (*Session, error) {
	sessions, err := cs.listSessions()
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(os.Stdin)

	if len(sessions) > 0 {
		fmt.Println("\nExisting sessions:")
		for i, s := range sessions {
			fmt.Printf("  [%d] %s (%s) - %s\n", i+1, s.Name, s.CredType, s.Email)
		}
		fmt.Printf("  [%d] Add new credentials\n", len(sessions)+1)
		fmt.Print("\nSelect session: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		choice, err := strconv.Atoi(input)
		if err == nil && choice >= 1 && choice <= len(sessions) {
			s := sessions[choice-1]
			fmt.Printf("Using session: %s\n", s.Name)
			return s, nil
		}
	}

	return cs.createSession(reader)
}

// SwapSession lets the user switch to a different session.
func (cs *CredentialStore) SwapSession() (*Session, error) {
	sessions, err := cs.listSessions()
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return cs.createSession(bufio.NewReader(os.Stdin))
	}

	fmt.Println("\nAvailable sessions:")
	for i, s := range sessions {
		fmt.Printf("  [%d] %s (%s) - %s\n", i+1, s.Name, s.CredType, s.Email)
	}
	fmt.Printf("  [%d] Add new credentials\n", len(sessions)+1)
	fmt.Print("\nSelect: ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	choice, _ := strconv.Atoi(strings.TrimSpace(input))

	if choice >= 1 && choice <= len(sessions) {
		return sessions[choice-1], nil
	}
	return cs.createSession(reader)
}

func (cs *CredentialStore) createSession(reader *bufio.Reader) (*Session, error) {
	fmt.Println("\nCredential types:")
	fmt.Println("  [1] Application Default Credentials (gcloud auth)")
	fmt.Println("  [2] Service Account Key (JSON file)")
	fmt.Println("  [3] OAuth2 Access Token")
	fmt.Println("  [4] None (unauthenticated)")
	fmt.Print("\nSelect type: ")

	input, _ := reader.ReadString('\n')
	choice, _ := strconv.Atoi(strings.TrimSpace(input))

	fmt.Print("Session name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}

	var rec credRecord
	rec.Name = name

	switch choice {
	case 1:
		rec.CredType = CredADC
		fmt.Print("Project ID (optional): ")
		proj, _ := reader.ReadString('\n')
		rec.Project = strings.TrimSpace(proj)

	case 2:
		rec.CredType = CredServiceAccount
		fmt.Print("Path to SA key JSON: ")
		path, _ := reader.ReadString('\n')
		path = strings.TrimSpace(path)
		keyData, email, err := readServiceAccountKeyFile(path)
		if err != nil {
			return nil, err
		}
		rec.RawCred = keyData
		rec.Email = email
		fmt.Printf("Loaded key for: %s\n", email)

	case 3:
		rec.CredType = CredOAuthToken
		fmt.Println("\n  [a] Browser login (opens a link to authenticate via Google)")
		fmt.Println("  [b] Paste a raw access token (e.g. stolen from metadata server)")
		fmt.Print("\nSelect: ")
		oauthChoice, _ := reader.ReadString('\n')
		oauthChoice = strings.TrimSpace(strings.ToLower(oauthChoice))

		if oauthChoice == "b" {
			fmt.Print("Access token: ")
			token, _ := reader.ReadString('\n')
			rec.RawCred = strings.TrimSpace(token)
		} else {
			tokenJSON, email, err := OAuthBrowserFlow(nil)
			if err != nil {
				return nil, fmt.Errorf("OAuth flow failed: %w", err)
			}
			rec.RawCred = tokenJSON
			rec.Email = email
			fmt.Print("Project ID (optional): ")
			proj, _ := reader.ReadString('\n')
			rec.Project = strings.TrimSpace(proj)
		}

	default:
		rec.CredType = CredNone
		fmt.Println("Running in unauthenticated mode.")
	}

	return cs.saveAndLoad(rec)
}

func (cs *CredentialStore) saveAndLoad(rec credRecord) (*Session, error) {
	recBytes, _ := json.Marshal(rec)

	res, err := cs.store.DB.Exec(
		`INSERT INTO sessions (workspace_id, name, cred_type, email, project, scopes, cred_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(workspace_id, name) DO UPDATE SET
		   cred_type=excluded.cred_type, email=excluded.email,
		   project=excluded.project, cred_data=excluded.cred_data`,
		cs.workspaceID, rec.Name, string(rec.CredType), rec.Email, rec.Project, "", string(recBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	id, _ := res.LastInsertId()

	creds, err := loadCredentials(rec)
	if err != nil {
		return nil, err
	}

	return &Session{
		ID:          id,
		WorkspaceID: cs.workspaceID,
		Name:        rec.Name,
		CredType:    rec.CredType,
		Email:       rec.Email,
		Project:     rec.Project,
		Scopes:      rec.Scopes,
		creds:       creds,
	}, nil
}

func (cs *CredentialStore) listSessions() ([]*Session, error) {
	rows, err := cs.store.DB.Query(
		`SELECT id, name, cred_type, email, project, cred_data FROM sessions WHERE workspace_id = ? ORDER BY id`,
		cs.workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		s := &Session{WorkspaceID: cs.workspaceID}
		var credType, credData string
		if err := rows.Scan(&s.ID, &s.Name, &credType, &s.Email, &s.Project, &credData); err != nil {
			return nil, err
		}
		s.CredType = CredType(credType)

		// Hydrate credentials from stored data.
		if credData != "" {
			var rec credRecord
			if json.Unmarshal([]byte(credData), &rec) == nil {
				creds, err := loadCredentials(rec)
				if err == nil {
					s.creds = creds
				}
			}
		}

		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}
