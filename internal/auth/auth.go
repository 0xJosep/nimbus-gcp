package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

)

// CredType defines the supported credential types.
type CredType string

const (
	CredADC            CredType = "adc"
	CredServiceAccount CredType = "service_account"
	CredOAuthToken     CredType = "oauth_token"
	CredNone           CredType = "none"
)

// Session holds the active credential context for module execution.
type Session struct {
	ID          int64
	WorkspaceID int64
	Name        string
	CredType    CredType
	Email       string
	Project     string
	Scopes      []string
	creds       *google.Credentials
}

// ClientOption returns a google API client option for the session credentials.
func (s *Session) ClientOption() option.ClientOption {
	if s.creds == nil {
		return option.WithoutAuthentication()
	}
	return option.WithCredentials(s.creds)
}

// TokenSource returns the underlying token source, or nil for unauthenticated sessions.
func (s *Session) TokenSource() *google.Credentials {
	return s.creds
}

// IsAuthenticated returns true if the session has valid credentials.
func (s *Session) IsAuthenticated() bool {
	return s.CredType != CredNone && s.creds != nil
}

// credRecord is the serializable form of a session stored in the database.
type credRecord struct {
	Name     string   `json:"name"`
	CredType CredType `json:"cred_type"`
	Email    string   `json:"email"`
	Project  string   `json:"project"`
	Scopes   []string `json:"scopes"`
	// For service account: the key JSON. For OAuth: the token string.
	RawCred string `json:"raw_cred,omitempty"`
}

// loadCredentials hydrates a Session's google.Credentials from the stored data.
func loadCredentials(rec credRecord) (*google.Credentials, error) {
	ctx := context.Background()
	scopes := rec.Scopes
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	switch rec.CredType {
	case CredADC:
		creds, err := google.FindDefaultCredentials(ctx, scopes...)
		if err != nil {
			return nil, fmt.Errorf("ADC: %w", err)
		}
		return creds, nil

	case CredServiceAccount:
		if rec.RawCred == "" {
			return nil, fmt.Errorf("service account key data is empty")
		}
		creds, err := google.CredentialsFromJSON(ctx, []byte(rec.RawCred), scopes...)
		if err != nil {
			return nil, fmt.Errorf("service account: %w", err)
		}
		return creds, nil

	case CredOAuthToken:
		// For a raw OAuth token, we create a static token source.
		// This won't auto-refresh but is useful for stolen/metadata tokens.
		creds, err := google.CredentialsFromJSON(ctx, []byte(fmt.Sprintf(
			`{"type":"authorized_user","token":"%s"}`, rec.RawCred,
		)), scopes...)
		if err != nil {
			// Fallback: treat as ADC if parsing fails.
			return nil, fmt.Errorf("oauth token: %w", err)
		}
		return creds, nil

	case CredNone:
		return nil, nil

	default:
		return nil, fmt.Errorf("unknown credential type: %s", rec.CredType)
	}
}

// readServiceAccountKeyFile reads and returns the contents of a SA key file.
func readServiceAccountKeyFile(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read key file: %w", err)
	}
	var keyFile struct {
		ClientEmail string `json:"client_email"`
		ProjectID   string `json:"project_id"`
	}
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return "", "", fmt.Errorf("parse key file: %w", err)
	}
	return string(data), keyFile.ClientEmail, nil
}
