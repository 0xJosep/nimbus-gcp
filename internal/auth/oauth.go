package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/user/nimbus/internal/output"
)

// Default OAuth2 client credentials.
// These are the "Google Cloud SDK" public client IDs — same ones gcloud uses.
// They are not secret; they identify the app, not the user.
const (
	oauthClientID     = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
	oauthClientSecret = "d-FL95Q19q7MQmFpd7hHD0Ty"
)

// OAuthBrowserFlow runs the full OAuth2 authorization code flow:
// 1. Starts a local HTTP server on a random port
// 2. Prints a URL for the user to open in their browser
// 3. Receives the authorization code via the callback
// 4. Exchanges the code for access + refresh tokens
// Returns the token JSON to store in the database.
func OAuthBrowserFlow(scopes []string) (string, string, error) {
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	// Find a free port for the callback server.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	conf := &oauth2.Config{
		ClientID:     oauthClientID,
		ClientSecret: oauthClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	// Generate the authorization URL.
	state := "nimbus-auth"
	authURL := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	fmt.Println()
	output.Info("Open this URL in your browser to authenticate:")
	fmt.Printf("\n  %s\n\n", authURL)
	output.Info("Waiting for authorization...")

	// Start callback server and wait for the code.
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			errCh <- fmt.Errorf("invalid OAuth state")
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			errMsg := r.URL.Query().Get("error")
			http.Error(w, "Authorization failed: "+errMsg, http.StatusBadRequest)
			errCh <- fmt.Errorf("authorization denied: %s", errMsg)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body style="font-family:sans-serif;text-align:center;padding:50px">
			<h2>Authenticated</h2>
			<p>You can close this tab and return to nimbus.</p>
		</body></html>`)
		codeCh <- code
	})

	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for code or error.
	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		server.Shutdown(context.Background())
		return "", "", err
	}

	server.Shutdown(context.Background())

	// Exchange the authorization code for tokens.
	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		return "", "", fmt.Errorf("token exchange: %w", err)
	}

	output.Success("Authentication successful!")

	// Get the user's email from the token info.
	email := ""
	client := conf.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err == nil {
		defer resp.Body.Close()
		var userInfo struct {
			Email string `json:"email"`
		}
		if json.NewDecoder(resp.Body).Decode(&userInfo) == nil {
			email = userInfo.Email
		}
	}

	if email != "" {
		output.Info("Authenticated as: %s", email)
	}

	// Serialize the token for storage.
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", "", fmt.Errorf("marshal token: %w", err)
	}

	return string(tokenJSON), email, nil
}
