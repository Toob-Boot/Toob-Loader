package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/toob-boot/toob/internal/oidc"
)

// AuthConfig is what the registry publishes about how to authenticate against it.
//
// Read from the registry rather than configured here. An issuer, an audience and a client id are
// per-deployment facts, and a client carrying its own copy is a client that is right about one
// environment and quietly wrong about the next.
type AuthConfig struct {
	Issuer   string   `json:"issuer"`
	Audience string   `json:"audience"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	// AccountsURL is where identity-api answers: organizations are managed there, not at the registry.
	AccountsURL string `json:"accounts_url"`
	// SettingsURL is where account settings open in a browser.
	SettingsURL string `json:"settings_url"`
}

// FetchAuthConfig asks the registry who issues the tokens it accepts.
func (c *Client) FetchAuthConfig(ctx context.Context) (*AuthConfig, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/auth/config", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asking %s how to authenticate: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s does not publish an authentication configuration; it is older than this client", c.BaseURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d when asked how to authenticate", c.BaseURL, resp.StatusCode)
	}

	var config AuthConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("the registry's authentication configuration is not readable: %w", err)
	}
	if config.Issuer == "" || config.ClientID == "" {
		return nil, fmt.Errorf("%s published an incomplete authentication configuration", c.BaseURL)
	}

	return &config, nil
}

// Profile is the JSON body of GET /api/v1/me.
type Profile struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Orgs        []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"orgs"`
}

// Whoami asks the registry who it takes the caller to be.
//
// The one call that exercises the whole chain: the token was issued by the expected issuer, for the
// expected audience, signed by a key the registry could fetch, and the subject resolved to a user.
// Anything wrong anywhere in that sequence shows up here as a 401, which is why signing in ends with
// it rather than with a stored file.
func (c *Client) Whoami(ctx context.Context) (*Profile, error) {
	var profile Profile
	if err := c.getJSON(ctx, "/api/v1/me", &profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// HasSession reports whether a person's session is stored.
func HasSession() bool {
	creds := loadCredentials()

	return creds.Identity != nil && creds.Identity.Token != nil && creds.Identity.Token.RefreshToken != ""
}

// IdentityCredentials is a person's session, as it is kept on disk.
//
// The issuer and client id are stored beside the tokens because a refresh needs both, and because
// they say which deployment this session belongs to: pointing the client at another registry and
// finding a stored token for a different issuer is a mismatch worth noticing rather than a request
// worth sending.
type IdentityCredentials struct {
	Issuer   string      `json:"issuer"`
	ClientID string      `json:"client_id"`
	Subject  string      `json:"subject,omitempty"`
	Token    *oidc.Token `json:"token"`
}

// refreshMu serialises refreshes within a process. Two commands in one process refreshing the same
// session would each write the file, and the loser's refresh token is then one the issuer has
// already rotated away.
var refreshMu sync.Mutex

// SaveIdentity persists a session, leaving any API key in place.
//
// Merged rather than written whole: the API key is a separate credential for non-interactive use,
// and logging in interactively must not silently revoke a machine's ability to publish.
func SaveIdentity(identity *IdentityCredentials, login string) error {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	return mergeCredentials(func(creds *Credentials) {
		creds.Identity = identity
		if login != "" {
			creds.Login = login
		}
	})
}

// DeleteIdentity removes the stored session and leaves the API key.
func DeleteIdentity() error {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	return mergeCredentials(func(creds *Credentials) { creds.Identity = nil })
}

// mergeCredentials reads, changes and atomically rewrites the credentials file.
func mergeCredentials(change func(*Credentials)) error {
	path := credentialsPath()
	if path == "" {
		return fmt.Errorf("cannot determine credentials path")
	}

	creds := loadCredentials()
	change(&creds)

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

// bearer returns the credential to present, refreshing an expired session first.
//
// TOOB_TOKEN comes first, since it was set for this run. Otherwise a session is preferred over an
// API key: the key is the long-lived credential meant for machines, and a person who has just
// logged in should be acting as themselves.
func (c *Client) bearer(ctx context.Context) string {
	if token := os.Getenv(TokenEnv); token != "" {
		return token
	}
	creds := loadCredentials()
	if creds.Identity == nil || creds.Identity.Token == nil {
		return c.Token
	}
	if creds.Identity.Token.Usable() {
		return creds.Identity.Token.AccessToken
	}

	refreshed, err := refreshSession(ctx, creds.Identity)
	if err != nil {
		// Deliberately not fatal here. The request goes out with whatever is left and the server
		// answers 401, which is the same outcome the caller has to handle anyway — and a refresh that
		// fails because the network is down should not look like a different problem than a request
		// that fails because the network is down.
		return creds.Identity.Token.AccessToken
	}

	return refreshed.AccessToken
}

// refreshSession trades the stored refresh token for a new one and writes it back.
func refreshSession(ctx context.Context, identity *IdentityCredentials) (*oidc.Token, error) {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	// Read again under the lock: another goroutine may have refreshed while this one waited, and
	// redeeming an already-rotated refresh token invalidates the session for both.
	if current := loadCredentials().Identity; current != nil && current.Token.Usable() {
		return current.Token, nil
	}

	provider, err := oidc.Discover(ctx, identity.Issuer)
	if err != nil {
		return nil, err
	}
	token, err := oidc.Refresh(ctx, provider, identity.ClientID, identity.Token.RefreshToken)
	if err != nil {
		return nil, err
	}

	refreshed := *identity
	refreshed.Token = token

	return token, mergeCredentials(func(creds *Credentials) { creds.Identity = &refreshed })
}
