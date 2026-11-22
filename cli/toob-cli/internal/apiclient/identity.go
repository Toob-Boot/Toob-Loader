package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/toob-boot/toob/internal/filelock"
	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/oidc"
	"github.com/toob-boot/toob/internal/paths"
)

// AuthConfig describes how a CLI client authenticates against a Toob Registry deployment.
type AuthConfig struct {
	Issuer      string   `json:"issuer"`
	Audience    string   `json:"audience"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	AccountsURL string   `json:"accounts_url"`
	SettingsURL string   `json:"settings_url"`
}

func cloneAuthConfig(cfg *AuthConfig) *AuthConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	cp.Scopes = slices.Clone(cfg.Scopes)
	return &cp
}

// FetchAuthConfig queries the public GET /api/v1/auth/config endpoint without sending
// stored credentials, validates all advertised URLs, and memoizes the result on Client.
func (c *Client) FetchAuthConfig(ctx context.Context) (*AuthConfig, error) {
	if c.transportErr != nil {
		return nil, c.transportErr
	}

	c.authMu.Lock()
	if c.cachedAuthConfig != nil {
		cached := cloneAuthConfig(c.cachedAuthConfig)
		c.authMu.Unlock()
		return cached, nil
	}
	c.authMu.Unlock()

	if _, err := httputil.ValidateHTTPSOrLoopbackURL(c.BaseURL); err != nil {
		return nil, fmt.Errorf("invalid registry URL %q: %w", c.BaseURL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/v1/auth/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Toob-CLI")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("asking %s how to authenticate: %w", c.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s does not publish an authentication configuration; it is older than this client", c.BaseURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d when asked how to authenticate", c.BaseURL, resp.StatusCode)
	}

	raw, err := httputil.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading authentication configuration from %s: %w", c.BaseURL, err)
	}

	var config AuthConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("the registry's authentication configuration is not readable: %w", err)
	}
	if config.Issuer == "" || config.ClientID == "" {
		return nil, fmt.Errorf("%s published an incomplete authentication configuration", c.BaseURL)
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(config.Issuer); err != nil {
		return nil, fmt.Errorf("registry %s published invalid issuer URL %q: %w", c.BaseURL, config.Issuer, err)
	}
	if config.AccountsURL != "" {
		if _, err := httputil.ValidateHTTPSOrLoopbackURL(config.AccountsURL); err != nil {
			return nil, fmt.Errorf("registry %s published invalid accounts_url %q: %w", c.BaseURL, config.AccountsURL, err)
		}
	}
	if config.SettingsURL != "" {
		if _, err := httputil.ValidateHTTPSOrLoopbackURL(config.SettingsURL); err != nil {
			return nil, fmt.Errorf("registry %s published invalid settings_url %q: %w", c.BaseURL, config.SettingsURL, err)
		}
	}

	c.authMu.Lock()
	c.cachedAuthConfig = cloneAuthConfig(&config)
	c.authMu.Unlock()

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
func (c *Client) Whoami(ctx context.Context) (*Profile, error) {
	var profile Profile
	if err := c.getJSON(ctx, "/api/v1/me", &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

// HasSession reports whether a usable or refreshable interactive OIDC session is stored.
func HasSession() bool {
	creds := loadCredentials()
	if creds.Identity == nil || creds.Identity.Token == nil {
		return false
	}
	return creds.Identity.Token.RefreshToken != "" || creds.Identity.Token.Usable()
}

// IdentityCredentials holds a persisted interactive OIDC session bound to its registry origin.
type IdentityCredentials struct {
	RegistryURL string      `json:"registry_url,omitempty"`
	Issuer      string      `json:"issuer"`
	ClientID    string      `json:"client_id"`
	Subject     string      `json:"subject,omitempty"`
	Token       *oidc.Token `json:"token"`
}

var refreshMu sync.Mutex

// SaveIdentity persists an interactive session (stamping the canonical RegistryURL when unset),
// leaving any machine API key intact.
func SaveIdentity(identity *IdentityCredentials, login string) error {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	var stamped *IdentityCredentials
	if identity != nil {
		cp := *identity
		if cp.RegistryURL == "" {
			if canon, err := httputil.CanonicalOrigin(resolveBaseURL()); err == nil {
				cp.RegistryURL = canon
			}
		}
		stamped = &cp
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return mergeCredentialsLocked(ctx, func(creds *Credentials) {
		creds.Identity = stamped
		creds.Login = login
	})
}

// DeleteIdentity removes the stored interactive session, clears Login and that account's
// active organization context, and leaves any machine API key intact.
func DeleteIdentity() error {
	return deleteIdentityWithContext(context.Background())
}

func deleteIdentityWithContext(ctx context.Context) error {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var prevIssuer, prevSubject string
	if err := mergeCredentialsLocked(lockCtx, func(creds *Credentials) {
		if creds.Identity != nil {
			prevIssuer = creds.Identity.Issuer
			prevSubject = creds.Identity.Subject
		}
		creds.Identity = nil
		creds.Login = ""
	}); err != nil {
		return err
	}

	return clearOrganizationForAccount(lockCtx, prevIssuer, prevSubject)
}

// Logout revokes the stored OIDC tokens at the identity provider's RFC 7009 revocation
// endpoint when available, then deletes the local session and organization context.
func (c *Client) Logout(ctx context.Context) error {
	creds := loadCredentials()
	if creds.Identity != nil && creds.Identity.Issuer != "" && creds.Identity.Token != nil {
		revokeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if provider, err := oidc.Discover(revokeCtx, creds.Identity.Issuer); err == nil && provider.RevocationEndpoint != "" {
			if creds.Identity.Token.RefreshToken != "" {
				_ = oidc.RevokeToken(revokeCtx, provider.RevocationEndpoint, creds.Identity.ClientID, creds.Identity.Token.RefreshToken, "refresh_token")
			}
			if creds.Identity.Token.AccessToken != "" {
				_ = oidc.RevokeToken(revokeCtx, provider.RevocationEndpoint, creds.Identity.ClientID, creds.Identity.Token.AccessToken, "access_token")
			}
		}
		cancel()
	}
	return deleteIdentityWithContext(ctx)
}

func mergeCredentialsLocked(ctx context.Context, change func(*Credentials)) error {
	path, err := paths.CredentialsPath()
	if err != nil {
		return fmt.Errorf("cannot determine credentials path: %w", err)
	}
	unlock, err := filelock.Lock(ctx, path+".lock")
	if err != nil {
		return fmt.Errorf("locking credentials file: %w", err)
	}
	defer func() { _ = unlock() }()

	creds, err := loadCredentialsStrict(path)
	if err != nil {
		return err
	}
	change(&creds)

	return writeCredentialsAtomic(path, creds)
}

func loadCredentialsStrict(path string) (Credentials, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Credentials{}, nil
	}
	if err != nil {
		return Credentials{}, fmt.Errorf("opening credentials %s: %w", path, err)
	}
	data, readErr := httputil.ReadBounded(f, 1<<20)
	closeErr := f.Close()
	if readErr != nil {
		return Credentials{}, fmt.Errorf("reading credentials %s: %w", path, readErr)
	}
	if closeErr != nil {
		return Credentials{}, fmt.Errorf("closing credentials %s: %w", path, closeErr)
	}
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return Credentials{}, fmt.Errorf("corrupted credentials file %s: %w", path, err)
	}
	return creds, nil
}

func writeCredentialsAtomic(path string, creds Credentials) error {
	//nolint:gosec // G117: intentionally serializes local user credentials into 0600 file inside 0700 ToobHome.
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return mkErr
	}
	tmp, err := os.CreateTemp(dir, ".toob-creds-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (c *Client) identityMatchesOrigin(id *IdentityCredentials, clientOrigin string) bool {
	if id == nil {
		return false
	}
	if id.RegistryURL != "" {
		boundOrigin, err := httputil.CanonicalOrigin(id.RegistryURL)
		if err != nil || boundOrigin != clientOrigin {
			return false
		}
	} else {
		defaultOrigin, err := httputil.CanonicalOrigin(resolveBaseURL())
		if err != nil || defaultOrigin != clientOrigin {
			return false
		}
	}

	c.authMu.Lock()
	cached := c.cachedAuthConfig
	c.authMu.Unlock()
	if cached != nil && id.Issuer != "" && cached.Issuer != id.Issuer {
		return false
	}
	return true
}

// sessionBearer returns ONLY an origin-bound interactive OIDC session access token,
// ignoring TOOB_TOKEN and machine API keys (required by identity-api and admin routes).
func (c *Client) sessionBearer(ctx context.Context) (string, error) {
	clientOrigin, err := httputil.CanonicalOrigin(c.BaseURL)
	if err != nil {
		return "", fmt.Errorf("refusing to send session credentials to insecure URL %q: %w", c.BaseURL, err)
	}
	creds := loadCredentials()
	if creds.Identity == nil || creds.Identity.Token == nil {
		return "", ErrNoSession
	}
	if !c.identityMatchesOrigin(creds.Identity, clientOrigin) {
		return "", fmt.Errorf("stored login session belongs to a different registry origin than %s; run 'toob login' for this registry", clientOrigin)
	}
	if creds.Identity.Token.Usable() {
		return creds.Identity.Token.AccessToken, nil
	}
	if creds.Identity.Token.RefreshToken == "" {
		return "", ErrNoSession
	}
	refreshed, err := refreshSession(ctx, creds.Identity)
	if err != nil {
		return "", fmt.Errorf("refreshing login session: %w", err)
	}
	return refreshed.AccessToken, nil
}

// bearer returns the credential to present on Registry API calls, refusing to send
// credentials to non-HTTPS non-loopback targets or mismatched origins.
func (c *Client) bearer(ctx context.Context) string {
	clientOrigin, err := httputil.CanonicalOrigin(c.BaseURL)
	if err != nil {
		return ""
	}
	if token := os.Getenv(TokenEnv); token != "" {
		return token
	}
	creds := loadCredentials()
	if creds.Identity != nil && creds.Identity.Token != nil {
		if !c.identityMatchesOrigin(creds.Identity, clientOrigin) {
			return ""
		}
		if creds.Identity.Token.Usable() {
			return creds.Identity.Token.AccessToken
		}
		if creds.Identity.Token.RefreshToken != "" {
			if refreshed, refErr := refreshSession(ctx, creds.Identity); refErr == nil {
				return refreshed.AccessToken
			}
		}
		return ""
	}
	if defaultOrigin, defErr := httputil.CanonicalOrigin(resolveBaseURL()); defErr == nil && defaultOrigin == clientOrigin {
		return c.Token
	}
	return ""
}

// refreshSession trades the stored refresh token for a new one under both in-process
// and cross-process file locks so parallel CLI invocations never double-rotate a token.
func refreshSession(ctx context.Context, identity *IdentityCredentials) (*oidc.Token, error) {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	path, err := paths.CredentialsPath()
	if err != nil {
		return nil, err
	}
	unlock, err := filelock.Lock(ctx, path+".lock")
	if err != nil {
		return nil, fmt.Errorf("locking credentials for token refresh: %w", err)
	}
	defer func() { _ = unlock() }()

	diskCreds, err := loadCredentialsStrict(path)
	if err != nil {
		return nil, err
	}
	current := diskCreds.Identity
	if current != nil && current.Issuer == identity.Issuer && current.Token != nil {
		if current.Token.Usable() {
			return current.Token, nil
		}
		identity = current
	}
	if identity.Token == nil || identity.Token.RefreshToken == "" {
		return nil, errors.New("no refresh token stored")
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
	diskCreds.Identity = &refreshed
	if err := writeCredentialsAtomic(path, diskCreds); err != nil {
		return nil, err
	}
	return token, nil
}
