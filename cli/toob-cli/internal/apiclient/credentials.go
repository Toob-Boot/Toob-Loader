package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
)

// Credential is a personal token, service account, or federated CI credential.
type Credential struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Kind       string     `json:"kind"`
	Name       string     `json:"name"`
	Namespace  string     `json:"namespace,omitempty"`
	Scopes     []string   `json:"scopes"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CredentialRequest asks for a personal token in TenantID, bound to Namespace.
type CredentialRequest struct {
	Name          string   `json:"name"`
	TenantID      string   `json:"tenant_id"`
	Namespace     string   `json:"namespace,omitempty"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expires_in_days,omitempty"`
}

// CreatedCredential carries a newly minted token and its one-time secret value.
type CreatedCredential struct {
	Credential Credential `json:"credential"`
	Token      string     `json:"token"`
}

// Credentials lists the signed-in person's tokens across organizations.
func (c *Client) Credentials(ctx context.Context) ([]Credential, error) {
	var answer struct {
		Credentials []Credential `json:"credentials"`
	}
	if err := c.identity(ctx, http.MethodGet, "/api/v1/me/credentials", nil, &answer); err != nil {
		return nil, err
	}
	return answer.Credentials, nil
}

// CreateCredential mints a personal token in identity-api.
func (c *Client) CreateCredential(ctx context.Context, request CredentialRequest) (*CreatedCredential, error) {
	var created CreatedCredential
	if err := c.identity(ctx, http.MethodPost, "/api/v1/me/credentials", request, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// RevokeCredential revokes one of the signed-in person's tokens.
func (c *Client) RevokeCredential(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("credential ID must not be empty")
	}
	return c.identity(ctx, http.MethodDelete, "/api/v1/me/credentials/"+url.PathEscape(id), nil, nil)
}

// ErrNotInGitHubActions indicates that GitHub Actions OIDC environment variables are absent.
var ErrNotInGitHubActions = errors.New("no GitHub Actions OIDC token is available; the job needs 'permissions: id-token: write'")

// ExchangeGitHubToken exchanges a GitHub Actions OIDC token for a short-lived Toob credential.
func (c *Client) ExchangeGitHubToken(ctx context.Context) (*CreatedCredential, error) {
	requestURL := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	requestToken := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if requestURL == "" || requestToken == "" {
		return nil, ErrNotInGitHubActions
	}
	parsedReqURL, err := httputil.ValidateHTTPSOrLoopbackURL(requestURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}

	config, err := c.FetchAuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	if config.AccountsURL == "" {
		return nil, fmt.Errorf("%s does not say where accounts are managed; it is older than this client", c.BaseURL)
	}

	q := parsedReqURL.Query()
	q.Set("audience", config.AccountsURL)
	parsedReqURL.RawQuery = q.Encode()

	//nolint:gosec // G704: parsedReqURL is validated via httputil.ValidateHTTPSOrLoopbackURL above.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedReqURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json")

	//nolint:gosec // G704: parsedReqURL is validated via httputil.ValidateHTTPSOrLoopbackURL above.
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asking GitHub for the job's OIDC token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %d when asked for the job's OIDC token", resp.StatusCode)
	}
	raw, err := httputil.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading GitHub OIDC token response: %w", err)
	}
	var issued struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &issued); err != nil || issued.Value == "" {
		return nil, fmt.Errorf("GitHub's OIDC token answer is not readable: %w", err)
	}

	var created CreatedCredential
	if err := c.accounts(ctx, http.MethodPost, "/api/v1/credentials/exchange", "", map[string]string{"token": issued.Value}, &created); err != nil {
		return nil, err
	}
	return &created, nil
}
