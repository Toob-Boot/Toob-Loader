package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Credential is a personal token, a service account or a CI run's credential; its secret is shown
// once, when it is made.
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

// CredentialRequest asks for a personal token in TenantID, bound to Namespace. Zero days is
// identity's default lifetime.
type CredentialRequest struct {
	Name          string   `json:"name"`
	TenantID      string   `json:"tenant_id"`
	Namespace     string   `json:"namespace,omitempty"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expires_in_days,omitempty"`
}

// CreatedCredential carries the secret, this once.
type CreatedCredential struct {
	Credential Credential `json:"credential"`
	Token      string     `json:"token"`
}

// Credentials lists the signed-in person's tokens in every organization.
func (c *Client) Credentials(ctx context.Context) ([]Credential, error) {
	var answer struct {
		Credentials []Credential `json:"credentials"`
	}
	return answer.Credentials, c.identity(ctx, http.MethodGet, "/api/v1/me/credentials", nil, &answer)
}

// CreateCredential makes a personal token; an organization may hold it for approval.
func (c *Client) CreateCredential(ctx context.Context, request CredentialRequest) (*CreatedCredential, error) {
	var created CreatedCredential
	return &created, c.identity(ctx, http.MethodPost, "/api/v1/me/credentials", request, &created)
}

// RevokeCredential ends one of the person's tokens.
func (c *Client) RevokeCredential(ctx context.Context, id string) error {
	return c.identity(ctx, http.MethodDelete, "/api/v1/me/credentials/"+url.PathEscape(id), nil, nil)
}

// ErrNotInGitHubActions is an exchange outside a GitHub Actions job allowed an OIDC token.
var ErrNotInGitHubActions = errors.New("no GitHub Actions OIDC token is available; the job needs 'permissions: id-token: write'")

// ExchangeGitHubToken trades the running GitHub Actions job's OIDC token, issued for identity's
// origin, for a short-lived credential of the organization that trusts the workflow.
func (c *Client) ExchangeGitHubToken(ctx context.Context) (*CreatedCredential, error) {
	requestURL, requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return nil, ErrNotInGitHubActions
	}
	config, err := c.FetchAuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	if config.AccountsURL == "" {
		return nil, fmt.Errorf("%s does not say where accounts are managed; it is older than this client", c.BaseURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL+"&audience="+url.QueryEscape(config.AccountsURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asking GitHub for the job's OIDC token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %d when asked for the job's OIDC token", resp.StatusCode)
	}
	var issued struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil || issued.Value == "" {
		return nil, fmt.Errorf("GitHub's OIDC token answer is not readable: %v", err)
	}

	var created CreatedCredential
	return &created, c.accounts(ctx, http.MethodPost, "/api/v1/credentials/exchange", "", map[string]string{"token": issued.Value}, &created)
}
