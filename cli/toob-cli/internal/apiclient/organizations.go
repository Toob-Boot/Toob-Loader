package apiclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/toob-boot/toob/internal/httputil"
)

// Organization is one tenant the signed-in person belongs to, with their role and active plan.
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
	Plan string `json:"plan"`
}

// Organizations lists the signed-in person's tenants and self-service creation quota.
type Organizations struct {
	Tenants     []Organization `json:"tenants"`
	Created     int            `json:"created"`
	CreateLimit int            `json:"create_limit"`
}

// Invitation represents an open e-mail organization invitation.
type Invitation struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
}

// InvitationAcceptance is returned by POST /api/v1/me/invitations/accept.
type InvitationAcceptance struct {
	Organization Organization `json:"organization"`
	Joined       bool         `json:"joined"`
}

// ErrNoSession indicates that an account/organization route was called without an interactive login.
var ErrNoSession = errors.New("organizations need a signed-in person; run 'toob login' first")

// Organizations lists the organizations the signed-in person belongs to.
func (c *Client) Organizations(ctx context.Context) (*Organizations, error) {
	var answer Organizations
	if err := c.identity(ctx, http.MethodGet, "/api/v1/me/tenants", nil, &answer); err != nil {
		return nil, err
	}
	return &answer, nil
}

// CreateOrganization creates a self-service tenant owned by the signed-in person.
func (c *Client) CreateOrganization(ctx context.Context, name string) (*Organization, error) {
	var created Organization
	if err := c.identity(ctx, http.MethodPost, "/api/v1/me/tenants", map[string]string{"name": name}, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// Invite sends an organization membership invitation by e-mail.
func (c *Client) Invite(ctx context.Context, tenantID, email, role string) (*Invitation, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("organization ID must not be empty")
	}
	var invitation Invitation
	path := "/api/v1/tenants/" + url.PathEscape(tenantID) + "/invitations"
	if err := c.identity(ctx, http.MethodPost, path, map[string]string{"email": email, "role": role}, &invitation); err != nil {
		return nil, err
	}
	return &invitation, nil
}

// AcceptInvitation accepts an e-mail invitation token via POST /api/v1/me/invitations/accept.
func (c *Client) AcceptInvitation(ctx context.Context, token string) (*InvitationAcceptance, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("invitation token must not be empty")
	}
	var accepted InvitationAcceptance
	if err := c.identity(ctx, http.MethodPost, "/api/v1/me/invitations/accept", map[string]string{"token": token}, &accepted); err != nil {
		return nil, err
	}
	return &accepted, nil
}

// LeaveOrganization ends the signed-in person's membership in tenantID.
func (c *Client) LeaveOrganization(ctx context.Context, tenantID string) error {
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("organization ID must not be empty")
	}
	return c.identity(ctx, http.MethodDelete, "/api/v1/tenants/"+url.PathEscape(tenantID)+"/membership", nil, nil)
}

// identity calls identity-api strictly with the interactive OIDC session (never TOOB_TOKEN).
func (c *Client) identity(ctx context.Context, method, path string, body, out any) error {
	if !HasSession() {
		return ErrNoSession
	}
	bearer, err := c.sessionBearer(ctx)
	if err != nil {
		return err
	}
	return c.accounts(ctx, method, path, bearer, body, out)
}

// accounts calls identity-api at AuthConfig.AccountsURL with bounded reads, Idempotency-Key,
// and transient retry protection.
func (c *Client) accounts(ctx context.Context, method, path, bearer string, body, out any) error {
	config, err := c.FetchAuthConfig(ctx)
	if err != nil {
		return err
	}
	if config.AccountsURL == "" {
		return fmt.Errorf("%s does not say where accounts are managed; it is older than this client", c.BaseURL)
	}
	if _, urlErr := httputil.ValidateHTTPSOrLoopbackURL(config.AccountsURL); urlErr != nil {
		return fmt.Errorf("refusing to contact insecure accounts_url %q: %w", config.AccountsURL, urlErr)
	}

	var payload io.Reader
	if body != nil {
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return marshalErr
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(config.AccountsURL, "/")+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Toob-CLI")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Idempotency-Key", rand.Text())
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return extractError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	raw, err := httputil.ReadBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
