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
)

// Organization is one the signed-in person belongs to, with their role and the plan in force.
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
	Plan string `json:"plan"`
}

// Organizations is the person's organizations and their self-service quota.
type Organizations struct {
	Tenants     []Organization `json:"tenants"`
	Created     int            `json:"created"`
	CreateLimit int            `json:"create_limit"`
}

// Invitation is an open invitation; its link travels by e-mail only.
type Invitation struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
}

// ErrNoSession is an organization command without a person signed in. An API key reaches the
// registry only.
var ErrNoSession = errors.New("organizations need a signed-in person; run 'toob login' first")

// Organizations lists the organizations the signed-in person belongs to.
func (c *Client) Organizations(ctx context.Context) (*Organizations, error) {
	var answer Organizations
	return &answer, c.identity(ctx, http.MethodGet, "/api/v1/me/tenants", nil, &answer)
}

// CreateOrganization creates an organization of the person's own, which they then own.
func (c *Client) CreateOrganization(ctx context.Context, name string) (*Organization, error) {
	var created Organization
	return &created, c.identity(ctx, http.MethodPost, "/api/v1/me/tenants", map[string]string{"name": name}, &created)
}

// Invite sends an invitation by e-mail to join the organization in a role up to the person's own.
func (c *Client) Invite(ctx context.Context, tenantID, email, role string) (*Invitation, error) {
	var invitation Invitation
	path := "/api/v1/tenants/" + url.PathEscape(tenantID) + "/invitations"
	return &invitation, c.identity(ctx, http.MethodPost, path, map[string]string{"email": email, "role": role}, &invitation)
}

// LeaveOrganization ends the person's membership; the last owner cannot leave.
func (c *Client) LeaveOrganization(ctx context.Context, tenantID string) error {
	return c.identity(ctx, http.MethodDelete, "/api/v1/tenants/"+url.PathEscape(tenantID)+"/membership", nil, nil)
}

// identity calls identity-api at the origin the registry publishes, with the person's session.
func (c *Client) identity(ctx context.Context, method, path string, body, out any) error {
	if !HasSession() {
		return ErrNoSession
	}
	return c.accounts(ctx, method, path, c.bearer(ctx), body, out)
}

// accounts calls identity-api at the origin the registry publishes; bearer is empty for a call
// nobody is signed in to.
func (c *Client) accounts(ctx context.Context, method, path, bearer string, body, out any) error {
	config, err := c.FetchAuthConfig(ctx)
	if err != nil {
		return err
	}
	if config.AccountsURL == "" {
		return fmt.Errorf("%s does not say where accounts are managed; it is older than this client", c.BaseURL)
	}

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
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
	var resp *http.Response
	if method == http.MethodGet {
		resp, err = c.doWithRetry(req)
	} else {
		// Sent once: identity refuses a change without a key, and a body is read by its first send.
		req.Header.Set("Idempotency-Key", rand.Text())
		resp, err = c.HTTPClient.Do(req)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return extractError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
