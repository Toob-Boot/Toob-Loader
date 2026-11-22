package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
)

// Token holds OAuth2 / OIDC credentials persisted for a signed-in session.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

const (
	expiryMargin       = 60 * time.Second
	defaultTokenExpiry = 5 * time.Minute
)

// Usable reports whether the access token is non-empty and valid past expiryMargin.
func (t *Token) Usable() bool {
	return t != nil && t.AccessToken != "" && time.Now().Add(expiryMargin).Before(t.ExpiresAt)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func postForm(ctx context.Context, endpoint string, form url.Values) (*tokenResponse, error) {
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(endpoint); err != nil {
		return nil, fmt.Errorf("invalid token endpoint %q: %w", endpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client, err := httputil.NewClient(30 * time.Second)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := httputil.ReadBounded(resp.Body, maxOIDCResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("reading token endpoint response: %w", err)
	}

	var parsed tokenResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("the identity provider answered %d with something unreadable", resp.StatusCode)
	}

	// Non-2xx responses without an RFC 6749 error code (e.g. 503 Problem Details) must fail explicitly.
	if (resp.StatusCode < 200 || resp.StatusCode >= 300) && parsed.Error == "" {
		return nil, fmt.Errorf("the identity provider token endpoint answered HTTP %d", resp.StatusCode)
	}

	return &parsed, nil
}

func jwtExpiry(rawJWT string) (time.Time, bool) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	exp := time.Unix(claims.Exp, 0)
	if !exp.After(time.Now()) {
		return time.Time{}, false
	}
	return exp, true
}

func resolveTokenExpiry(resp *tokenResponse) time.Time {
	now := time.Now()
	if resp.ExpiresIn > 60 {
		return now.Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	if exp, ok := jwtExpiry(resp.AccessToken); ok {
		return exp
	}
	if exp, ok := jwtExpiry(resp.IDToken); ok {
		return exp
	}
	if resp.ExpiresIn > 0 {
		return now.Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	return now.Add(defaultTokenExpiry)
}

func tokenFrom(resp *tokenResponse) (*Token, error) {
	if resp.Error != "" {
		return nil, fmt.Errorf("%s: %s", resp.Error, resp.ErrorDescription)
	}
	if resp.AccessToken == "" {
		return nil, errors.New("the identity provider returned no access token")
	}

	return &Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		IDToken:      resp.IDToken,
		TokenType:    resp.TokenType,
		ExpiresAt:    resolveTokenExpiry(resp),
	}, nil
}

// Refresh exchanges a refresh token for a fresh access token, preserving the existing
// refresh token when the issuer does not rotate it.
func Refresh(ctx context.Context, provider *Provider, clientID, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, errors.New("no refresh token stored")
	}
	if provider == nil || provider.TokenEndpoint == "" {
		return nil, errors.New("identity provider has no token endpoint")
	}

	resp, err := postForm(ctx, provider.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	if err != nil {
		return nil, err
	}

	token, err := tokenFrom(resp)
	if err != nil {
		return nil, err
	}
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}

	return token, nil
}

// RevokeToken revokes an access or refresh token at the provider's RFC 7009 revocation endpoint.
func RevokeToken(ctx context.Context, revocationEndpoint, clientID, token, tokenTypeHint string) error {
	revocationEndpoint = strings.TrimSpace(revocationEndpoint)
	token = strings.TrimSpace(token)
	if revocationEndpoint == "" || token == "" {
		return errors.New("revocation endpoint and token must not be empty")
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(revocationEndpoint); err != nil {
		return fmt.Errorf("invalid revocation endpoint %q: %w", revocationEndpoint, err)
	}

	form := url.Values{"token": {token}}
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client, err := httputil.NewClient(15 * time.Second)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("revoking token at identity provider: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	_, _ = httputil.ReadBounded(resp.Body, 64<<10)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("identity provider answered HTTP %d to token revocation", resp.StatusCode)
	}
	return nil
}
