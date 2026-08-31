package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Token is what an issuer hands back, and what this client stores.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// expiryMargin is how long before expiry a token is treated as spent.
//
// A token that is valid for another two seconds is not usable: the request carrying it may still be
// in flight when it stops being accepted, and the caller sees an authentication failure for a token
// that was fresh when it was chosen.
const expiryMargin = 60 * time.Second

// Usable reports whether the access token can still be presented.
func (t *Token) Usable() bool {
	return t != nil && t.AccessToken != "" && time.Now().Add(expiryMargin).Before(t.ExpiresAt)
}

// tokenResponse is the wire shape. ExpiresIn is seconds, which is why Token carries an absolute time
// instead: a duration is only meaningful next to the moment it was received, and that moment is not
// something a stored file keeps.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// postForm exchanges a form at the token endpoint.
//
// No client secret anywhere in this package. A command-line tool is a public client: whatever it
// held would be readable by everyone who has the binary, so it would not be a secret. PKCE is what
// makes the exchange safe instead, and it does so without one.
func postForm(ctx context.Context, endpoint string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("the identity provider answered %d with something unreadable", resp.StatusCode)
	}

	// The error is returned even on a non-2xx, because the device flow's polling states arrive as
	// errors and the caller has to tell them apart from a real failure.
	return &parsed, nil
}

// tokenFrom turns a successful response into a stored token.
func tokenFrom(resp *tokenResponse) (*Token, error) {
	if resp.Error != "" {
		return nil, fmt.Errorf("%s: %s", resp.Error, resp.ErrorDescription)
	}
	if resp.AccessToken == "" {
		return nil, fmt.Errorf("the identity provider returned no access token")
	}

	return &Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		IDToken:      resp.IDToken,
		TokenType:    resp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
	}, nil
}

// Refresh trades a refresh token for a new access token.
//
// The response may or may not carry a new refresh token. When it does not, the old one stays valid
// and is kept; dropping it would log the person out at the next expiry for no reason.
func Refresh(ctx context.Context, provider *Provider, clientID string, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh token stored")
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
