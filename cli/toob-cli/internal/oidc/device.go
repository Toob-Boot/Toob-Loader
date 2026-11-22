package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
)

// DeviceLogin implements RFC 8628 OAuth 2.0 Device Authorization Grant for headless hosts.
type DeviceLogin struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	provider *Provider
	clientID string
}

// StartDeviceLogin requests a device code and user verification URI from the provider.
func StartDeviceLogin(ctx context.Context, provider *Provider, clientID, audience string, scopes []string) (*DeviceLogin, error) {
	if !provider.SupportsDeviceFlow() {
		return nil, errors.New("the identity provider does not offer a login for devices without a browser")
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(provider.DeviceAuthorizationEndpoint); err != nil {
		return nil, fmt.Errorf("invalid device_authorization_endpoint: %w", err)
	}

	form := url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(scopes, " ")},
	}
	if audience != "" {
		form.Set("audience", audience)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
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
		return nil, fmt.Errorf("reading device code response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the identity provider answered %d when asked for a device code", resp.StatusCode)
	}

	var login DeviceLogin
	if err := json.Unmarshal(raw, &login); err != nil {
		return nil, fmt.Errorf("the device code response is not readable: %w", err)
	}
	login.VerificationURI = strings.TrimSpace(login.VerificationURI)
	login.VerificationURIComplete = strings.TrimSpace(login.VerificationURIComplete)
	if login.DeviceCode == "" || login.UserCode == "" || login.VerificationURI == "" {
		return nil, errors.New("the identity provider returned an incomplete device code response")
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(login.VerificationURI); err != nil {
		return nil, fmt.Errorf("invalid verification_uri %q: %w", login.VerificationURI, err)
	}
	if login.VerificationURIComplete != "" {
		if _, err := httputil.ValidateHTTPSOrLoopbackURL(login.VerificationURIComplete); err != nil {
			return nil, fmt.Errorf("invalid verification_uri_complete %q: %w", login.VerificationURIComplete, err)
		}
	}
	if login.Interval <= 0 {
		login.Interval = 5
	}
	login.provider = provider
	login.clientID = clientID

	return &login, nil
}

// Wait polls the token endpoint until approval, denial, or expiry.
func (d *DeviceLogin) Wait(ctx context.Context) (*Token, error) {
	interval := time.Duration(d.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	if d.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("gave up waiting for the login to be approved: %w", ctx.Err())
		case <-timer.C:
		}

		if time.Now().After(deadline) {
			return nil, errors.New("the device code expired before the login was approved")
		}

		resp, err := postForm(ctx, d.provider.TokenEndpoint, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {d.DeviceCode},
			"client_id":   {d.clientID},
		})
		if err != nil {
			return nil, err
		}

		switch resp.Error {
		case "":
			return tokenFrom(resp)
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return nil, errors.New("the login was refused")
		case "expired_token":
			return nil, errors.New("the device code expired before the login was approved")
		default:
			return nil, fmt.Errorf("%s: %s", resp.Error, resp.ErrorDescription)
		}

		timer.Reset(interval)
	}
}
