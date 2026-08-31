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
)

// DeviceLogin is a login for a machine with no browser of its own: a server over SSH, a container, a
// terminal on a box nobody is sitting at. The person completes it on a device that does have one.
//
// This replaces the old out-of-band redirect (urn:ietf:wg:oauth:2.0:oob), which is deprecated and
// which no current provider accepts. The device grant is the flow that was designed for the case.
type DeviceLogin struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete already contains the code, so a person with a browser can follow one
	// link instead of typing anything. Providers are not required to send it.
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	provider *Provider
	clientID string
}

// StartDeviceLogin asks the provider for a code the person can enter elsewhere.
func StartDeviceLogin(ctx context.Context, provider *Provider, clientID, audience string, scopes []string) (*DeviceLogin, error) {
	if !provider.SupportsDeviceFlow() {
		return nil, errors.New("the identity provider does not offer a login for devices without a browser")
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

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the identity provider answered %d when asked for a device code", resp.StatusCode)
	}

	var login DeviceLogin
	if err := json.NewDecoder(resp.Body).Decode(&login); err != nil {
		return nil, fmt.Errorf("the device code response is not readable: %w", err)
	}
	if login.DeviceCode == "" || login.UserCode == "" {
		return nil, errors.New("the identity provider returned an incomplete device code response")
	}
	if login.Interval <= 0 {
		// RFC 8628 says five seconds when the provider names no interval.
		login.Interval = 5
	}
	login.provider = provider
	login.clientID = clientID

	return &login, nil
}

// Wait polls until the person approves, refuses, or the code expires.
//
// The polling rules are the protocol's, and following them is not politeness: a provider that
// answers slow_down and is polled at the old rate will start refusing the client outright.
func (d *DeviceLogin) Wait(ctx context.Context) (*Token, error) {
	interval := time.Duration(d.Interval) * time.Second

	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	if d.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("gave up waiting for the login to be approved: %w", ctx.Err())
		case <-time.After(interval):
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
			// The person has not finished yet. Keep the same interval.
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return nil, errors.New("the login was refused")
		case "expired_token":
			return nil, errors.New("the device code expired before the login was approved")
		default:
			return nil, fmt.Errorf("%s: %s", resp.Error, resp.ErrorDescription)
		}
	}
}
