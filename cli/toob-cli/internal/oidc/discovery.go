// Package oidc implements OpenID Connect discovery, PKCE browser login,
// RFC 8628 device authorization grant, token refresh, and RFC 7009 revocation.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
)

const maxOIDCResponseBytes = 1 << 20 // 1 MiB

// Provider holds OIDC discovery metadata published by an issuer.
type Provider struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	RevocationEndpoint          string   `json:"revocation_endpoint"`
	EndSessionEndpoint          string   `json:"end_session_endpoint"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
	GrantTypes                  []string `json:"grant_types_supported"`
}

// Discover fetches and validates the issuer's /.well-known/openid-configuration document.
func Discover(ctx context.Context, issuer string) (*Provider, error) {
	expectedIssuer := strings.TrimSpace(issuer)
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(expectedIssuer); err != nil {
		return nil, fmt.Errorf("invalid identity provider issuer %q: %w", expectedIssuer, err)
	}

	wellKnownURL := strings.TrimSuffix(expectedIssuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client, err := httputil.NewClient(15 * time.Second)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading the identity provider's configuration: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the identity provider at %s answered %d for its configuration", expectedIssuer, resp.StatusCode)
	}

	raw, err := httputil.ReadBounded(resp.Body, maxOIDCResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("reading the identity provider's configuration: %w", err)
	}

	var provider Provider
	if err := json.Unmarshal(raw, &provider); err != nil {
		return nil, fmt.Errorf("the identity provider's configuration is not readable: %w", err)
	}
	if provider.Issuer != expectedIssuer {
		return nil, fmt.Errorf("the configuration at %s claims to belong to %q; refusing to send a login anywhere it names",
			expectedIssuer, provider.Issuer)
	}
	if provider.TokenEndpoint == "" {
		return nil, fmt.Errorf("the identity provider at %s publishes no token endpoint", expectedIssuer)
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(provider.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("invalid token_endpoint %q: %w", provider.TokenEndpoint, err)
	}
	for _, ep := range []struct {
		name string
		val  string
	}{
		{"authorization_endpoint", provider.AuthorizationEndpoint},
		{"device_authorization_endpoint", provider.DeviceAuthorizationEndpoint},
		{"revocation_endpoint", provider.RevocationEndpoint},
		{"end_session_endpoint", provider.EndSessionEndpoint},
	} {
		if ep.val != "" {
			if _, err := httputil.ValidateHTTPSOrLoopbackURL(ep.val); err != nil {
				return nil, fmt.Errorf("invalid %s %q: %w", ep.name, ep.val, err)
			}
		}
	}

	return &provider, nil
}

// SupportsS256 reports whether the provider accepts S256 PKCE code challenges.
func (p *Provider) SupportsS256() bool {
	return p != nil && slices.Contains(p.CodeChallengeMethods, "S256")
}

// SupportsDeviceFlow reports whether RFC 8628 device authorization is offered.
func (p *Provider) SupportsDeviceFlow() bool {
	if p == nil || p.DeviceAuthorizationEndpoint == "" {
		return false
	}
	return slices.Contains(p.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code")
}
