// Package oidc is how the command line authenticates a person.
//
// It replaces a GitHub OAuth flow that talked to four registry endpoints — /api/v1/auth/github,
// /api/v1/auth/token, /api/v1/auth/logout and /api/v1/auth/rotate-key — none of which the registry
// serves any more. What took their place is the identity provider itself: the registry verifies
// tokens it issues, so the client asks it for one directly rather than asking the registry to
// broker a third party's login.
//
// Nothing here is specific to a deployment. The client is configured with one thing — the registry's
// URL — asks it who issues its tokens, and asks that issuer where its endpoints are. Both steps are
// protocol-defined, so an environment cannot be half-configured into a client.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Provider is what an issuer publishes about itself.
type Provider struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	EndSessionEndpoint          string   `json:"end_session_endpoint"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
	GrantTypes                  []string `json:"grant_types_supported"`
}

// Discover reads the issuer's metadata.
//
// The document's own issuer must equal the one asked for. RFC 8414 requires the check and the reason
// is direct: everything else here — where to send a person to log in, where to exchange their code —
// is taken from a document fetched over the network, and without that comparison a redirect could
// hand those addresses to somebody else's server.
func Discover(ctx context.Context, issuer string) (*Provider, error) {
	issuer = strings.TrimSuffix(issuer, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading the identity provider's configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the identity provider at %s answered %d for its configuration", issuer, resp.StatusCode)
	}

	var provider Provider
	if err := json.NewDecoder(resp.Body).Decode(&provider); err != nil {
		return nil, fmt.Errorf("the identity provider's configuration is not readable: %w", err)
	}
	if provider.Issuer != issuer {
		return nil, fmt.Errorf("the configuration at %s claims to belong to %q; refusing to send a login anywhere it names",
			issuer, provider.Issuer)
	}
	if provider.TokenEndpoint == "" {
		return nil, fmt.Errorf("the identity provider at %s publishes no token endpoint", issuer)
	}

	return &provider, nil
}

// SupportsS256 reports whether the provider accepts the only code challenge method this client uses.
//
// Only S256. The "plain" method sends the verifier itself as the challenge, which protects against
// nothing; a provider that offers only plain is one this client will not complete a login against.
func (p *Provider) SupportsS256() bool {
	for _, method := range p.CodeChallengeMethods {
		if method == "S256" {
			return true
		}
	}

	return false
}

// SupportsDeviceFlow reports whether a login without a browser on this machine is possible.
func (p *Provider) SupportsDeviceFlow() bool {
	if p.DeviceAuthorizationEndpoint == "" {
		return false
	}
	for _, grant := range p.GrantTypes {
		if grant == "urn:ietf:params:oauth:grant-type:device_code" {
			return true
		}
	}

	return false
}
