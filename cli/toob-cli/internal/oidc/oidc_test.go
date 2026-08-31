package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/oidc"
)

// discoveryServer serves a metadata document that names itself, unless told otherwise.
func discoveryServer(t *testing.T, issuerOverride string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := server.URL
		if issuerOverride != "" {
			issuer = issuerOverride
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           issuer,
			"authorization_endpoint":           server.URL + "/authorize",
			"token_endpoint":                   server.URL + "/token",
			"device_authorization_endpoint":    server.URL + "/device",
			"code_challenge_methods_supported": []string{"S256"},
			"grant_types_supported":            []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		})
	})

	return server
}

// A discovery document must name the issuer it was fetched from (RFC 8414).
//
// Everything else in it — where to send a person to sign in, where their code is exchanged — is
// taken from a document fetched over the network. Without this comparison, a redirect on the way to
// the issuer could hand those addresses to somebody else's server, and the client would follow them.
func TestDiscover_RefusesADocumentThatNamesAnotherIssuer(t *testing.T) {
	server := discoveryServer(t, "https://somewhere-else.example")

	if _, err := oidc.Discover(context.Background(), server.URL); err == nil {
		t.Error("a configuration claiming to belong to another issuer was accepted")
	}
}

func TestDiscover_ReadsTheEndpointsItIsGiven(t *testing.T) {
	server := discoveryServer(t, "")

	provider, err := oidc.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("discovering %s: %v", server.URL, err)
	}
	if provider.TokenEndpoint != server.URL+"/token" {
		t.Errorf("token endpoint is %q", provider.TokenEndpoint)
	}
	if !provider.SupportsS256() {
		t.Error("a provider offering S256 was not recognised as offering it")
	}
	if !provider.SupportsDeviceFlow() {
		t.Error("a provider offering the device grant was not recognised as offering it")
	}
}

// Only S256. The "plain" method sends the verifier as the challenge and protects against nothing, so
// a provider offering only plain must not be completed against.
func TestProvider_DoesNotAcceptPlainPKCE(t *testing.T) {
	provider := &oidc.Provider{CodeChallengeMethods: []string{"plain"}}

	if provider.SupportsS256() {
		t.Error("a provider offering only the plain challenge method was treated as usable")
	}
	if _, err := oidc.StartBrowserLogin(provider, "client", "aud", []string{"openid"}); err == nil {
		t.Error("a browser sign-in started against a provider that cannot do S256")
	}
}

// The challenge has to be the S256 of the verifier, or the exchange fails at the issuer with an
// error that says nothing about which half was wrong.
func TestNewPKCE_ChallengeIsTheHashOfTheVerifier(t *testing.T) {
	pkce, err := oidc.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(pkce.Verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); pkce.Challenge != want {
		t.Errorf("challenge %q is not the S256 of the verifier", pkce.Challenge)
	}
	if strings.ContainsAny(pkce.Verifier+pkce.Challenge, "+/=") {
		t.Error("the verifier or challenge is standard base64; RFC 7636 requires base64url without padding")
	}
}

func TestNewPKCE_IsDifferentEveryTime(t *testing.T) {
	first, err := oidc.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	second, err := oidc.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if first.Verifier == second.Verifier {
		t.Error("two sign-ins would share a PKCE verifier")
	}
}

// The callback carries a state this client issued, or it is not this client's callback.
//
// Without the check, anything able to reach the loopback port could hand the client an authorization
// code of its own choosing and have the client redeem it — the code injection that state exists to
// prevent.
func TestBrowserLogin_RefusesACallbackWithTheWrongState(t *testing.T) {
	server := discoveryServer(t, "")
	provider, err := oidc.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	login, err := oidc.StartBrowserLogin(provider, "client", "aud", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	defer login.Close()

	resp, err := http.Get(login.Redirect() + "?code=stolen&state=not-the-one-issued")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("the loopback callback accepted a state this client never issued")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := login.Wait(ctx); err == nil {
		t.Error("a sign-in completed from a callback with the wrong state")
	}
}

// The authorization request has to carry the challenge, the method and a redirect on the loopback.
func TestBrowserLogin_AsksForWhatTheExchangeWillRequire(t *testing.T) {
	server := discoveryServer(t, "")
	provider, err := oidc.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	login, err := oidc.StartBrowserLogin(provider, "client-123", "the-audience", []string{"openid", "offline_access"})
	if err != nil {
		t.Fatal(err)
	}
	defer login.Close()

	parsed, err := url.Parse(login.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()

	for name, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "client-123",
		"code_challenge_method": "S256",
		"audience":              "the-audience",
		"scope":                 "openid offline_access",
	} {
		if got := query.Get(name); got != want {
			t.Errorf("the authorization request sends %s=%q, expected %q", name, got, want)
		}
	}
	if query.Get("code_challenge") == "" || query.Get("state") == "" {
		t.Error("the authorization request carries no challenge or no state")
	}
	if !strings.HasPrefix(query.Get("redirect_uri"), "http://127.0.0.1:") {
		t.Errorf("the redirect is %q; RFC 8252 wants a loopback address on an ephemeral port", query.Get("redirect_uri"))
	}
}

// A token about to expire is not usable. The request carrying it may still be in flight when it
// stops being accepted, and the caller then sees an authentication failure for a token that was
// fresh when it was chosen.
func TestToken_TreatsAnImminentExpiryAsSpent(t *testing.T) {
	almost := &oidc.Token{AccessToken: "a", ExpiresAt: time.Now().Add(5 * time.Second)}
	if almost.Usable() {
		t.Error("a token expiring in five seconds was treated as usable")
	}

	fresh := &oidc.Token{AccessToken: "a", ExpiresAt: time.Now().Add(10 * time.Minute)}
	if !fresh.Usable() {
		t.Error("a token valid for ten minutes was treated as spent")
	}
}

// A refresh that returns no new refresh token keeps the old one. Dropping it would sign the person
// out at the next expiry for no reason.
func TestRefresh_KeepsTheRefreshTokenWhenTheIssuerSendsNone(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "expires_in": 3600})
	})

	token, err := oidc.Refresh(context.Background(), &oidc.Provider{TokenEndpoint: server.URL + "/token"}, "client", "the-refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if token.RefreshToken != "the-refresh-token" {
		t.Errorf("the refresh token became %q", token.RefreshToken)
	}
	if !token.Usable() {
		t.Error("the refreshed token is not usable")
	}
}

// The device flow's polling rules are the protocol's, and slow_down is not advice: a provider that
// is polled at the old rate after sending it starts refusing the client outright.
func TestDeviceLogin_SlowsDownWhenAskedTo(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	polls := 0
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev", "user_code": "ABCD-EFGH",
			"verification_uri": "https://example.test/device", "expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		polls++
		if polls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "slow_down"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "granted", "expires_in": 3600})
	})

	provider := &oidc.Provider{
		TokenEndpoint:               server.URL + "/token",
		DeviceAuthorizationEndpoint: server.URL + "/device",
		GrantTypes:                  []string{"urn:ietf:params:oauth:grant-type:device_code"},
	}

	login, err := oidc.StartDeviceLogin(context.Background(), provider, "client", "aud", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := login.Wait(ctx)
	if err != nil {
		t.Fatalf("the device sign-in failed: %v", err)
	}
	if token.AccessToken != "granted" {
		t.Errorf("got token %q", token.AccessToken)
	}
	if polls < 2 {
		t.Error("the client did not poll again after being told to slow down")
	}
}

// A refusal ends the wait rather than being polled through to the expiry.
func TestDeviceLogin_StopsWhenTheSignInIsRefused(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev", "user_code": "ABCD", "verification_uri": "https://example.test", "expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "access_denied"})
	})

	provider := &oidc.Provider{
		TokenEndpoint:               server.URL + "/token",
		DeviceAuthorizationEndpoint: server.URL + "/device",
		GrantTypes:                  []string{"urn:ietf:params:oauth:grant-type:device_code"},
	}
	login, err := oidc.StartDeviceLogin(context.Background(), provider, "client", "aud", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := login.Wait(ctx); err == nil {
		t.Error("a refused sign-in was not reported as refused")
	}
}
