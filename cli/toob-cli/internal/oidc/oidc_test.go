package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/oidc"
)

func discoveryServer(t *testing.T, issuerOverride string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		issuer := server.URL
		if issuerOverride != "" {
			issuer = issuerOverride
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           issuer,
			"authorization_endpoint":           server.URL + "/authorize",
			"token_endpoint":                   server.URL + "/token",
			"device_authorization_endpoint":    server.URL + "/device",
			"revocation_endpoint":              server.URL + "/revoke",
			"code_challenge_methods_supported": []string{"S256"},
			"grant_types_supported":            []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		})
	})

	return server
}

func TestDiscover_RefusesADocumentThatNamesAnotherIssuer(t *testing.T) {
	server := discoveryServer(t, "https://somewhere-else.example")

	if _, err := oidc.Discover(t.Context(), server.URL); err == nil {
		t.Error("a configuration claiming to belong to another issuer was accepted")
	}
}

func TestDiscover_PreservesTrailingSlashIssuerExactMatch(t *testing.T) {
	var server *httptest.Server
	mux := http.NewServeMux()
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           server.URL + "/",
			"authorization_endpoint":           server.URL + "/authorize",
			"token_endpoint":                   server.URL + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})

	provider, err := oidc.Discover(t.Context(), server.URL+"/")
	if err != nil {
		t.Fatalf("Discover with trailing-slash issuer failed: %v", err)
	}
	if provider.Issuer != server.URL+"/" {
		t.Fatalf("provider.Issuer = %q, want %q", provider.Issuer, server.URL+"/")
	}
}

func TestDiscover_ReadsTheEndpointsItIsGiven(t *testing.T) {
	server := discoveryServer(t, "")

	provider, err := oidc.Discover(t.Context(), server.URL)
	if err != nil {
		t.Fatalf("discovering %s: %v", server.URL, err)
	}
	if provider.TokenEndpoint != server.URL+"/token" {
		t.Errorf("token endpoint is %q", provider.TokenEndpoint)
	}
	if !provider.SupportsS256() {
		t.Error("a provider offering S256 was not recognized as offering it")
	}
	if !provider.SupportsDeviceFlow() {
		t.Error("a provider offering the device grant was not recognized as offering it")
	}
}

func TestProvider_DoesNotAcceptPlainPKCE(t *testing.T) {
	provider := &oidc.Provider{CodeChallengeMethods: []string{"plain"}}

	if provider.SupportsS256() {
		t.Error("a provider offering only the plain challenge method was treated as usable")
	}
	if _, err := oidc.StartBrowserLogin(provider, "client", "aud", []string{"openid"}); err == nil {
		t.Error("a browser sign-in started against a provider that cannot do S256")
	}
}

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

func TestBrowserLogin_IgnoresBadProbesAndCompletesOnValidCallback(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "browser-access-token",
			"expires_in":   3600,
		})
	})

	provider := &oidc.Provider{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize?realm=embedded",
		TokenEndpoint:         server.URL + "/token",
		CodeChallengeMethods:  []string{"S256"},
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
	if got := query.Get("realm"); got != "embedded" {
		t.Fatalf("existing query param realm lost: got %q", got)
	}
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
	validState := query.Get("state")
	if query.Get("code_challenge") == "" || validState == "" {
		t.Fatal("missing PKCE challenge or state")
	}

	// 1. POST probe must return 405 without killing the listener.
	postResp, err := http.Post(login.Redirect(), "text/plain", strings.NewReader("probe"))
	if err != nil {
		t.Fatal(err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on POST probe, got %d", postResp.StatusCode)
	}

	// 2. Wrong-state GET probe must return 400 without killing the active sign-in.
	badStateResp, err := http.Get(login.Redirect() + "?code=stolen&state=wrong-state")
	if err != nil {
		t.Fatal(err)
	}
	_ = badStateResp.Body.Close()
	if badStateResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on mismatched state, got %d", badStateResp.StatusCode)
	}

	// 3. Genuine redirect with valid state must still succeed!
	goodResp, err := http.Get(login.Redirect() + "?code=valid-code&state=" + url.QueryEscape(validState))
	if err != nil {
		t.Fatal(err)
	}
	_ = goodResp.Body.Close()
	if goodResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on valid callback, got %d", goodResp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tok, err := login.Wait(ctx)
	if err != nil {
		t.Fatalf("BrowserLogin.Wait failed after valid callback: %v", err)
	}
	if tok.AccessToken != "browser-access-token" {
		t.Fatalf("got token %q", tok.AccessToken)
	}
}

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

func TestRefresh_JWTExpiryFallback503ErrorAndRevokeToken(t *testing.T) {
	expUnix := time.Now().Add(30 * time.Minute).Unix()
	jwtHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	jwtPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, expUnix)))
	fakeJWT := jwtHeader + "." + jwtPayload + ".sig"

	mode := "jwt-no-expires-in"
	var revokedToken, revokedHint string

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		if mode == "503" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "upstream unavailable"})
			return
		}
		// Deliberately omit expires_in so JWT exp fallback is exercised.
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fakeJWT})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		revokedToken = r.FormValue("token")
		revokedHint = r.FormValue("token_type_hint")
		w.WriteHeader(http.StatusOK)
	})

	provider := &oidc.Provider{TokenEndpoint: server.URL + "/token", RevocationEndpoint: server.URL + "/revoke"}
	tok, err := oidc.Refresh(t.Context(), provider, "client", "the-refresh-token")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if tok.RefreshToken != "the-refresh-token" || !tok.Usable() {
		t.Fatalf("expected usable token keeping refresh token, got %+v", tok)
	}

	mode = "503"
	if _, err := oidc.Refresh(t.Context(), provider, "client", "the-refresh-token"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected HTTP 503 failure on non-OAuth Problem Details JSON, got %v", err)
	}

	if err := oidc.RevokeToken(t.Context(), provider.RevocationEndpoint, "client", "the-refresh-token", "refresh_token"); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}
	if revokedToken != "the-refresh-token" || revokedHint != "refresh_token" {
		t.Fatalf("unexpected revoke payload: token=%q hint=%q", revokedToken, revokedHint)
	}
}

func TestDeviceLogin_SlowsDownAndRejectsEmptyVerificationURI(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	emptyURI := true
	polls := 0
	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		if emptyURI {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dev", "user_code": "ABCD-EFGH", "expires_in": 60, "interval": 1,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev", "user_code": "ABCD-EFGH",
			"verification_uri": "https://example.test/device", "expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
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

	if _, err := oidc.StartDeviceLogin(t.Context(), provider, "client", "aud", []string{"openid"}); err == nil {
		t.Fatal("expected StartDeviceLogin to fail when verification_uri is empty")
	}

	emptyURI = false
	login, err := oidc.StartDeviceLogin(t.Context(), provider, "client", "aud", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	token, err := login.Wait(ctx)
	if err != nil {
		t.Fatalf("the device sign-in failed: %v", err)
	}
	if token.AccessToken != "granted" || polls < 2 {
		t.Fatalf("got token %q after %d polls", token.AccessToken, polls)
	}
}

func TestDeviceLogin_StopsWhenTheSignInIsRefused(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev", "user_code": "ABCD", "verification_uri": "https://example.test", "expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "access_denied"})
	})

	provider := &oidc.Provider{
		TokenEndpoint:               server.URL + "/token",
		DeviceAuthorizationEndpoint: server.URL + "/device",
		GrantTypes:                  []string{"urn:ietf:params:oauth:grant-type:device_code"},
	}
	login, err := oidc.StartDeviceLogin(t.Context(), provider, "client", "aud", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := login.Wait(ctx); err == nil {
		t.Error("a refused sign-in was not reported as refused")
	}
}
