package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
)

// PKCE holds a proof-key verifier and its S256 challenge (RFC 7636).
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a 256-bit verifier and its S256 challenge (RFC 7636).
func NewPKCE() (PKCE, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PKCE{}, fmt.Errorf("generating a PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))

	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

func newState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a login state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// BrowserLogin runs an OAuth2 authorization-code exchange with PKCE on a loopback port.
type BrowserLogin struct {
	AuthorizationURL string

	provider *Provider
	clientID string
	pkce     PKCE
	state    string
	redirect string
	listener net.Listener
	server   *http.Server
	sendOnce sync.Once
	results  chan callbackResult
}

type callbackResult struct {
	code string
	err  error
}

// StepUp specifies RFC 9470 step-up authentication constraints.
type StepUp struct {
	ACRValues string
	MaxAge    time.Duration
}

// StartBrowserLogin opens the loopback listener and builds the authorization URL.
func StartBrowserLogin(provider *Provider, clientID, audience string, scopes []string) (*BrowserLogin, error) {
	return startBrowserLogin(provider, clientID, audience, scopes, nil)
}

// StartBrowserStepUp starts a browser login forcing re-authentication for step-up challenges.
func StartBrowserStepUp(provider *Provider, clientID, audience string, scopes []string, stepUp StepUp) (*BrowserLogin, error) {
	return startBrowserLogin(provider, clientID, audience, scopes, &stepUp)
}

func startBrowserLogin(provider *Provider, clientID, audience string, scopes []string, stepUp *StepUp) (*BrowserLogin, error) {
	if !provider.SupportsS256() {
		return nil, errors.New("the identity provider does not offer PKCE with S256, and this client will not log in without it")
	}
	if strings.TrimSpace(provider.AuthorizationEndpoint) == "" {
		return nil, errors.New("the identity provider publishes no authorization endpoint")
	}
	authURL, err := httputil.ValidateHTTPSOrLoopbackURL(provider.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	pkce, err := NewPKCE()
	if err != nil {
		return nil, err
	}
	state, err := newState()
	if err != nil {
		return nil, err
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("opening a local port for the login callback: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("loopback listener did not bind a TCP address")
	}

	redirect := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpAddr.Port)) + "/callback"

	login := &BrowserLogin{
		provider: provider,
		clientID: clientID,
		pkce:     pkce,
		state:    state,
		redirect: redirect,
		listener: listener,
		results:  make(chan callbackResult, 1),
	}

	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", login.redirect)
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", pkce.Challenge)
	query.Set("code_challenge_method", "S256")
	if audience != "" {
		query.Set("audience", audience)
	}
	if stepUp != nil {
		query.Set("prompt", "login")
		if stepUp.ACRValues != "" {
			query.Set("acr_values", stepUp.ACRValues)
		}
		if stepUp.MaxAge > 0 {
			query.Set("max_age", strconv.Itoa(int(stepUp.MaxAge.Seconds())))
		}
	}
	authURL.RawQuery = query.Encode()
	login.AuthorizationURL = authURL.String()

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", login.handleCallback)
	login.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       5 * time.Second,
	}

	go login.serve()

	return login, nil
}

// Redirect returns the loopback callback URI.
func (l *BrowserLogin) Redirect() string { return l.redirect }

// Close shuts down the loopback HTTP server and listener. Safe to call multiple times.
func (l *BrowserLogin) Close() {
	if l.server != nil {
		_ = l.server.Close()
	}
	if l.listener != nil {
		_ = l.listener.Close()
	}
}

func (l *BrowserLogin) deliver(res callbackResult) {
	l.sendOnce.Do(func() {
		l.results <- res
	})
}

func (l *BrowserLogin) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	// Reject mismatched state with 400 without aborting the active listener so
	// unrelated browser prefetches or local probes cannot DoS an in-progress login.
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(l.state)) != 1 {
		http.Error(w, "This callback does not belong to a login started here.", http.StatusBadRequest)
		return
	}
	if failure := query.Get("error"); failure != "" {
		http.Error(w, "Login failed. You can close this tab.", http.StatusBadRequest)
		l.deliver(callbackResult{err: fmt.Errorf("%s: %s", failure, query.Get("error_description"))})
		return
	}

	code := query.Get("code")
	if code == "" {
		http.Error(w, "Login failed. You can close this tab.", http.StatusBadRequest)
		l.deliver(callbackResult{err: errors.New("the identity provider returned no authorization code")})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><title>Signed in</title><p>You are signed in. You can close this tab and return to the terminal.</p>"))
	l.deliver(callbackResult{code: code})
}

func (l *BrowserLogin) serve() {
	_ = l.server.Serve(l.listener)
}

// Wait blocks until the browser callback delivers a valid authorization code or ctx expires.
func (l *BrowserLogin) Wait(ctx context.Context) (*Token, error) {
	defer l.Close()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("gave up waiting for the browser login: %w", ctx.Err())
	case result := <-l.results:
		if result.err != nil {
			return nil, result.err
		}

		resp, err := postForm(ctx, l.provider.TokenEndpoint, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {result.code},
			"redirect_uri":  {l.redirect},
			"client_id":     {l.clientID},
			"code_verifier": {l.pkce.Verifier},
		})
		if err != nil {
			return nil, err
		}

		return tokenFrom(resp)
	}
}
