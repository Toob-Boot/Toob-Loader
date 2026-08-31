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
	"strings"
	"time"
)

// PKCE is the proof a client keeps to itself until it redeems its code.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a verifier and its S256 challenge (RFC 7636).
//
// 32 random bytes, base64url without padding: 43 characters, which is the shortest the RFC permits
// and already 256 bits of entropy.
func NewPKCE() (PKCE, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PKCE{}, fmt.Errorf("generating a PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))

	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// newState returns an unguessable value tying a callback to the request that started it.
func newState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a login state: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// BrowserLogin is an authorization code exchange with PKCE, answered on the loopback interface.
//
// The redirect goes to 127.0.0.1 on a port the operating system picks (RFC 8252). A fixed port would
// fail whenever something else held it, and — more to the point — a port is not a secret: what makes
// the callback trustworthy is the state value and the fact that only this process holds the PKCE
// verifier.
type BrowserLogin struct {
	// AuthorizationURL is where the person has to be sent.
	AuthorizationURL string

	provider *Provider
	clientID string
	pkce     PKCE
	state    string
	redirect string
	listener net.Listener
	results  chan callbackResult
}

type callbackResult struct {
	code string
	err  error
}

// StartBrowserLogin opens the loopback listener and builds the URL to send the person to. The caller
// opens a browser, prints the URL, or both, and then calls Wait.
func StartBrowserLogin(provider *Provider, clientID, audience string, scopes []string) (*BrowserLogin, error) {
	if !provider.SupportsS256() {
		return nil, errors.New("the identity provider does not offer PKCE with S256, and this client will not log in without it")
	}

	pkce, err := NewPKCE()
	if err != nil {
		return nil, err
	}
	state, err := newState()
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("opening a local port for the login callback: %w", err)
	}

	login := &BrowserLogin{
		provider: provider,
		clientID: clientID,
		pkce:     pkce,
		state:    state,
		redirect: fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port),
		listener: listener,
		results:  make(chan callbackResult, 1),
	}

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {login.redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
	}
	if audience != "" {
		// Which resource the token is for. Without it an issuer may hand back a token that is valid
		// for its own userinfo endpoint and for nothing else, and the registry would reject it.
		query.Set("audience", audience)
	}
	login.AuthorizationURL = provider.AuthorizationEndpoint + "?" + query.Encode()

	go login.serve()

	return login, nil
}

// Redirect is the address the identity provider will send the person back to.
func (l *BrowserLogin) Redirect() string { return l.redirect }

// Close releases the loopback listener. Safe to call more than once.
func (l *BrowserLogin) Close() { _ = l.listener.Close() }

func (l *BrowserLogin) serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		// Constant time, because this compares a secret the browser carries against one held here.
		if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(l.state)) != 1 {
			http.Error(w, "This callback does not belong to a login started here.", http.StatusBadRequest)
			l.results <- callbackResult{err: errors.New("the login callback carried a state this client did not issue")}
			return
		}
		if failure := query.Get("error"); failure != "" {
			http.Error(w, "Login failed. You can close this tab.", http.StatusBadRequest)
			l.results <- callbackResult{err: fmt.Errorf("%s: %s", failure, query.Get("error_description"))}
			return
		}

		code := query.Get("code")
		if code == "" {
			http.Error(w, "Login failed. You can close this tab.", http.StatusBadRequest)
			l.results <- callbackResult{err: errors.New("the identity provider returned no authorization code")}
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Deliberately plain, and served from the loopback: nothing here is fetched from a network.
		_, _ = w.Write([]byte("<!doctype html><title>Signed in</title><p>You are signed in. You can close this tab and return to the terminal.</p>"))
		l.results <- callbackResult{code: code}
	})

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	_ = server.Serve(l.listener)
}

// Wait blocks until the person finishes in the browser, then redeems the code.
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
