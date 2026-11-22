// Package httputil provides hardened leaf HTTP transport, redirect, URL, and
// bounded-read primitives shared across apiclient, oidc, updater, and toolchain.
package httputil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	maxRedirects   = 10
	maxCACertBytes = 4 << 20 // 4 MiB PEM bundle cap
)

// ErrResponseTooLarge indicates that an HTTP response body exceeded its byte cap.
var ErrResponseTooLarge = errors.New("http response exceeds maximum allowed size")

// BuildTransport clones http.DefaultTransport, enforces TLS >= 1.2, and loads any
// custom PEM root bundle configured via TOOB_CA_CERT. If TOOB_CA_CERT is set to an
// unreadable file or contains no valid PEM certificates, BuildTransport fails fast.
func BuildTransport() (*http.Transport, error) {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	} else {
		tr = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			tr.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}

	caPath := strings.TrimSpace(os.Getenv("TOOB_CA_CERT"))
	if caPath == "" {
		return tr, nil
	}

	absCA, err := filepath.Abs(caPath)
	if err != nil {
		return nil, fmt.Errorf("invalid TOOB_CA_CERT path %q: %w", caPath, err)
	}
	caRoot, err := os.OpenRoot(filepath.Dir(absCA))
	if err != nil {
		return nil, fmt.Errorf("cannot open TOOB_CA_CERT directory for %q: %w", caPath, err)
	}
	defer func() { _ = caRoot.Close() }()

	cf, err := caRoot.Open(filepath.Base(absCA))
	if err != nil {
		return nil, fmt.Errorf("cannot open TOOB_CA_CERT %q: %w", caPath, err)
	}
	caCert, readErr := ReadBounded(cf, maxCACertBytes)
	closeErr := cf.Close()
	if readErr != nil {
		return nil, fmt.Errorf("cannot read TOOB_CA_CERT %q: %w", caPath, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("cannot close TOOB_CA_CERT %q: %w", caPath, closeErr)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("TOOB_CA_CERT %q contains no valid PEM certificates", caPath)
	}
	tr.TLSClientConfig.RootCAs = pool
	return tr, nil
}

// NewClient constructs an *http.Client using BuildTransport and SafeCheckRedirect.
func NewClient(timeout time.Duration) (*http.Client, error) {
	tr, err := BuildTransport()
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: SafeCheckRedirect,
	}, nil
}

// SafeCheckRedirect caps redirects at 10, blocks HTTPS-to-HTTP downgrades, and
// strips Authorization headers across host boundaries (such as S3/CDN redirects).
func SafeCheckRedirect(req *http.Request, via []*http.Request) error {
	return NewSafeCheckRedirect(nil)(req, via)
}

// NewSafeCheckRedirect returns a CheckRedirect policy matching SafeCheckRedirect
// that additionally forwards any intermediate X-Toob-Warning headers to onWarning.
func NewSafeCheckRedirect(onWarning func(string)) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if onWarning != nil && req.Response != nil {
			for _, w := range req.Response.Header.Values("X-Toob-Warning") {
				if trimmed := strings.TrimSpace(w); trimmed != "" {
					onWarning(trimmed)
				}
			}
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
			return fmt.Errorf("refusing redirect to unsupported URL scheme %q", req.URL.Scheme)
		}
		if len(via) > 0 {
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect downgrade from HTTPS to %s", req.URL.Redacted())
			}
			if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del("Authorization")
			}
		}
		return nil
	}
}

// ValidateHTTPSOrLoopbackURL rejects control characters and whitespace, and requires
// either https:// or loopback http:// (localhost, 127.0.0.0/8, [::1]).
func ValidateHTTPSOrLoopbackURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, errors.New("URL must not be empty")
	}
	for _, r := range rawURL {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return nil, errors.New("URL contains forbidden control or whitespace character")
		}
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("URL is missing a host")
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		return u, nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return u, nil
		}
		return nil, fmt.Errorf("insecure http:// URL is only permitted for loopback hosts, got %q", u.Hostname())
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q (expected https://)", u.Scheme)
	}
}

// CanonicalOrigin validates rawURL via ValidateHTTPSOrLoopbackURL and returns its
// normalized origin ("scheme://host[:port]" with lowercase host and default port stripped).
func CanonicalOrigin(rawURL string) (string, error) {
	u, err := ValidateHTTPSOrLoopbackURL(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), nil
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]", nil
	}
	return scheme + "://" + host, nil
}

func isLoopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(hostname)
	return err == nil && addr.IsLoopback()
}

// ReadBounded reads up to maxBytes from r and fails with ErrResponseTooLarge if r
// contains more than maxBytes.
func ReadBounded(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, fmt.Errorf("invalid negative maxBytes %d", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w (%d bytes)", ErrResponseTooLarge, maxBytes)
	}
	return data, nil
}
