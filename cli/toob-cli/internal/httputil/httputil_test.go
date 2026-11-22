package httputil_test

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
)

func TestBuildTransport_FailsFastOnBadCACertAndTrustsValidPEM(t *testing.T) {
	t.Setenv("TOOB_CA_CERT", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := httputil.BuildTransport(); err == nil {
		t.Fatal("expected BuildTransport to fail when TOOB_CA_CERT file does not exist")
	}

	derPath := filepath.Join(t.TempDir(), "not_pem.cer")
	if err := os.WriteFile(derPath, []byte("not-a-valid-pem-bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOOB_CA_CERT", derPath)
	if _, err := httputil.BuildTransport(); err == nil || !strings.Contains(err.Error(), "no valid PEM") {
		t.Fatalf("expected invalid PEM error, got %v", err)
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()

	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOOB_CA_CERT", pemPath)

	tr, err := httputil.BuildTransport()
	if err != nil {
		t.Fatalf("BuildTransport with valid PEM failed: %v", err)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("expected TLS >= 1.2 enforced on transport")
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: tr, CheckRedirect: httputil.SafeCheckRedirect}
	resp, err := client.Get(tlsSrv.URL)
	if err != nil {
		t.Fatalf("TLS request using TOOB_CA_CERT failed: %v", err)
	}
	_ = resp.Body.Close()
}

func TestSafeCheckRedirect_StripsCrossHostAuthBlocksDowngradeAndCapturesWarnings(t *testing.T) {
	var seenAuthOnS3 string
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthOnS3 = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Srv.Close()

	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Toob-Warning", "series v0.6 is deprecated")
		http.Redirect(w, r, s3Srv.URL+"/blob.tgz", http.StatusFound)
	}))
	defer regSrv.Close()

	var warnings []string
	client := &http.Client{
		CheckRedirect: httputil.NewSafeCheckRedirect(func(w string) {
			warnings = append(warnings, w)
		}),
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, regSrv.URL+"/dl", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("cross-host redirect failed: %v", err)
	}
	_ = resp.Body.Close()

	if seenAuthOnS3 != "" {
		t.Fatalf("Authorization header leaked across hosts: %q", seenAuthOnS3)
	}
	if len(warnings) != 1 || warnings[0] != "series v0.6 is deprecated" {
		t.Fatalf("expected captured X-Toob-Warning, got %+v", warnings)
	}

	// HTTPS -> HTTP downgrade must be blocked.
	httpsOrigin, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://registry.the-toob.com/dl", nil)
	httpDowngrade, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://cdn.the-toob.com/dl", nil)
	if err := httputil.SafeCheckRedirect(httpDowngrade, []*http.Request{httpsOrigin}); err == nil {
		t.Fatal("expected HTTPS -> HTTP downgrade redirect to be rejected")
	}
}

func TestValidateHTTPSOrLoopbackURL_AndCanonicalOrigin(t *testing.T) {
	valid := map[string]string{
		"https://Registry.The-Toob.com:443/api/v1": "https://registry.the-toob.com",
		"http://127.0.0.1:8080/callback":           "http://127.0.0.1:8080",
		"http://[::1]:80/callback":                 "http://[::1]",
		"http://localhost:3000/auth":               "http://localhost:3000",
	}
	for raw, wantOrigin := range valid {
		if _, err := httputil.ValidateHTTPSOrLoopbackURL(raw); err != nil {
			t.Errorf("valid URL %q rejected: %v", raw, err)
		}
		got, err := httputil.CanonicalOrigin(raw)
		if err != nil || got != wantOrigin {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q", raw, got, err, wantOrigin)
		}
	}

	invalid := []string{
		"",
		"http://registry.the-toob.com/api",
		"file:///etc/passwd",
		`\\attacker\share\payload`,
		"https://registry.the-toob.com/path\nwith-newline",
		"https://registry.the-toob.com/path with space",
		"javascript:alert(1)",
	}
	for _, raw := range invalid {
		if _, err := httputil.ValidateHTTPSOrLoopbackURL(raw); err == nil {
			t.Errorf("unsafe URL %q was accepted", raw)
		}
	}
}

func TestReadBounded(t *testing.T) {
	got, err := httputil.ReadBounded(bytes.NewReader([]byte("hello")), 5)
	if err != nil || string(got) != "hello" {
		t.Fatalf("exact cap read failed: %q, %v", string(got), err)
	}
	if _, err := httputil.ReadBounded(bytes.NewReader([]byte("hello!")), 5); !errors.Is(err, httputil.ErrResponseTooLarge) {
		t.Fatalf("expected ErrResponseTooLarge on overflow, got %v", err)
	}
}
