package updater_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/updater"
)

func TestGetUpdatePublicKey_RejectsPlaceholdersAndSupportsVaultAndHexSignatures(t *testing.T) {
	origKey := updater.ToobMasterPublicKeyHex
	t.Cleanup(func() {
		updater.ToobMasterPublicKeyHex = origKey
	})

	t.Setenv("TOOB_DEV", "")
	t.Setenv("TOOB_REGISTRY_PUBKEY", "")

	// 1. Empty default key fails closed.
	updater.ToobMasterPublicKeyHex = ""
	if _, err := updater.GetUpdatePublicKey(); err == nil {
		t.Fatal("expected empty ToobMasterPublicKeyHex to fail closed")
	}

	// 2. All-zero key fails closed.
	updater.ToobMasterPublicKeyHex = strings.Repeat("0", 64)
	if _, err := updater.GetUpdatePublicKey(); err == nil {
		t.Fatal("expected all-zero public key to be rejected")
	}

	// 3. RFC 8032 test vector 1 public key fails closed outside TOOB_DEV=1.
	updater.ToobMasterPublicKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	if _, err := updater.GetUpdatePublicKey(); err == nil {
		t.Fatal("expected RFC 8032 test-vector public key to be rejected outside dev mode")
	}

	// 4. TOOB_REGISTRY_PUBKEY without TOOB_DEV=1 fails closed.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	t.Setenv("TOOB_REGISTRY_PUBKEY", pubHex)
	if _, err := updater.GetUpdatePublicKey(); err == nil {
		t.Fatal("expected TOOB_REGISTRY_PUBKEY without TOOB_DEV=1 to fail")
	}

	// 5. Valid key with TOOB_DEV=1 verifies both 128-hex and Vault Transit "vault:v<digits>:<base64>" signatures.
	t.Setenv("TOOB_DEV", "1")
	payload := []byte(`{"format_version":1,"ecosystem":{"cli":["0.7.0"]}}`)
	digest := sha256.Sum256(payload)
	sig := ed25519.Sign(priv, digest[:])

	hexSig := hex.EncodeToString(sig)
	if err := updater.VerifySignature(payload, hexSig); err != nil {
		t.Fatalf("VerifySignature(hex) failed: %v", err)
	}

	vaultV1 := "vault:v1:" + base64.StdEncoding.EncodeToString(sig)
	if err := updater.VerifySignature(payload, vaultV1); err != nil {
		t.Fatalf("VerifySignature(vault:v1) failed: %v", err)
	}

	vaultV12 := "vault:v12:" + base64.StdEncoding.EncodeToString(sig)
	if err := updater.VerifySignature(payload, vaultV12); err != nil {
		t.Fatalf("VerifySignature(vault:v12) failed: %v", err)
	}

	if err := updater.VerifySignature([]byte("tampered"), vaultV12); err == nil {
		t.Fatal("expected tampered payload signature check to fail")
	}
}

func TestCheckForUpdate_DevBuildUnsignedRejectionSignedUpdateAndOriginCache(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	origKey := updater.ToobMasterPublicKeyHex
	updater.ToobMasterPublicKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() {
		updater.ToobMasterPublicKeyHex = origKey
	})

	indexJSON := []byte(`{"format_version":1,"ecosystem":{"cli":["0.8.0"]}}`)
	digest := sha256.Sum256(indexJSON)
	vaultSig := "vault:v2:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))

	sendSig := false
	return404 := false
	bgHit := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/registry/index" {
			if return404 {
				http.NotFound(w, r)
				select {
				case bgHit <- struct{}{}:
				default:
				}
				return
			}
			if sendSig {
				w.Header().Set("X-Registry-Signature", vaultSig)
			}
			_, _ = w.Write(indexJSON)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	toobHome := filepath.Join(t.TempDir(), ".toob")
	t.Setenv("TOOB_HOME", toobHome)
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)
	t.Setenv("TOOB_DEV", "")
	t.Setenv("CI", "")
	t.Setenv("TOOB_NO_UPDATE_CHECK", "")

	// 1. "dev" builds never false-positive as v0.0.0 needing update.
	devRes, err := updater.CheckForUpdate("dev", true, false)
	if err != nil || devRes.Available {
		t.Fatalf("expected CheckForUpdate(\"dev\") Available=false, got %+v, %v", devRes, err)
	}

	// 2. --insecure fails closed with ErrInsecureTLS.
	if _, insErr := updater.CheckForUpdate("v0.7.0", true, true); !errors.Is(insErr, updater.ErrInsecureTLS) {
		t.Fatalf("expected ErrInsecureTLS, got %v", insErr)
	}

	// 3. Unsigned index response in non-dev mode MUST be rejected!
	if _, unsigErr := updater.CheckForUpdate("v0.7.0", true, false); unsigErr == nil || !strings.Contains(unsigErr.Error(), "X-Registry-Signature") {
		t.Fatalf("expected unsigned index rejection, got %v", unsigErr)
	}

	// 4. Signed index succeeds and writes origin-bound update_check.json, which serves cache hits synchronously.
	sendSig = true
	res, err := updater.CheckForUpdate("v0.7.0", true, false)
	if err != nil || !res.Available || res.Version != "v0.8.0" {
		t.Fatalf("signed CheckForUpdate failed: %+v, %v", res, err)
	}
	if !strings.Contains(res.DownloadURL, "/api/v1/releases/cli/0.8.0/download/") {
		t.Fatalf("unexpected release DownloadURL: %q", res.DownloadURL)
	}
	hitRes, err := updater.CheckForUpdate("v0.7.0", false, false)
	if err != nil || hitRes == nil || !hitRes.Available || hitRes.Version != "v0.8.0" {
		t.Fatalf("expected origin-matching cache hit, got %+v, %v", hitRes, err)
	}

	// 5. Poisoned update_check.json pointing at another origin is ignored!
	return404 = true
	poisoned := `{"registry_url":"https://evil.example","last_check":"` + time.Now().UTC().Format(time.RFC3339) + `","latest_ver":"v9.9.9","download_url":"https://evil.example/toob.zip","sig_url":"https://evil.example/toob.zip.sig"}`
	if wErr := os.WriteFile(filepath.Join(toobHome, "update_check.json"), []byte(poisoned), 0o600); wErr != nil {
		t.Fatal(wErr)
	}
	cachedRes, err := updater.CheckForUpdate("v0.7.0", false, false)
	if err != nil {
		t.Fatalf("non-forced CheckForUpdate failed: %v", err)
	}
	if cachedRes != nil && cachedRes.Available {
		t.Fatalf("cross-origin poisoned update_check.json was trusted: %+v", cachedRes)
	}
	select {
	case <-bgHit:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for background refresh attempt")
	}

	// 6. FetchReleaseByTag rejects non-SemVer / traversal tags.
	for _, badTag := range []string{"", "../evil", "v1.0.0/../../pwn", "latest"} {
		if _, tagErr := updater.FetchReleaseByTag(badTag, false); tagErr == nil {
			t.Errorf("FetchReleaseByTag(%q) succeeded unexpectedly", badTag)
		}
	}
	goodTag, err := updater.FetchReleaseByTag("0.7.2", false)
	if err != nil || goodTag.Version != "v0.7.2" {
		t.Fatalf("FetchReleaseByTag(\"0.7.2\") = %+v, %v", goodTag, err)
	}
}
