package tbm1http

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
)

func sampleTestManifest() tbm1.Manifest {
	return tbm1.Manifest{
		VendorID:  0x1234,
		ProductID: 0x5678,
		HWRevMin:  1,
		HWRevMax:  4,
		KeyIndex:  2,
		SVN:       7,
		Images: []tbm1.Image{
			{
				Type:       1,
				TargetSlot: tbm1.SlotApp,
				Installed:  bytes.Repeat([]byte("FIRMWARE_IMAGE_BYTE_DATA_PAYLOAD"), 50),
				VerMajor:   1,
				VerMinor:   0,
			},
		},
	}
}

func setupTestServer(t *testing.T, withSigner bool, authFn func(h tbm1.Header) error) (*httptest.Server, *tbm1.LocalSigner, ed25519.PublicKey) {
	t.Helper()
	var signer tbm1.Signer
	var localSigner *tbm1.LocalSigner
	var pub ed25519.PublicKey
	if withSigner {
		var priv ed25519.PrivateKey
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		localSigner, err = tbm1.NewLocalSigner(priv)
		if err != nil {
			t.Fatal(err)
		}
		signer = localSigner
	}

	handler := New(Options{
		Signer:        signer,
		AuthorizeSign: authFn,
	})

	server := httptest.NewServer(handler)
	return server, localSigner, pub
}

func TestHTTPBuild(t *testing.T) {
	ts, _, _ := setupTestServer(t, true, nil)
	defer ts.Close()

	// 1. Valid Build
	m := sampleTestManifest()
	body, _ := json.Marshal(m)
	resp, err := http.Post(ts.URL+"/v1/package/build", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/package/build failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var bResp buildResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&bResp); decErr != nil {
		t.Fatalf("failed to decode response: %v", decErr)
	}
	if len(bResp.UnsignedBlock) == 0 || bResp.TotalLen == 0 {
		t.Fatal("empty unsigned block returned")
	}

	// 2. Invalid Manifest (no images)
	badM := sampleTestManifest()
	badM.Images = nil
	badBody, _ := json.Marshal(badM)
	badResp, err := http.Post(ts.URL+"/v1/package/build", "application/json", bytes.NewReader(badBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = badResp.Body.Close() }()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", badResp.StatusCode)
	}

	// 3. Wrong Method
	getResp, err := http.Get(ts.URL + "/v1/package/build")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", getResp.StatusCode)
	}
}

func TestHTTPSignAndPackage(t *testing.T) {
	ts, _, pub := setupTestServer(t, true, nil)
	defer ts.Close()

	m := sampleTestManifest()
	pkg, err := tbm1.BuildUnsigned(m)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Sign valid unsigned block
	signReq := map[string][]byte{"unsigned_block": pkg.Block}
	body, _ := json.Marshal(signReq)
	resp, err := http.Post(ts.URL+"/v1/package/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var sResp signResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&sResp); decErr != nil {
		t.Fatal(decErr)
	}
	if vErr := tbm1.VerifyBlock(sResp.SignedBlock, pub); vErr != nil {
		t.Fatalf("signed block verification failed: %v", vErr)
	}

	// 2. Build + Sign in one go (/v1/package)
	mBody, _ := json.Marshal(m)
	pkgResp, err := http.Post(ts.URL+"/v1/package", "application/json", bytes.NewReader(mBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pkgResp.Body.Close() }()
	if pkgResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", pkgResp.StatusCode)
	}
	var pResp signResponse
	if err := json.NewDecoder(pkgResp.Body).Decode(&pResp); err != nil {
		t.Fatal(err)
	}
	if err := tbm1.VerifyBlock(pResp.SignedBlock, pub); err != nil {
		t.Fatalf("package block verification failed: %v", err)
	}
}

func TestHTTPSignerNotConfigured(t *testing.T) {
	// Server without signer
	ts, _, _ := setupTestServer(t, false, nil)
	defer ts.Close()

	m := sampleTestManifest()
	pkg, _ := tbm1.BuildUnsigned(m)

	signReq := map[string][]byte{"unsigned_block": pkg.Block}
	body, _ := json.Marshal(signReq)
	resp, err := http.Post(ts.URL+"/v1/package/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 Not Implemented, got %d", resp.StatusCode)
	}

	// GET /v1/pubkey without signer
	pkResp, err := http.Get(ts.URL + "/v1/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pkResp.Body.Close() }()
	if pkResp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 for pubkey route, got %d", pkResp.StatusCode)
	}
}

func TestHTTPAuthorizeSignPolicy(t *testing.T) {
	// Auth policy refusing signing if SVN < 10
	authPolicy := func(h tbm1.Header) error {
		if h.SVN < 10 {
			return errors.New("SVN too low for signing policy")
		}
		return nil
	}

	ts, _, _ := setupTestServer(t, true, authPolicy)
	defer ts.Close()

	// Manifest with SVN = 7 (should be rejected by policy)
	m := sampleTestManifest()
	m.SVN = 7
	pkg, _ := tbm1.BuildUnsigned(m)

	signReq := map[string][]byte{"unsigned_block": pkg.Block}
	body, _ := json.Marshal(signReq)
	resp, err := http.Post(ts.URL+"/v1/package/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

func TestHTTPVerifyAndPubkey(t *testing.T) {
	ts, signer, pub := setupTestServer(t, true, nil)
	defer ts.Close()

	// 1. GET /v1/pubkey
	pkResp, err := http.Get(ts.URL + "/v1/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pkResp.Body.Close() }()
	if pkResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", pkResp.StatusCode)
	}
	var pkr pubkeyResponse
	if decErr := json.NewDecoder(pkResp.Body).Decode(&pkr); decErr != nil {
		t.Fatalf("decode pubkey response: %v", decErr)
	}
	if !bytes.Equal(pkr.PublicKey, pub) {
		t.Fatal("pubkey mismatch")
	}

	// 2. POST /v1/verify valid signed block
	m := sampleTestManifest()
	pkg, _ := (&tbm1.Encoder{}).BuildUnsigned(m)
	signedBlock, err := tbm1.SignBlock(pkg.Block, signer)
	if err != nil {
		t.Fatalf("SignBlock failed: %v", err)
	}

	vReq := map[string]any{
		"block":      signedBlock,
		"public_key": pub,
	}
	vBody, _ := json.Marshal(vReq)
	vResp, err := http.Post(ts.URL+"/v1/verify", "application/json", bytes.NewReader(vBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = vResp.Body.Close() }()
	var vr verifyResponse
	if decErr := json.NewDecoder(vResp.Body).Decode(&vr); decErr != nil {
		t.Fatalf("decode verify response: %v", decErr)
	}
	if !vr.Valid || !vr.SignatureChecked {
		t.Fatalf("expected valid=true signature_checked=true, got %+v", vr)
	}

	// 3. POST /v1/verify tampered block
	tampered := append([]byte(nil), signedBlock...)
	tampered[tbm1.FixedLen+1] ^= 0xFF
	vReqTampered := map[string]any{
		"block":      tampered,
		"public_key": pub,
	}
	vtBody, err := json.Marshal(vReqTampered)
	if err != nil {
		t.Fatalf("marshal tampered verify request: %v", err)
	}
	vtResp, err := http.Post(ts.URL+"/v1/verify", "application/json", bytes.NewReader(vtBody))
	if err != nil {
		t.Fatalf("POST /v1/verify (tampered): %v", err)
	}
	defer func() { _ = vtResp.Body.Close() }()
	var vrTampered verifyResponse
	if err := json.NewDecoder(vtResp.Body).Decode(&vrTampered); err != nil {
		t.Fatalf("decode tampered verify response: %v", err)
	}
	if vrTampered.Valid {
		t.Fatal("expected valid=false on tampered block")
	}
}
