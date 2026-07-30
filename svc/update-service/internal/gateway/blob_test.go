package gateway_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/toob-boot/update-service/internal/gateway"
	"github.com/toob-boot/update-service/internal/store"
)

func setupBlobTest(t *testing.T) (*store.LocalWORMStore, *gateway.BlobHandler, string, []byte) {
	tempDir, err := os.MkdirTemp("", "blob_gateway_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	st, err := store.NewLocalWORMStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create LocalWORMStore: %v", err)
	}

	// Construct 1000-byte test payload
	payload := make([]byte, 1000)
	for i := range payload {
		payload[i] = byte((i * 31) % 256)
	}

	digestArr := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digestArr[:])

	if err := st.Put(context.Background(), digestHex, payload, digestArr[:]); err != nil {
		t.Fatalf("failed to store blob: %v", err)
	}

	handler := gateway.NewBlobHandler(st)
	return st, handler, digestHex, payload
}

func TestBlobGateway_UnsatisfiableRange416Guard(t *testing.T) {
	_, handler, digestHex, _ := setupBlobTest(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/blobs/%s", digestHex)
	req := httptest.NewRequest(http.MethodGet, urlPath, nil)
	req.Header.Set("Range", "bytes=999999999-") // Unsatisfiable range (start >= totalSize)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// CRITICAL SAFETY INVARIANT: Must return 416, NEVER 200!
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("HARD SAFETY VIOLATION: expected HTTP 416 Range Not Satisfiable, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	if rec.Header().Get("Content-Range") != "bytes */1000" {
		t.Errorf("expected Content-Range 'bytes */1000', got %q", rec.Header().Get("Content-Range"))
	}
}

func TestBlobGateway_ValidRange206PartialContent(t *testing.T) {
	_, handler, digestHex, payload := setupBlobTest(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/blobs/%s", digestHex)
	req := httptest.NewRequest(http.MethodGet, urlPath, nil)
	req.Header.Set("Range", "bytes=100-199") // Bytes 100..199 (100 bytes)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("expected HTTP 206 Partial Content, got %d", rec.Code)
	}

	if rec.Header().Get("Content-Range") != "bytes 100-199/1000" {
		t.Errorf("expected Content-Range 'bytes 100-199/1000', got %q", rec.Header().Get("Content-Range"))
	}

	if rec.Header().Get("Content-Length") != "100" {
		t.Errorf("expected Content-Length 100, got %q", rec.Header().Get("Content-Length"))
	}

	gotBytes := rec.Body.Bytes()
	if len(gotBytes) != 100 {
		t.Fatalf("expected 100 bytes payload, got %d", len(gotBytes))
	}

	expectedRange := payload[100:200]
	if !bytes.Equal(gotBytes, expectedRange) {
		t.Errorf("range payload content mismatch!")
	}
}

func TestBlobGateway_ForceIdentityEncoding(t *testing.T) {
	_, handler, digestHex, _ := setupBlobTest(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/blobs/%s", digestHex)
	req := httptest.NewRequest(http.MethodGet, urlPath, nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br") // Client requests gzip

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d", rec.Code)
	}

	// MUST force identity encoding to prevent transparent Gzip corrupting MCU resume offsets
	if rec.Header().Get("Content-Encoding") != "identity" {
		t.Errorf("expected Content-Encoding: identity, got %q", rec.Header().Get("Content-Encoding"))
	}
}

func TestBlobGateway_No3xxRedirects(t *testing.T) {
	_, handler, digestHex, _ := setupBlobTest(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/blobs/%s", digestHex)
	req := httptest.NewRequest(http.MethodGet, urlPath, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code >= 300 && rec.Code <= 399 {
		t.Fatalf("CRITICAL FAULT: Blob delivery issued HTTP redirect status %d!", rec.Code)
	}
}

func TestBlobGateway_BitExact2PartResume(t *testing.T) {
	_, handler, digestHex, payload := setupBlobTest(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	urlPath := fmt.Sprintf("/v1/blobs/%s", digestHex)

	// Part 1: Download bytes 0-499
	req1 := httptest.NewRequest(http.MethodGet, urlPath, nil)
	req1.Header.Set("Range", "bytes=0-499")
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusPartialContent {
		t.Fatalf("part 1 failed with status %d", rec1.Code)
	}
	part1 := rec1.Body.Bytes()

	// Part 2: Resume download bytes 500- (from 500 to end)
	req2 := httptest.NewRequest(http.MethodGet, urlPath, nil)
	req2.Header.Set("Range", "bytes=500-")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusPartialContent {
		t.Fatalf("part 2 failed with status %d", rec2.Code)
	}
	part2 := rec2.Body.Bytes()

	// Concatenate Part 1 + Part 2
	assembled := append(part1, part2...)

	if len(assembled) != len(payload) {
		t.Fatalf("assembled size %d != original payload size %d", len(assembled), len(payload))
	}

	if !bytes.Equal(assembled, payload) {
		t.Fatalf("BIT-EXACT RESUME FAILURE: assembled bytes do not match original payload!")
	}

	assembledDigest := sha256.Sum256(assembled)
	assembledHex := hex.EncodeToString(assembledDigest[:])
	if assembledHex != digestHex {
		t.Fatalf("assembled SHA-256 %s != original digest %s", assembledHex, digestHex)
	}
}

func TestBlobGateway_HeadMethodSupport(t *testing.T) {
	_, handler, digestHex, _ := setupBlobTest(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/blobs/%s", digestHex)
	req := httptest.NewRequest(http.MethodHead, urlPath, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK on HEAD, got %d", rec.Code)
	}

	if rec.Header().Get("Content-Length") != "1000" {
		t.Errorf("expected Content-Length 1000 on HEAD, got %q", rec.Header().Get("Content-Length"))
	}

	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("expected Accept-Ranges: bytes, got %q", rec.Header().Get("Accept-Ranges"))
	}

	// Body MUST be 0 bytes on HEAD request!
	if rec.Body.Len() != 0 {
		t.Errorf("expected 0-byte body on HEAD request, got %d bytes", rec.Body.Len())
	}
}
