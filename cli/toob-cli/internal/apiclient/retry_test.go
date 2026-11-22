package apiclient

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(server *httptest.Server) *Client {
	return &Client{BaseURL: server.URL, HTTPClient: server.Client()}
}

func TestDoWithRetry_HonorsRetryAfter(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	resp, err := newTestClient(server).doWithRetry(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("expected one retry ending in 200, got %d after %d calls", resp.StatusCode, calls.Load())
	}
	if waited := time.Since(started); waited < time.Second {
		t.Errorf("the retry came after %s; the server asked for one second", waited)
	}
}

func TestDoWithRetry_RewindsRequestBodyOn503WhenIdempotent(t *testing.T) {
	var calls atomic.Int32
	var secondBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		n := calls.Add(1)
		if n == 1 || n == 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		secondBody = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 1. POST without Idempotency-Key must NOT be retried on 503.
	unkeyedReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/publish", bytes.NewReader([]byte("once")))
	if err != nil {
		t.Fatal(err)
	}
	unkeyedResp, err := newTestClient(server).doWithRetry(unkeyedReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = unkeyedResp.Body.Close()
	if unkeyedResp.StatusCode != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("expected un-keyed POST to stop after 1 call with 503, got status=%d calls=%d", unkeyedResp.StatusCode, calls.Load())
	}

	// 2. POST with Idempotency-Key rewinds req.GetBody() and retries cleanly on 503.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/publish", bytes.NewReader([]byte("tarball-payload")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Idempotency-Key", "idem-publish-1")
	resp, err := newTestClient(server).doWithRetry(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK || secondBody != "tarball-payload" {
		t.Fatalf("expected retried POST to preserve full body, got status=%d body=%q", resp.StatusCode, secondBody)
	}
}

func TestDoWithRetry_A429WithoutRetryAfterIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newTestClient(server).doWithRetry(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTooManyRequests || calls.Load() != 1 {
		t.Fatalf("expected the 429 returned after one call, got %d after %d calls", resp.StatusCode, calls.Load())
	}
}

func TestRetryAfterOf_IsCapped(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": {"3600"}}}
	wait, ok := retryAfterOf(resp)
	if !ok || wait != maxRetryAfter {
		t.Fatalf("expected the cap of %s, got %s (%v)", maxRetryAfter, wait, ok)
	}
	if _, ok := retryAfterOf(&http.Response{Header: http.Header{"Retry-After": {"Wed, 21 Oct 2015 07:28:00 GMT"}}}); ok {
		t.Error("a date-form Retry-After was accepted; only seconds are read")
	}
}
