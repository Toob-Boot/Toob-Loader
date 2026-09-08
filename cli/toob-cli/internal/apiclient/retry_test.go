package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(server *httptest.Server) *Client {
	return &Client{BaseURL: server.URL, HTTPClient: server.Client()}
}

// A 429 with Retry-After is waited out and retried; the second answer is the one returned.
func TestDoWithRetry_HonoursRetryAfter(t *testing.T) {
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

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/", nil)
	started := time.Now()
	resp, err := newTestClient(server).doWithRetry(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("expected one retry ending in 200, got %d after %d calls", resp.StatusCode, calls.Load())
	}
	if waited := time.Since(started); waited < time.Second {
		t.Errorf("the retry came after %s; the server asked for one second", waited)
	}
}

// A 429 that names no wait is returned as it is: there is nothing to act on, and a backoff of our
// own would be a guess about a budget the server did not describe.
func TestDoWithRetry_A429WithoutRetryAfterIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/", nil)
	resp, err := newTestClient(server).doWithRetry(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests || calls.Load() != 1 {
		t.Fatalf("expected the 429 returned after one call, got %d after %d calls", resp.StatusCode, calls.Load())
	}
}

// A wait longer than the registry ever asks for is not one the registry sent.
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
