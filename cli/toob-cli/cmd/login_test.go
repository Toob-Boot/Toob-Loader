package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStartLocalServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := "test-state-123"
	listener, port, codeChan, errChan := startLocalServer(ctx, state)
	if listener == nil {
		t.Fatalf("failed to start local server: %v", <-errChan)
	}
	defer listener.Close()

	// 1. Test Valid Callback
	t.Run("Valid callback request", func(t *testing.T) {
		client := &http.Client{}
		url := fmt.Sprintf("http://127.0.0.1:%d/callback?code=authcode123&state=%s", port, state)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to perform request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", resp.StatusCode)
		}

		select {
		case code := <-codeChan:
			if code != "authcode123" {
				t.Errorf("expected code 'authcode123', got %q", code)
			}
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for auth code on channel")
		}
	})

	// 2. Test Invalid Host Header (DNS Rebinding)
	t.Run("Invalid Host header rejection", func(t *testing.T) {
		client := &http.Client{}
		url := fmt.Sprintf("http://127.0.0.1:%d/callback?code=authcode123&state=%s", port, state)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Host = "evil.com" // Mock malicious host

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to perform request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "Invalid Host Header") {
			t.Errorf("expected 'Invalid Host Header' error body, got %q", string(body))
		}
	})

	// 3. Test Invalid State (CSRF mismatch)
	t.Run("CSRF state mismatch rejection", func(t *testing.T) {
		client := &http.Client{}
		url := fmt.Sprintf("http://127.0.0.1:%d/callback?code=authcode123&state=wrongstate", port)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to perform request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "CSRF State mismatch") {
			t.Errorf("expected 'CSRF State mismatch' error body, got %q", string(body))
		}
	})

	// 4. Test Invalid HTTP Method (POST)
	t.Run("Method Not Allowed rejection", func(t *testing.T) {
		client := &http.Client{}
		url := fmt.Sprintf("http://127.0.0.1:%d/callback?code=authcode123&state=%s", port, state)

		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to perform request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 Method Not Allowed, got %d", resp.StatusCode)
		}
	})
}
