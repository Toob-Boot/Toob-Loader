package apiclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/oidc"
)

func TestClientV2_SessionSeparationOriginBindingAndEndpoints(t *testing.T) {
	var authConfigHits atomic.Int32
	var seenAuthOnAuthConfig string
	var seenAuthOnIdentity string
	var seenAuthOnAdmin string
	var seenIdempotencyKey string

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/api/v1/auth/config", func(w http.ResponseWriter, r *http.Request) {
		authConfigHits.Add(1)
		seenAuthOnAuthConfig = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(AuthConfig{
			Issuer:      srv.URL,
			ClientID:    "toob-cli",
			AccountsURL: srv.URL,
		})
	})

	mux.HandleFunc("/api/v1/me/invitations/accept", func(w http.ResponseWriter, r *http.Request) {
		seenAuthOnIdentity = r.Header.Get("Authorization")
		seenIdempotencyKey = r.Header.Get("Idempotency-Key")
		_ = json.NewEncoder(w).Encode(InvitationAcceptance{
			Organization: Organization{ID: "org_7", Name: "silicon-labs", Role: "member"},
			Joined:       true,
		})
	})

	mux.HandleFunc("/api/v1/admin/staging", func(w http.ResponseWriter, r *http.Request) {
		seenAuthOnAdmin = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"accepted":[{"ID":"pkg_1","Name":"@acme/drv","Version":"1.0.0","Category":"driver","StagingStatus":"ACCEPTED"}]}`))
	})

	mux.HandleFunc("/api/v1/admin/mock-webhook", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"queued","job_id":77}`))
	})

	mux.HandleFunc("/api/v1/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte(`{"id":"ns_1","name":"acme","tenant_id":"org_7"}`))
	})

	mux.HandleFunc("/api/v1/publish/promote", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"queued","name":"@acme/drv","version":"1.0.0","job_id":9001,"message":"queued"}`))
	})

	mux.HandleFunc("/api/v1/search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"name":"@toob/esp32c6","version":"1.3.2","category":"chip","download_count":42}],"has_more":true}`))
	})

	mux.HandleFunc("/api/v1/packages/mine", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") == "0" {
			_, _ = w.Write([]byte(`{"count":1,"packages":[{"id":"1","name":"a","version":"1.0.0","category":"driver"}],"has_more":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"count":1,"packages":[{"id":"2","name":"b","version":"1.0.0","category":"driver"}],"has_more":false}`))
	})

	mux.HandleFunc("/api/v1/releases/core/0.0.1/download/core-source.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Toob-Warning", "core v0.0.1 is pre-release")
		_, _ = w.Write([]byte("core-tarball-bytes"))
	})

	var jobPolls atomic.Int32
	mux.HandleFunc("/api/v1/publish/jobs/9001", func(w http.ResponseWriter, _ *http.Request) {
		jobPolls.Add(1)
		_, _ = w.Write([]byte(`{"id":9001,"package_name":"@acme/drv","package_version":"1.0.0","status":"QUEUED"}`))
	})
	mux.HandleFunc("/api/v1/publish/jobs/9001/stream", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, ": heartbeat\n\n")
		_, _ = fmt.Fprint(w, "event: status\ndata: {\"id\":9001,\"package_name\":\"@acme/drv\",\"package_version\":\"1.0.0\",\"status\":\"RUNNING\"}\n\n")
		_, _ = fmt.Fprint(w, "event: status\ndata: {\"id\":9001,\"package_name\":\"@acme/drv\",\"package_version\":\"1.0.0\",\"status\":\"PASSED\"}\n\n")
	})

	toobHome := filepath.Join(t.TempDir(), ".toob")
	t.Setenv("TOOB_HOME", toobHome)
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)
	// Even when TOOB_TOKEN is set for CI registry calls, identity-api & admin routes MUST use the OIDC session!
	t.Setenv(TokenEnv, "toob_pat_machine_token")

	if err := SaveIdentity(&IdentityCredentials{
		RegistryURL: srv.URL,
		Issuer:      srv.URL,
		ClientID:    "toob-cli",
		Subject:     "usr_1",
		Token: &oidc.Token{
			AccessToken: "oidc-session-jwt",
			ExpiresAt:   time.Now().Add(30 * time.Minute),
		},
	}, "alice"); err != nil {
		t.Fatal(err)
	}

	c := New()

	// 1. FetchAuthConfig sends NO Authorization header and memoizes across calls.
	cfg1, err := c.FetchAuthConfig(t.Context())
	if err != nil {
		t.Fatalf("FetchAuthConfig failed: %v", err)
	}
	cfg2, err := c.FetchAuthConfig(t.Context())
	if err != nil || cfg2.Issuer != cfg1.Issuer {
		t.Fatalf("second FetchAuthConfig failed: %v", err)
	}
	if authConfigHits.Load() != 1 {
		t.Fatalf("expected FetchAuthConfig memoization (1 hit), got %d", authConfigHits.Load())
	}
	if seenAuthOnAuthConfig != "" {
		t.Fatalf("FetchAuthConfig leaked Authorization header: %q", seenAuthOnAuthConfig)
	}

	// 2. Identity & Admin routes use OIDC session (ignoring TOOB_TOKEN) + Idempotency-Key.
	acc, err := c.AcceptInvitation(t.Context(), "inv_tok_123")
	if err != nil || !acc.Joined {
		t.Fatalf("AcceptInvitation failed: %+v, %v", acc, err)
	}
	if seenAuthOnIdentity != "Bearer oidc-session-jwt" {
		t.Fatalf("identity-api got Authorization=%q, want OIDC session JWT", seenAuthOnIdentity)
	}
	if seenIdempotencyKey == "" {
		t.Fatal("expected Idempotency-Key on identity mutation")
	}

	stg, err := c.AdminStaging(t.Context())
	if err != nil || len(stg.Packages) != 1 || stg.Packages[0].Name != "@acme/drv" {
		t.Fatalf("AdminStaging failed: %+v, %v", stg, err)
	}
	if seenAuthOnAdmin != "Bearer oidc-session-jwt" {
		t.Fatalf("admin route got Authorization=%q, want OIDC session JWT", seenAuthOnAdmin)
	}

	wh, err := c.AdminMockWebhook(t.Context(), AdminMockWebhookRequest{Action: "opened", PRNumber: 5, Repo: "toob/reg", HeadSHA: "abc"})
	if err != nil || wh.JobID != 77 {
		t.Fatalf("AdminMockWebhook failed: %+v, %v", wh, err)
	}

	ns, err := c.ReserveNamespace(t.Context(), "@acme", "org_7")
	if err != nil || ns.Name != "acme" {
		t.Fatalf("ReserveNamespace failed: %+v, %v", ns, err)
	}

	// 3. Cross-origin client must refuse to bleed stored OIDC session!
	otherSrv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(otherSrv.Close)
	otherClient := NewForBaseURL(otherSrv.URL, 5*time.Second)
	if _, crossErr := otherClient.AdminStaging(t.Context()); crossErr == nil {
		t.Fatal("expected cross-origin client to refuse stored OIDC session")
	}

	// 4. Promote (int64 JobID), Search, MyPackages pagination, DownloadRelease, StreamPublishJob.
	prom, err := c.Promote(t.Context(), "@acme/drv", "1.0.0")
	if err != nil || prom.JobID != 9001 {
		t.Fatalf("Promote failed: %+v, %v", prom, err)
	}

	sr, err := c.Search(t.Context(), "esp32")
	if err != nil || !sr.HasMore || sr.Count != 1 || sr.Results[0].Downloads != 42 {
		t.Fatalf("Search failed: %+v, %v", sr, err)
	}

	mine, err := c.MyPackages(t.Context())
	if err != nil || mine.Count != 2 || len(mine.Packages) != 2 {
		t.Fatalf("MyPackages pagination failed: %+v, %v", mine, err)
	}

	rc, err := c.DownloadRelease(t.Context(), "core", "core/v0.0.1", "core-source.tar.gz")
	if err != nil {
		t.Fatalf("DownloadRelease failed: %v", err)
	}
	relBytes, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(relBytes) != "core-tarball-bytes" || len(c.Warnings()) == 0 {
		t.Fatalf("unexpected DownloadRelease bytes=%q warnings=%v", string(relBytes), c.Warnings())
	}

	var seenStatuses []string
	finalJob, err := c.StreamPublishJob(t.Context(), 9001, func(j *PublishJob) error {
		seenStatuses = append(seenStatuses, j.Status)
		return nil
	})
	if err != nil || finalJob.Status != "PASSED" {
		t.Fatalf("StreamPublishJob failed: %+v, %v", finalJob, err)
	}
	if len(seenStatuses) != 3 || seenStatuses[0] != "QUEUED" || seenStatuses[1] != "RUNNING" || seenStatuses[2] != "PASSED" {
		t.Fatalf("unexpected SSE status transitions: %v", seenStatuses)
	}
}
