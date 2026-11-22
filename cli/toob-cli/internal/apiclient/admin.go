package apiclient

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
)

// AdminJobsStats summarizes queued/running/passed/failed Firecracker job counts.
type AdminJobsStats struct {
	Queued      int     `json:"queued"`
	Running     int     `json:"running"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
	Total       int     `json:"total"`
	FailureRate float64 `json:"failure_rate"`
}

// AdminDashboardPackage is one staging package row in AdminStatusResponse.
type AdminDashboardPackage struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Category  string    `json:"category"`
	Publisher string    `json:"publisher"`
	CreatedAt time.Time `json:"created_at"`
}

// AdminPendingPR is one pending PR job row in AdminStatusResponse.
type AdminPendingPR struct {
	ID        int64     `json:"id"`
	PRNumber  int       `json:"pr_number"`
	Repo      string    `json:"repo"`
	HeadSHA   string    `json:"head_sha"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// AdminStatusResponse is the JSON body of GET /api/v1/admin/status.
type AdminStatusResponse struct {
	StagingPackages     []AdminDashboardPackage `json:"staging_packages"`
	PendingPRs          []AdminPendingPR        `json:"pending_prs"`
	ValidationJobsStats AdminJobsStats          `json:"validation_jobs_stats"`
	PublishJobsStats    AdminJobsStats          `json:"publish_jobs_stats"`
}

// AdminStagingPackage represents a package in the staging review queue.
type AdminStagingPackage struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Category        string `json:"category"`
	PublisherID     string `json:"publisher_id,omitempty"`
	StagingStatus   string `json:"staging_status,omitempty"`
	StagingFeedback string `json:"staging_feedback,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
}

func (p *AdminStagingPackage) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID              string `json:"id"`
		IDPascal        string `json:"ID"`
		Name            string `json:"name"`
		NamePascal      string `json:"Name"`
		Version         string `json:"version"`
		VersionPascal   string `json:"Version"`
		Category        string `json:"category"`
		CategoryPascal  string `json:"Category"`
		PublisherID     string `json:"publisher_id"`
		PubIDPascal     string `json:"PublisherID"`
		StagingStatus   string `json:"staging_status"`
		StatusPascal    string `json:"StagingStatus"`
		StagingFeedback string `json:"staging_feedback"`
		FeedbackPascal  string `json:"StagingFeedback"`
		CreatedAt       string `json:"created_at"`
		CreatedAtPascal string `json:"CreatedAt"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	p.ID = cmp.Or(wire.ID, wire.IDPascal)
	p.Name = cmp.Or(wire.Name, wire.NamePascal)
	p.Version = cmp.Or(wire.Version, wire.VersionPascal)
	p.Category = cmp.Or(wire.Category, wire.CategoryPascal)
	p.PublisherID = cmp.Or(wire.PublisherID, wire.PubIDPascal)
	p.StagingStatus = cmp.Or(wire.StagingStatus, wire.StatusPascal)
	p.StagingFeedback = cmp.Or(wire.StagingFeedback, wire.FeedbackPascal)
	p.CreatedAt = cmp.Or(wire.CreatedAt, wire.CreatedAtPascal)
	return nil
}

// AdminStagingResponse is the normalized shape of GET /api/v1/admin/staging.
type AdminStagingResponse struct {
	Packages []AdminStagingPackage `json:"packages"`
}

// AdminReleaseResponse is the JSON body of POST /api/v1/admin/release.
type AdminReleaseResponse struct {
	Status       string `json:"status"`
	RevisionID   int64  `json:"revision_id"`
	Count        int    `json:"count"`
	MirrorStatus string `json:"mirror_status,omitempty"`
}

// AdminRevokeRequest is the JSON body of POST /api/v1/admin/revoke.
type AdminRevokeRequest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// AdminRevokeResponse is the JSON body of POST /api/v1/admin/revoke.
type AdminRevokeResponse struct {
	Status             string `json:"status"`
	AdvisoryID         int64  `json:"advisory_id"`
	AffectedRevisions  int    `json:"affected_revisions"`
	AffectedPublishers int    `json:"affected_publishers"`
	MirrorStatus       string `json:"mirror_status,omitempty"`
}

// AdminMockWebhookRequest is the JSON body of POST /api/v1/admin/mock-webhook.
type AdminMockWebhookRequest struct {
	Action       string   `json:"action"`
	PRNumber     int      `json:"pr_number"`
	Repo         string   `json:"repo"`
	HeadSHA      string   `json:"head_sha"`
	GitHubUserID int64    `json:"github_user_id"`
	Files        []string `json:"files"`
}

// AdminMockWebhookResponse is the JSON body of POST /api/v1/admin/mock-webhook.
type AdminMockWebhookResponse struct {
	Status string `json:"status"`
	JobID  int64  `json:"job_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (r *AdminMockWebhookResponse) UnmarshalJSON(data []byte) error {
	var wire struct {
		Status string          `json:"status"`
		JobID  json.RawMessage `json:"job_id"`
		Reason string          `json:"reason"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.Status = wire.Status
	r.Reason = wire.Reason
	trimmed := bytes.TrimSpace(wire.JobID)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		var num int64
		if err := json.Unmarshal(trimmed, &num); err == nil {
			r.JobID = num
		} else {
			var str string
			if err := json.Unmarshal(trimmed, &str); err == nil && str != "" {
				parsed, parseErr := strconv.ParseInt(str, 10, 64)
				if parseErr != nil {
					return fmt.Errorf("invalid job_id %q: %w", str, parseErr)
				}
				r.JobID = parsed
			}
		}
	}
	return nil
}

func (c *Client) doSessionJSON(ctx context.Context, method, path string, body, out any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := c.newSessionRequest(ctx, method, path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Idempotency-Key", rand.Text())
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return extractError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	raw, err := httputil.ReadBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// AdminStatus queries GET /api/v1/admin/status using the interactive OIDC session.
func (c *Client) AdminStatus(ctx context.Context) (*AdminStatusResponse, error) {
	var out AdminStatusResponse
	if err := c.doSessionJSON(ctx, http.MethodGet, "/api/v1/admin/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminStaging queries GET /api/v1/admin/staging using the interactive OIDC session.
func (c *Client) AdminStaging(ctx context.Context) (*AdminStagingResponse, error) {
	var wire struct {
		Packages []AdminStagingPackage `json:"packages"`
		Accepted []AdminStagingPackage `json:"accepted"`
	}
	if err := c.doSessionJSON(ctx, http.MethodGet, "/api/v1/admin/staging", nil, &wire); err != nil {
		return nil, err
	}
	pkgs := wire.Packages
	if len(pkgs) == 0 && len(wire.Accepted) > 0 {
		pkgs = wire.Accepted
	}
	return &AdminStagingResponse{Packages: pkgs}, nil
}

// AdminAccept marks a staging package accepted via POST /api/v1/admin/accept.
func (c *Client) AdminAccept(ctx context.Context, name, version string) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
		return errors.New("package name and version are required")
	}
	return c.doSessionJSON(ctx, http.MethodPost, "/api/v1/admin/accept", map[string]string{
		"name":    name,
		"version": version,
	}, nil)
}

// AdminReject marks a staging package rejected via POST /api/v1/admin/reject.
func (c *Client) AdminReject(ctx context.Context, name, version, reason string) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
		return errors.New("package name and version are required")
	}
	return c.doSessionJSON(ctx, http.MethodPost, "/api/v1/admin/reject", map[string]string{
		"name":    name,
		"version": version,
		"reason":  reason,
	}, nil)
}

// AdminRelease promotes accepted staging packages to stable via POST /api/v1/admin/release.
func (c *Client) AdminRelease(ctx context.Context) (*AdminReleaseResponse, error) {
	var out AdminReleaseResponse
	if err := c.doSessionJSON(ctx, http.MethodPost, "/api/v1/admin/release", map[string]string{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminRevoke withdraws a package version and creates a security advisory via POST /api/v1/admin/revoke.
func (c *Client) AdminRevoke(ctx context.Context, req AdminRevokeRequest) (*AdminRevokeResponse, error) {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Version) == "" ||
		strings.TrimSpace(req.Severity) == "" || strings.TrimSpace(req.Title) == "" {
		return nil, errors.New("name, version, severity, and title are required for revocation")
	}
	var out AdminRevokeResponse
	if err := c.doSessionJSON(ctx, http.MethodPost, "/api/v1/admin/revoke", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminArchive deprecates a stable package version via POST /api/v1/admin/archive.
func (c *Client) AdminArchive(ctx context.Context, name, version string) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
		return errors.New("package name and version are required")
	}
	return c.doSessionJSON(ctx, http.MethodPost, "/api/v1/admin/archive", map[string]string{
		"name":    name,
		"version": version,
	}, nil)
}

// AdminCachePurge purges the Cloudflare edge cache via POST /api/v1/admin/cache-purge.
func (c *Client) AdminCachePurge(ctx context.Context) error {
	return c.doSessionJSON(ctx, http.MethodPost, "/api/v1/admin/cache-purge", map[string]string{}, nil)
}

// AdminMockWebhook dispatches a non-production PR validation webhook via POST /api/v1/admin/mock-webhook.
func (c *Client) AdminMockWebhook(ctx context.Context, req AdminMockWebhookRequest) (*AdminMockWebhookResponse, error) {
	var out AdminMockWebhookResponse
	if err := c.doSessionJSON(ctx, http.MethodPost, "/api/v1/admin/mock-webhook", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
