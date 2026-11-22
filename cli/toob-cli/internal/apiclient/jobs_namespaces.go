package apiclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Namespace represents a reserved @scope namespace on the Toob Registry.
type Namespace struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id,omitempty"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	SyncedAt  *time.Time `json:"synced_at,omitempty"`
}

// NamespaceMembership represents one registry namespace membership from GET /api/v1/orgs/mine.
type NamespaceMembership struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// ReserveNamespace reserves a @scope namespace on the registry via POST /api/v1/orgs.
func (c *Client) ReserveNamespace(ctx context.Context, name, tenantID string) (*Namespace, error) {
	name = strings.TrimPrefix(strings.TrimSpace(name), "@")
	if name == "" {
		return nil, errors.New("namespace name must not be empty")
	}
	body := map[string]string{"name": name}
	if strings.TrimSpace(tenantID) != "" {
		body["tenant_id"] = strings.TrimSpace(tenantID)
	}
	var out Namespace
	if err := c.doSessionJSON(ctx, http.MethodPost, "/api/v1/orgs", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListNamespaces lists the signed-in caller's registry namespaces via GET /api/v1/orgs/mine.
func (c *Client) ListNamespaces(ctx context.Context) ([]NamespaceMembership, error) {
	var out []NamespaceMembership
	if err := c.doSessionJSON(ctx, http.MethodGet, "/api/v1/orgs/mine", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PublishJob represents a Firecracker compile validation job from /api/v1/publish/jobs/{id}.
type PublishJob struct {
	ID               int64           `json:"id"`
	PackageID        string          `json:"package_id"`
	PackageName      string          `json:"package_name"`
	PackageVersion   string          `json:"package_version"`
	PublisherID      string          `json:"publisher_id"`
	ReferenceContext json.RawMessage `json:"reference_context"`
	Status           string          `json:"status"`
	CompilerLog      *string         `json:"compiler_log,omitempty"`
	ErrorMessage     *string         `json:"error_message,omitempty"`
	ErrorSummary     *string         `json:"error_summary,omitempty"`
	RetryCount       int             `json:"retry_count"`
	CreatedAt        time.Time       `json:"created_at"`
	StartedAt        *time.Time      `json:"started_at,omitempty"`
	FinishedAt       *time.Time      `json:"finished_at,omitempty"`
}

func isTerminalJobStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "PASSED", "FAILED", "CANCELLED":
		return true
	default:
		return false
	}
}

// GetPublishJob fetches the current state of a Firecracker publish validation job.
func (c *Client) GetPublishJob(ctx context.Context, jobID int64) (*PublishJob, error) {
	if jobID <= 0 {
		return nil, fmt.Errorf("invalid publish job ID %d", jobID)
	}
	var job PublishJob
	path := "/api/v1/publish/jobs/" + strconv.FormatInt(jobID, 10)
	if err := c.getJSON(ctx, path, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// StreamPublishJob connects to GET /api/v1/publish/jobs/{id}/stream (SSE), invokes
// onUpdate for each job status update, and returns the terminal PublishJob.
func (c *Client) StreamPublishJob(ctx context.Context, jobID int64, onUpdate func(*PublishJob) error) (*PublishJob, error) {
	if jobID <= 0 {
		return nil, fmt.Errorf("invalid publish job ID %d", jobID)
	}

	initial, err := c.GetPublishJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if onUpdate != nil {
		if cbErr := onUpdate(initial); cbErr != nil {
			return initial, cbErr
		}
	}
	if isTerminalJobStatus(initial.Status) {
		return initial, nil
	}

	streamPath := "/api/v1/publish/jobs/" + strconv.FormatInt(jobID, 10) + "/stream"
	req, err := c.newRequest(ctx, http.MethodGet, streamPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	streamClient := *c.HTTPClient
	streamClient.Timeout = 0 // Governed by ctx so long-running Firecracker jobs do not time out at 60s.

	resp, err := streamClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opening publish job stream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(resp)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)

	var eventName string
	var dataBuf strings.Builder
	latest := initial

	dispatch := func() (bool, error) {
		raw := strings.TrimSpace(dataBuf.String())
		ev := eventName
		eventName = ""
		dataBuf.Reset()

		if raw == "" || (ev != "" && ev != "status") {
			return false, nil
		}
		var job PublishJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			return false, fmt.Errorf("decoding publish job SSE event: %w", err)
		}
		latest = &job
		if onUpdate != nil {
			if cbErr := onUpdate(&job); cbErr != nil {
				return true, cbErr
			}
		}
		return isTerminalJobStatus(job.Status), nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			done, dErr := dispatch()
			if dErr != nil {
				return latest, dErr
			}
			if done {
				return latest, nil
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if after, ok := strings.CutPrefix(line, "event:"); ok {
			eventName = strings.TrimSpace(after)
		} else if after, ok := strings.CutPrefix(line, "data:"); ok {
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(strings.TrimSpace(after))
		}
	}
	if err := scanner.Err(); err != nil {
		return latest, fmt.Errorf("reading publish job stream: %w", err)
	}
	if dataBuf.Len() > 0 {
		if _, dErr := dispatch(); dErr != nil {
			return latest, dErr
		}
	}
	if isTerminalJobStatus(latest.Status) {
		return latest, nil
	}
	return c.GetPublishJob(ctx, jobID)
}
