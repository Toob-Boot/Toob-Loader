// Package apiclient provides a centralized HTTP client for all Toob Registry
// API interactions. It consolidates the scattered http.Client usage across
// cache.go, regcheck.go, and chip.go into a single, configurable client.
//
// URL resolution priority:
//  1. TOOB_REGISTRY_URL environment variable
//  2. TOOB_HUB_URL environment variable (deprecated alias)
//  3. Hardcoded default: https://registry.the-toob.com
package apiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/paths"
)

var (
	// DefaultBaseURL is the production API endpoint served via Cloudflare.
	DefaultBaseURL = "https://registry.the-toob.com"
)

const (
	// defaultTimeout is the standard timeout for read operations (GET, list, etc.).
	defaultTimeout = 60 * time.Second

	// UploadTimeout is the extended timeout for write operations (publish, upload).
	UploadTimeout = 120 * time.Second

	// maxRetries is the number of automatic retries for transient (5xx) errors.
	maxRetries = 3

	// maxErrorBodySize limits how much of an error response body we read.
	maxErrorBodySize = 4096
)

// Client communicates with the Toob Registry API.
type Client struct {
	BaseURL    string
	Token      string // Optional API key from ~/.toob/credentials.json
	HTTPClient *http.Client
}

// New creates a Client with the resolved base URL and optional auth token.
func New() *Client {
	baseURL := resolveBaseURL()
	creds := loadCredentials()
	return &Client{
		BaseURL: baseURL,
		Token:   creds.APIKey,
		HTTPClient: &http.Client{
			Timeout:   defaultTimeout,
			Transport: BuildTransport(),
		},
	}
}

// BuildTransport creates an http.Transport with proxy support and optional
// custom CA certificate via TOOB_CA_CERT environment variable.
// Exported so other packages can build HTTP clients with the same enterprise
// network configuration (CA roots, proxy) without duplicating this logic.
func BuildTransport() *http.Transport {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}

	caPath := os.Getenv("TOOB_CA_CERT")
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(caCert)
			transport.TLSClientConfig = &tls.Config{RootCAs: pool}
		}
	}

	return transport
}

// NewWithTimeout creates a Client with a custom timeout for upload-heavy operations.
func NewWithTimeout(timeout time.Duration) *Client {
	c := New()
	c.HTTPClient.Timeout = timeout
	return c
}

// --- URL Resolution ---

func resolveBaseURL() string {
	if url := os.Getenv("TOOB_REGISTRY_URL"); url != "" {
		return url
	}
	// Backward compat: TOOB_HUB_URL was the old env var name.
	if url := os.Getenv("TOOB_HUB_URL"); url != "" {
		return url
	}
	return DefaultBaseURL
}

// --- Credentials Management ---

// Credentials holds the persisted authentication state.
type Credentials struct {
	// APIKey is the long-lived credential for machines: CI jobs, scripts, anything that cannot open
	// a browser. It stays alongside a person's session rather than being replaced by it.
	APIKey    string `json:"api_key"`
	Login     string `json:"login,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`

	// Identity is the person's own session, obtained from the identity provider.
	Identity *IdentityCredentials `json:"identity,omitempty"`
}

func credentialsPath() string {
	home, err := paths.ToobHome()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "credentials.json")
}

func loadCredentials() Credentials {
	path := credentialsPath()
	if path == "" {
		return Credentials{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}
	}
	var creds Credentials
	if json.Unmarshal(data, &creds) != nil {
		return Credentials{}
	}
	return creds
}

// SaveCredentials persists an API key and login to ~/.toob/credentials.json
// using atomic write (temp file + rename) to prevent corruption from parallel processes.
func SaveCredentials(apiKey, login string) error {
	path := credentialsPath()
	if path == "" {
		return fmt.Errorf("cannot determine credentials path")
	}

	creds := Credentials{
		APIKey:    apiKey,
		Login:     login,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	// Atomic write: write to temp file, then rename to target
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// SaveToken is a backward-compatible wrapper around SaveCredentials.
func SaveToken(apiKey string) error {
	return SaveCredentials(apiKey, "")
}

// DeleteCredentials removes the local credentials file.
func DeleteCredentials() error {
	path := credentialsPath()
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// HasToken returns true if the client has a stored API key.
func (c *Client) HasToken() bool {
	return c.Token != ""
}

// GetLogin returns the stored login name from credentials, if available.
func GetLogin() string {
	return loadCredentials().Login
}

// --- API Error Handling ---

// APIError represents a structured error response from the server.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// StepUpRequired is the registry asking for a fresher or stronger authentication before it will
// perform the operation (RFC 9470).
//
// It is its own error type because it is not a failure: the credential was accepted, and what is
// missing is a ceremony the person can perform right now. A command that receives it signs in again
// with what the challenge names and retries once — see cmd.withStepUp — instead of reporting a 401
// the person has no way to act on.
type StepUpRequired struct {
	// ACRValues is the authentication context the registry asks for, passed through to the
	// identity provider as acr_values.
	ACRValues string
	// MaxAge is how recent the authentication has to be.
	MaxAge time.Duration
	Detail string
}

func (e *StepUpRequired) Error() string {
	if e.Detail != "" {
		return "the registry requires a fresh sign-in for this operation: " + e.Detail
	}
	return "the registry requires a fresh sign-in for this operation"
}

// stepUpChallenge is the WWW-Authenticate value the registry sends for a step-up, e.g.
//
//	DPoP error="insufficient_user_authentication", acr_values="urn:toob:mfa:webauthn", max_age=300
var stepUpChallenge = regexp.MustCompile(`error="insufficient_user_authentication"`)

// parseStepUp reads a step-up challenge from a 401, or reports that the response is not one.
func parseStepUp(resp *http.Response, detail string) (*StepUpRequired, bool) {
	header := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized || !stepUpChallenge.MatchString(header) {
		return nil, false
	}

	challenge := &StepUpRequired{Detail: detail}
	for _, param := range strings.Split(header, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found {
			continue
		}
		value = strings.Trim(value, `"`)
		switch strings.TrimSpace(key) {
		case "acr_values":
			challenge.ACRValues = value
		case "max_age":
			if seconds, err := strconv.Atoi(value); err == nil {
				challenge.MaxAge = time.Duration(seconds) * time.Second
			}
		}
	}
	return challenge, true
}

// extractError reads the response body and creates a structured error.
// This ensures all API methods surface the server's error message to the user.
//
// Every service answers RFC 9457 Problem Details, whose text for a person is "detail" and whose
// name for a program is "code". A body in another shape — an edge proxy's page, a body of no
// shape at all — is shown as it is when short.
func extractError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))

	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	var msg string
	if json.Unmarshal(body, &problem) == nil {
		msg = problem.Detail
		if msg == "" {
			msg = problem.Code
		}
	}
	if msg == "" && len(body) > 0 && len(body) < 512 {
		msg = string(body)
	}

	if challenge, ok := parseStepUp(resp, msg); ok {
		return challenge
	}
	return &APIError{StatusCode: resp.StatusCode, Message: msg}
}

// --- API Methods ---

// RevisionResponse is the JSON shape of GET /api/v1/registry/revision.
type RevisionResponse struct {
	Revision      int64  `json:"revision"`
	FormatVersion int    `json:"format_version"`
	CommitSHA     string `json:"commit_sha"`
	Signature     string `json:"signature,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// GetRevision returns the current registry revision from the API.
func (c *Client) GetRevision(ctx context.Context) (*RevisionResponse, error) {
	var rev RevisionResponse
	if err := c.getJSON(ctx, "/api/v1/registry/revision", &rev); err != nil {
		return nil, err
	}
	return &rev, nil
}

// GetIndex downloads the full registry.json index.
func (c *Client) GetIndex(ctx context.Context) ([]byte, error) {
	return c.getRaw(ctx, "/api/v1/registry/index")
}

// ChipResolveResponse is the shape of GET /api/v1/resolve/chip.
type ChipResolveResponse struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Path     string          `json:"path"`
	Manifest json.RawMessage `json:"manifest"`
}

// ResolveChip queries the API for a specific chip.
func (c *Client) ResolveChip(ctx context.Context, name string) (*ChipResolveResponse, error) {
	var resp ChipResolveResponse
	err := c.getJSON(ctx, fmt.Sprintf("/api/v1/resolve/chip?name=%s", name), &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// IntegrationItem is one entry from /resolve/integrations.
type IntegrationItem struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Path        string `json:"path"`
}

// ListIntegrations returns all available integration frameworks.
func (c *Client) ListIntegrations(ctx context.Context) ([]IntegrationItem, error) {
	var items []IntegrationItem
	if err := c.getJSON(ctx, "/api/v1/resolve/integrations", &items); err != nil {
		return nil, err
	}
	return items, nil
}

// MatrixEntry represents a single verified (or pending) build combination
// for a chip at a specific version.
type MatrixEntry struct {
	ID             int64           `json:"id"`
	Chip           string          `json:"chip"`
	ChipVersion    string          `json:"chip_version"`
	EnvHash        string          `json:"env_hash"`
	Dependencies   json.RawMessage `json:"dependencies"`
	CombinationKey string          `json:"combination_key"`
	Status         string          `json:"status"`
	TestedAt       *time.Time      `json:"tested_at"`
	Revision       *int64          `json:"revision"`
}

// GetMatrix returns the full or chip-filtered compatibility matrix.
func (c *Client) GetMatrix(ctx context.Context, chip string) ([]MatrixEntry, error) {
	path := "/api/v1/resolve/matrix"
	if chip != "" {
		path += "?chip=" + chip
	}
	var entries []MatrixEntry
	if err := c.getJSON(ctx, path, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// LoginResponse was the shape of POST /api/v1/auth/github, an endpoint the registry does not serve.
// Signing in goes to the identity provider now; see internal/oidc and AuthConfig.
//
// Kept only for the fields other commands still read from stored credentials.
type LoginResponse struct {
	PublisherID string `json:"publisher_id"`
	Login       string `json:"login"`
	Role        string `json:"role"`
	APIKey      string `json:"api_key,omitempty"`
	HasAPIKey   bool   `json:"has_api_key"`
}

// CheckCombinationResponse is the shape of GET /api/v1/resolve/combination.
type CheckCombinationResponse struct {
	Compatible bool   `json:"compatible"`
	Status     string `json:"status"`
	LastTested string `json:"last_tested,omitempty"`
}

// CheckCombination verifies if a specific build combination is verified.
func (c *Client) CheckCombination(ctx context.Context, chip, chipVersion, cliVersion string) (*CheckCombinationResponse, error) {
	var resp CheckCombinationResponse
	path := fmt.Sprintf("/api/v1/resolve/combination?chip=%s&chip_version=%s", chip, chipVersion)
	if cliVersion != "" {
		path += "&cli=" + cliVersion
	}
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PackageResponse is the shape of GET /api/v1/package/{name}/{version}.
type PackageResponse struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Category string          `json:"category"`
	Stage    string          `json:"stage"`
	Path     string          `json:"path"`
	Manifest json.RawMessage `json:"manifest"`
}

// GetPackage returns the manifest and metadata for a specific package version.
func (c *Client) GetPackage(ctx context.Context, name, version string) (*PackageResponse, error) {
	var resp PackageResponse
	path := fmt.Sprintf("/api/v1/package/%s/%s", name, version)
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// MyPackageSummary is the shape of GET /api/v1/packages/mine element.
type MyPackageSummary struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Category        string `json:"category"`
	Stage           string `json:"stage"`
	StagingStatus   string `json:"staging_status,omitempty"`
	StagingFeedback string `json:"staging_feedback,omitempty"`
	TarballSHA      string `json:"tarball_sha"`
	CreatedAt       string `json:"created_at"`
}

// MyPackagesResponse is the shape of GET /api/v1/packages/mine.
type MyPackagesResponse struct {
	Count    int                `json:"count"`
	Packages []MyPackageSummary `json:"packages"`
}

// MyPackages returns all packages owned by the authenticated publisher.
func (c *Client) MyPackages(ctx context.Context) (*MyPackagesResponse, error) {
	var resp MyPackagesResponse
	if err := c.getJSON(ctx, "/api/v1/packages/mine", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PublishResponse is the shape of POST /api/v1/publish.
type PublishResponse struct {
	Status            string   `json:"status"`
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	Category          string   `json:"category"`
	Stage             string   `json:"stage"`
	TarballSHA        string   `json:"tarball_sha"`
	Signature         string   `json:"signature"`
	IngestionWarnings []string `json:"ingestion_warnings,omitempty"`
}

// Publish uploads a new package version.
func (c *Client) Publish(ctx context.Context, body io.Reader, contentType string) (*PublishResponse, error) {
	req, err := c.newRequest(ctx, "POST", "/api/v1/publish", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("publish request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, extractError(resp)
	}

	var result PublishResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PromoteResponse is the shape of POST /api/v1/publish/promote.
type PromoteResponse struct {
	Status  string `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
	JobID   string `json:"job_id"`
	Message string `json:"message"`
	Warning string `json:"warning,omitempty"`
}

// Promote triggers compile validation for a dev-stage package.
func (c *Client) Promote(ctx context.Context, name, version string) (*PromoteResponse, error) {
	payload, _ := json.Marshal(map[string]string{
		"name":    name,
		"version": version,
	})

	req, err := c.newRequest(ctx, "POST", "/api/v1/publish/promote", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("promote request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, extractError(resp)
	}

	var result PromoteResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckNameAvailableResponse is the shape of GET /api/v1/publish/check-name.
type CheckNameAvailableResponse struct {
	Available bool   `json:"available"`
	Message   string `json:"message,omitempty"`
}

// CheckNameAvailable checks if a package name is still available for publishing.
func (c *Client) CheckNameAvailable(ctx context.Context, name string) (*CheckNameAvailableResponse, error) {
	var resp CheckNameAvailableResponse
	path := fmt.Sprintf("/api/v1/packages/check-name?name=%s", name)
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UnpublishResponse is the shape of DELETE /api/v1/package/{name}/{version}.
type UnpublishResponse struct {
	Status  string `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Unpublish removes a package version in the dev stage.
func (c *Client) Unpublish(ctx context.Context, name, version string) (*UnpublishResponse, error) {
	path := fmt.Sprintf("/api/v1/package/%s/%s", name, version)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unpublish request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(resp)
	}

	var result UnpublishResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DownloadPackage follows the /download redirect and returns the tarball body.
// The caller is responsible for closing the returned ReadCloser.
func (c *Client) DownloadPackage(ctx context.Context, name, version string) (io.ReadCloser, error) {
	path := fmt.Sprintf("/api/v1/package/%s/%s/download", name, version)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, extractError(resp)
	}

	return resp.Body, nil
}

// Login with GitHub OAuth.
func (c *Client) Login(ctx context.Context, code string) (*LoginResponse, error) {
	payload, _ := json.Marshal(map[string]string{"code": code})
	req, err := c.newRequest(ctx, "POST", "/api/v1/auth/github", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(resp)
	}

	var result LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// LogoutResponse is the shape of POST /api/v1/auth/logout.
type LogoutResponse struct {
	Status string `json:"status"`
}

// --- Token Management ---

// TokenCreateRequest is the payload for POST /api/v1/tokens.
type TokenCreateRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresIn *int     `json:"expires_in_days,omitempty"`
}

// TokenCreateResponse is the shape of POST /api/v1/tokens.
type TokenCreateResponse struct {
	Token string `json:"token"`
	ID    string `json:"id"`
	Name  string `json:"name"`
}

// CreateToken creates a new scoped API token.
func (c *Client) CreateToken(ctx context.Context, req *TokenCreateRequest) (*TokenCreateResponse, error) {
	payload, _ := json.Marshal(req)
	httpReq, err := c.newRequest(ctx, "POST", "/api/v1/tokens", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(resp)
	}

	var result TokenCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TokenSummary is one element from GET /api/v1/tokens.
type TokenSummary struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	LastUsed  string   `json:"last_used_at,omitempty"`
}

// TokenListResponse is the shape of GET /api/v1/tokens.
type TokenListResponse struct {
	Tokens []TokenSummary `json:"tokens"`
}

// ListTokens returns all API tokens for the authenticated publisher.
func (c *Client) ListTokens(ctx context.Context) (*TokenListResponse, error) {
	var resp TokenListResponse
	if err := c.getJSON(ctx, "/api/v1/tokens", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeToken invalidates a specific API token by ID.
func (c *Client) RevokeToken(ctx context.Context, tokenID string) error {
	path := fmt.Sprintf("/api/v1/tokens/%s", tokenID)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return extractError(resp)
	}
	return nil
}

// --- Search ---

// SearchResult is one element from GET /api/v1/search.
type SearchResult struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
	Downloads   int    `json:"downloads,omitempty"`
}

// SearchResponse is the shape of GET /api/v1/search.
type SearchResponse struct {
	Results []SearchResult `json:"results"`
	Count   int            `json:"count"`
}

// Search queries the registry for packages matching a query string.
func (c *Client) Search(ctx context.Context, query string) (*SearchResponse, error) {
	var resp SearchResponse
	path := fmt.Sprintf("/api/v1/search?q=%s", query)
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// --- HTTP Primitives ---

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	url := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Toob-CLI")
	// Resolved per request rather than captured at construction: a session expires while a process
	// runs, and the refresh has to happen between two commands as readily as between two runs.
	if bearer := c.bearer(ctx); bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req, nil
}

// maxRetryAfter caps how long a Retry-After header may make this client wait.
//
// The registry names its windows in seconds and none is longer than a minute, so a value above
// this is not one the registry sent — and waiting an hour because a proxy said so is not something
// a command-line tool does silently.
const maxRetryAfter = 60 * time.Second

// doWithRetry executes a request again after a transient failure: a 5xx, or a 429 that says when
// to come back.
//
// A 429 is retried only when it carries Retry-After, and then after exactly that long. The server
// computed the wait from the budget it refused; guessing with a backoff of our own would either
// hammer a limit that has not reset or sit out one that has. A 429 without the header is returned
// as it is, because there is nothing to act on.
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	var wait time.Duration
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if wait == 0 {
				wait = time.Duration(math.Pow(2, float64(attempt-1))) * 500 * time.Millisecond
			}
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(wait):
			}
			wait = 0
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("api request failed: %w", err)
			continue
		}

		// A wait the server named is honoured before any backoff of our own: a 429 is the caller's
		// budget, a 503 with Retry-After is the registry at capacity or its authorization store not
		// answering (overloaded, authz_unavailable), and in both the header is the whole instruction.
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) && attempt < maxRetries {
			if retryAfter, ok := retryAfterOf(resp); ok {
				resp.Body.Close()
				wait = retryAfter
				lastErr = fmt.Errorf("server asked to retry after %s (HTTP %d, attempt %d/%d)", retryAfter, resp.StatusCode, attempt+1, maxRetries+1)
				continue
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			// No wait named: nothing to act on, and a backoff of our own would be a guess about a
			// budget the server did not describe.
			return resp, nil
		}
		if resp.StatusCode >= 500 && attempt < maxRetries {
			resp.Body.Close()
			lastErr = fmt.Errorf("server returned HTTP %d (attempt %d/%d)", resp.StatusCode, attempt+1, maxRetries+1)
			continue
		}

		return resp, nil
	}
	return nil, lastErr
}

// retryAfterOf reads a Retry-After given in seconds, and reports whether there was one to read.
func retryAfterOf(resp *http.Response) (time.Duration, bool) {
	seconds, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After")))
	if err != nil || seconds < 0 {
		return 0, false
	}
	wait := time.Duration(seconds) * time.Second
	if wait > maxRetryAfter {
		wait = maxRetryAfter
	}
	return wait, true
}

func (c *Client) getJSON(ctx context.Context, path string, target any) error {
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return extractError(resp)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(resp)
	}

	return io.ReadAll(resp.Body)
}
