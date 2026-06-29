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
	APIKey    string `json:"api_key"`
	Login     string `json:"login,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
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

// extractError reads the response body and creates a structured error.
// This ensures all API methods surface the server's error message to the user.
func extractError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))

	var apiErr struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &apiErr) == nil {
		msg := apiErr.Error
		if msg == "" {
			msg = apiErr.Message
		}
		if msg != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: msg}
		}
	}

	// Fallback: use raw body if it's short enough, otherwise just the status
	if len(body) > 0 && len(body) < 512 {
		return &APIError{StatusCode: resp.StatusCode, Message: string(body)}
	}
	return &APIError{StatusCode: resp.StatusCode}
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

// LoginResponse is the shape of POST /api/v1/auth/github.
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

// RotateKey rotates the publisher's API key.
func (c *Client) RotateKey(ctx context.Context, code string) (*LoginResponse, error) {
	payload, _ := json.Marshal(map[string]string{"code": code})
	req, err := c.newRequest(ctx, "POST", "/api/v1/auth/rotate-key", bytes.NewReader(payload))
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

// TokenExchange exchanges the temporary session code and PKCE verifier for the final API key.
func (c *Client) TokenExchange(ctx context.Context, code, verifier string) (*LoginResponse, error) {
	payload, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": verifier,
	})
	req, err := c.newRequest(ctx, "POST", "/api/v1/auth/token", bytes.NewReader(payload))
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

// Logout invalidates the publisher's API key on the server.
func (c *Client) Logout(ctx context.Context) (*LogoutResponse, error) {
	req, err := c.newRequest(ctx, "POST", "/api/v1/auth/logout", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(resp)
	}

	var result LogoutResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
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
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return req, nil
}

// doWithRetry executes a request with exponential backoff for transient server errors (5xx).
// Non-5xx responses and client errors are returned immediately without retry.
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * 500 * time.Millisecond
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(backoff):
			}
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("api request failed: %w", err)
			continue
		}

		// Only retry on 5xx server errors
		if resp.StatusCode >= 500 && attempt < maxRetries {
			resp.Body.Close()
			lastErr = fmt.Errorf("server returned HTTP %d (attempt %d/%d)", resp.StatusCode, attempt+1, maxRetries+1)
			continue
		}

		return resp, nil
	}
	return nil, lastErr
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
