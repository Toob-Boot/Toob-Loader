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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/toob-boot/toob/internal/paths"
)

const (
	// DefaultBaseURL is the production API endpoint served via Cloudflare.
	DefaultBaseURL = "https://registry.the-toob.com"

	defaultTimeout = 10 * time.Second
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
	token := loadToken()
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout:   defaultTimeout,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
		},
	}
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

// --- Token Management ---

type credentials struct {
	APIKey string `json:"api_key"`
}

func credentialsPath() string {
	home, err := paths.ToobHome()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "credentials.json")
}

func loadToken() string {
	path := credentialsPath()
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var creds credentials
	if json.Unmarshal(data, &creds) != nil {
		return ""
	}
	return creds.APIKey
}

// SaveToken persists an API key to ~/.toob/credentials.json with mode 0600.
func SaveToken(apiKey string) error {
	path := credentialsPath()
	if path == "" {
		return fmt.Errorf("cannot determine credentials path")
	}
	data, _ := json.MarshalIndent(credentials{APIKey: apiKey}, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// HasToken returns true if the client has a stored API key.
func (c *Client) HasToken() bool {
	return c.Token != ""
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

// RegistryVersionResponse is the backward-compat shape of /resolve/registry.
type RegistryVersionResponse struct {
	Version string `json:"version"`
}

// GetRegistryVersion calls the backward-compatible /resolve/registry endpoint.
func (c *Client) GetRegistryVersion(ctx context.Context) (string, error) {
	var resp RegistryVersionResponse
	if err := c.getJSON(ctx, "/api/v1/resolve/registry?version=latest", &resp); err != nil {
		return "", err
	}
	return resp.Version, nil
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
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ListIntegrations returns all available integration frameworks.
func (c *Client) ListIntegrations(ctx context.Context) ([]IntegrationItem, error) {
	var items []IntegrationItem
	if err := c.getJSON(ctx, "/api/v1/resolve/integrations", &items); err != nil {
		return nil, err
	}
	return items, nil
}

// GetMatrix returns the full or chip-filtered compatibility matrix.
func (c *Client) GetMatrix(ctx context.Context, chip string) (json.RawMessage, error) {
	path := "/api/v1/resolve/matrix"
	if chip != "" {
		path += "?chip=" + chip
	}
	return c.getRaw(ctx, path)
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
	Status     string `json:"status"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	TarballSHA string `json:"tarball_sha"`
	Signature  string `json:"signature"`
}

// Publish uploads a new package version.
func (c *Client) Publish(ctx context.Context, body io.Reader, contentType string) (*PublishResponse, error) {
	req, err := c.newRequest(ctx, "POST", "/api/v1/publish", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("publish failed with HTTP %d", resp.StatusCode)
	}

	var result PublishResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
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
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unpublish failed with HTTP %d", resp.StatusCode)
	}

	var result UnpublishResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SyncDeltaResponse is the shape of GET /api/v1/registry/sync.
type SyncDeltaResponse struct {
	Since     int64             `json:"since"`
	Count     int               `json:"count"`
	Revisions []json.RawMessage `json:"revisions"` // Opaque for now
	HasMore   bool              `json:"has_more"`
}

// GetSyncDelta fetches registry changes since a given revision.
func (c *Client) GetSyncDelta(ctx context.Context, since int64) (*SyncDeltaResponse, error) {
	var resp SyncDeltaResponse
	path := fmt.Sprintf("/api/v1/registry/sync?since=%d", since)
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AckSyncResponse is the shape of POST /api/v1/registry/ack.
type AckSyncResponse struct {
	Status     string            `json:"status"`
	Advisories []json.RawMessage `json:"advisories"` // Opaque for now
}

// AckSync acknowledges a registry sync to receive pending security advisories.
func (c *Client) AckSync(ctx context.Context, revisionID int64, clientInfo string) (*AckSyncResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"revision_id": revisionID,
		"client_info": clientInfo,
	})

	req, err := c.newRequest(ctx, "POST", "/api/v1/registry/ack", bytes.NewReader(payload))
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
		return nil, fmt.Errorf("ack failed with HTTP %d", resp.StatusCode)
	}

	var result AckSyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
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
		return nil, fmt.Errorf("rotate-key failed with HTTP %d", resp.StatusCode)
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
		return nil, fmt.Errorf("login failed with HTTP %d", resp.StatusCode)
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

// Logout invalidates the publisher's API key.
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
		return nil, fmt.Errorf("logout failed with HTTP %d", resp.StatusCode)
	}

	var result LogoutResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
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

func (c *Client) getJSON(ctx context.Context, path string, target interface{}) error {
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("api returned HTTP %d for %s", resp.StatusCode, path)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned HTTP %d for %s", resp.StatusCode, path)
	}

	return io.ReadAll(resp.Body)
}
