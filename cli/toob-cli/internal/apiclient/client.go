// Package apiclient provides a centralized HTTP client for all Toob Registry
// and Identity API interactions.
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
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/paths"
)

// DefaultBaseURL is the production Registry API endpoint served via Cloudflare.
var DefaultBaseURL = "https://registry.the-toob.com"

const (
	defaultTimeout      = 60 * time.Second
	UploadTimeout       = 120 * time.Second
	maxRetries          = 3
	maxErrorBodySize    = 4096
	maxRawResponseBytes = 50 << 20 // 50 MiB
	maxUploadBodyBytes  = 64 << 20 // 64 MiB

	// TokenEnv carries a TOOB credential for one run (CI / automation).
	TokenEnv = "TOOB_TOKEN"
)

type errorRoundTripper struct {
	err error
}

func (e errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.err
}

// Client communicates with the Toob Registry and Identity APIs.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client

	transportErr     error
	authMu           sync.Mutex
	cachedAuthConfig *AuthConfig

	warnMu   sync.Mutex
	warnings []string
}

// SafeCheckRedirect enforces redirect caps, blocks HTTPS->HTTP scheme downgrades,
// and strips cross-host Authorization headers.
func SafeCheckRedirect(req *http.Request, via []*http.Request) error {
	return httputil.SafeCheckRedirect(req, via)
}

// BuildTransport returns an http.RoundTripper configured with enterprise proxy and
// TOOB_CA_CERT roots, surfacing any TOOB_CA_CERT load error on the first request.
func BuildTransport() http.RoundTripper {
	tr, err := httputil.BuildTransport()
	if err != nil {
		return errorRoundTripper{err: err}
	}
	return tr
}

// New creates a Client with the resolved base URL and default timeout.
func New() *Client {
	return NewForBaseURL("", defaultTimeout)
}

// NewWithTimeout creates a Client with a custom timeout on the resolved base URL.
func NewWithTimeout(timeout time.Duration) *Client {
	return NewForBaseURL("", timeout)
}

// NewForBaseURL creates a Client targeting baseURL (falling back to environment/default
// when empty) with trailing slashes stripped and TOOB_CA_CERT validated.
func NewForBaseURL(baseURL string, timeout time.Duration) *Client {
	resolvedDefault := resolveBaseURL()
	cleanBase := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if cleanBase == "" {
		cleanBase = resolvedDefault
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	creds := loadCredentials()
	token := os.Getenv(TokenEnv)
	if token == "" {
		baseOrigin, bErr := httputil.CanonicalOrigin(cleanBase)
		defOrigin, dErr := httputil.CanonicalOrigin(resolvedDefault)
		if bErr == nil && dErr == nil && baseOrigin == defOrigin {
			token = creds.APIKey
		}
	}

	c := &Client{
		BaseURL: cleanBase,
		Token:   token,
	}

	tr, err := httputil.BuildTransport()
	var rt http.RoundTripper = tr
	if err != nil {
		c.transportErr = err
		rt = errorRoundTripper{err: err}
	}

	c.HTTPClient = &http.Client{
		Timeout:   timeout,
		Transport: rt,
		CheckRedirect: httputil.NewSafeCheckRedirect(func(warning string) {
			c.recordWarning(warning)
		}),
	}
	return c
}

func (c *Client) recordWarning(w string) {
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	if !slices.Contains(c.warnings, w) {
		c.warnings = append(c.warnings, w)
	}
}

// Warnings returns any X-Toob-Warning headers captured across requests and redirect hops.
func (c *Client) Warnings() []string {
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	return slices.Clone(c.warnings)
}

func resolveBaseURL() string {
	raw := cmp.Or(
		strings.TrimSpace(os.Getenv("TOOB_REGISTRY_URL")),
		strings.TrimSpace(os.Getenv("TOOB_HUB_URL")),
		DefaultBaseURL,
	)
	return strings.TrimRight(raw, "/")
}

// Credentials holds the persisted authentication state on disk.
type Credentials struct {
	APIKey    string               `json:"api_key"`
	Login     string               `json:"login,omitempty"`
	CreatedAt string               `json:"created_at,omitempty"`
	Identity  *IdentityCredentials `json:"identity,omitempty"`
}

func loadCredentials() Credentials {
	path, err := paths.CredentialsPath()
	if err != nil {
		return Credentials{}
	}
	creds, err := loadCredentialsStrict(path)
	if err != nil {
		return Credentials{}
	}
	return creds
}

// HasToken reports whether the client can authenticate via TOOB_TOKEN, API key, or session.
func (c *Client) HasToken() bool {
	return os.Getenv(TokenEnv) != "" || c.Token != "" || HasSession()
}

// GetLogin returns the stored login username from credentials, if available.
func GetLogin() string {
	return loadCredentials().Login
}

// APIError represents a structured HTTP error response from the server.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// StepUpRequired represents an RFC 9470 step-up authentication challenge.
//
//nolint:errname // Exported StepUpRequired type name is part of the apiclient contract referenced by cmd/.
type StepUpRequired struct {
	ACRValues string
	MaxAge    time.Duration
	Detail    string
}

func (e *StepUpRequired) Error() string {
	if e.Detail != "" {
		return "the registry requires a fresh sign-in for this operation: " + e.Detail
	}
	return "the registry requires a fresh sign-in for this operation"
}

var stepUpChallenge = regexp.MustCompile(`error="insufficient_user_authentication"`)

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

func extractError(resp *http.Response) error {
	body, _ := httputil.ReadBounded(resp.Body, maxErrorBodySize)

	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	var msg string
	if len(body) > 0 && json.Unmarshal(body, &problem) == nil {
		msg = cmp.Or(problem.Detail, problem.Code)
	}
	if msg == "" && len(body) > 0 && len(body) < 512 {
		msg = strings.TrimSpace(string(body))
	}

	if challenge, ok := parseStepUp(resp, msg); ok {
		return challenge
	}
	return &APIError{StatusCode: resp.StatusCode, Code: problem.Code, Message: msg}
}

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
	data, _, err := c.GetIndexWithMeta(ctx, "")
	return data, err
}

// GetIndexWithMeta downloads registry.json (optionally pinned to revision) and returns
// its raw bytes together with any X-Registry-Signature header from the server.
func (c *Client) GetIndexWithMeta(ctx context.Context, revision string) ([]byte, string, error) {
	path := "/api/v1/registry/index"
	if revision != "" && revision != "latest" {
		path += "?revision=" + url.QueryEscape(revision)
	}
	req, err := c.newPublicRequest(ctx, http.MethodGet, path)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", extractError(resp)
	}
	data, err := httputil.ReadBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return nil, "", fmt.Errorf("reading registry index: %w", err)
	}
	return data, strings.TrimSpace(resp.Header.Get("X-Registry-Signature")), nil
}

func packageAPIPath(name, version, suffix string) (string, error) {
	if name == "" || version == "" {
		return "", errors.New("package name and version must not be empty")
	}
	var namePart string
	if strings.HasPrefix(name, "@") {
		scope, pkg, ok := strings.Cut(name, "/")
		if !ok || scope == "@" || pkg == "" || strings.Contains(pkg, "/") {
			return "", fmt.Errorf("invalid scoped package name %q", name)
		}
		namePart = url.PathEscape(scope) + "/" + url.PathEscape(pkg)
	} else {
		namePart = url.PathEscape(name)
	}
	return "/api/v1/package/" + namePart + "/" + url.PathEscape(version) + suffix, nil
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
	if err := c.getJSON(ctx, "/api/v1/resolve/chip?name="+url.QueryEscape(name), &resp); err != nil {
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

// MatrixEntry represents a single verified or pending build combination.
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
		path += "?chip=" + url.QueryEscape(chip)
	}
	var entries []MatrixEntry
	if err := c.getJSON(ctx, path, &entries); err != nil {
		return nil, err
	}
	return entries, nil
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
	path := fmt.Sprintf("/api/v1/resolve/combination?chip=%s&chip_version=%s", url.QueryEscape(chip), url.QueryEscape(chipVersion))
	if cliVersion != "" {
		path += "&cli=" + url.QueryEscape(cliVersion)
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
	path, err := packageAPIPath(name, version, "")
	if err != nil {
		return nil, err
	}
	var resp PackageResponse
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// MyPackageSummary is one element of GET /api/v1/packages/mine.
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

// MyPackages fetches all pages of packages owned by the authenticated publisher.
func (c *Client) MyPackages(ctx context.Context) (*MyPackagesResponse, error) {
	const pageLimit = 100
	var all []MyPackageSummary
	offset := 0

	for {
		var page struct {
			Count    int                `json:"count"`
			Packages []MyPackageSummary `json:"packages"`
			HasMore  bool               `json:"has_more"`
		}
		path := fmt.Sprintf("/api/v1/packages/mine?limit=%d&offset=%d", pageLimit, offset)
		if err := c.getJSON(ctx, path, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Packages...)
		if !page.HasMore || len(page.Packages) == 0 {
			break
		}
		offset += len(page.Packages)
	}

	return &MyPackagesResponse{
		Count:    len(all),
		Packages: all,
	}, nil
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

func rewindableBody(body io.Reader) (io.Reader, error) {
	if body == nil {
		return nil, nil
	}
	switch r := body.(type) {
	case *bytes.Reader:
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return r, nil
	case *strings.Reader:
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return r, nil
	case *bytes.Buffer:
		return bytes.NewReader(r.Bytes()), nil
	default:
		raw, err := httputil.ReadBounded(body, maxUploadBodyBytes)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(raw), nil
	}
}

// Publish uploads a new package version with an Idempotency-Key and rewindable body.
func (c *Client) Publish(ctx context.Context, body io.Reader, contentType string) (*PublishResponse, error) {
	rewindable, err := rewindableBody(body)
	if err != nil {
		return nil, fmt.Errorf("buffering publish payload: %w", err)
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/publish", rewindable)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Idempotency-Key", rand.Text())

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("publish request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, extractError(resp)
	}

	raw, err := httputil.ReadBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return nil, err
	}
	var result PublishResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PromoteResponse is the shape of POST /api/v1/publish/promote.
type PromoteResponse struct {
	Status  string `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
	JobID   int64  `json:"job_id"`
	Message string `json:"message"`
	Warning string `json:"warning,omitempty"`
}

// Promote triggers Firecracker compile validation for a dev-stage package.
func (c *Client) Promote(ctx context.Context, name, version string) (*PromoteResponse, error) {
	payload, err := json.Marshal(map[string]string{
		"name":    name,
		"version": version,
	})
	if err != nil {
		return nil, err
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/publish/promote", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", rand.Text())

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("promote request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, extractError(resp)
	}

	raw, err := httputil.ReadBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return nil, err
	}
	var result PromoteResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckNameAvailableResponse is the shape of GET /api/v1/packages/check-name.
type CheckNameAvailableResponse struct {
	Available bool   `json:"available"`
	Message   string `json:"message,omitempty"`
}

// CheckNameAvailable checks if a package name is still available for publishing.
func (c *Client) CheckNameAvailable(ctx context.Context, name string) (*CheckNameAvailableResponse, error) {
	var resp CheckNameAvailableResponse
	path := "/api/v1/packages/check-name?name=" + url.QueryEscape(name)
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
	path, err := packageAPIPath(name, version, "")
	if err != nil {
		return nil, err
	}
	req, err := c.newSessionRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Idempotency-Key", rand.Text())

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("unpublish request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(resp)
	}

	raw, err := httputil.ReadBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return nil, err
	}
	var result UnpublishResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DownloadPackage follows the /download redirect and returns the tarball body.
func (c *Client) DownloadPackage(ctx context.Context, name, version string) (io.ReadCloser, error) {
	path, err := packageAPIPath(name, version, "/download")
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		err = extractError(resp)
		_ = resp.Body.Close()
		return nil, err
	}
	if warn := strings.TrimSpace(resp.Header.Get("X-Toob-Warning")); warn != "" {
		c.recordWarning(warn)
	}
	return resp.Body, nil
}

// DownloadRelease downloads a public ecosystem release artifact (such as Core SDK or CLI)
// from GET /api/v1/releases/{component}/{version}/download/{filename}, normalizing tags
// like "core/v0.0.1" or "v0.7.0" to "0.0.1" / "0.7.0".
func (c *Client) DownloadRelease(ctx context.Context, component, version, filename string) (io.ReadCloser, error) {
	component = strings.TrimSpace(component)
	version = strings.TrimSpace(version)
	filename = strings.TrimSpace(filename)
	if component == "" || version == "" || filename == "" {
		return nil, errors.New("release component, version, and filename must not be empty")
	}

	version = strings.TrimPrefix(version, component+"/")
	version = strings.TrimPrefix(version, "core/")
	version = strings.TrimPrefix(version, "v")
	if version == "" || strings.Contains(version, "/") || strings.Contains(version, "..") {
		return nil, fmt.Errorf("invalid release version %q", version)
	}
	if strings.Contains(filename, "/") || strings.Contains(filename, `\`) || strings.Contains(filename, "..") {
		return nil, fmt.Errorf("invalid release filename %q", filename)
	}

	path := fmt.Sprintf("/api/v1/releases/%s/%s/download/%s",
		url.PathEscape(component),
		url.PathEscape(version),
		url.PathEscape(filename),
	)
	req, err := c.newPublicRequest(ctx, http.MethodGet, path)
	if err != nil {
		return nil, err
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("release download failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		err = extractError(resp)
		_ = resp.Body.Close()
		return nil, err
	}
	if warn := strings.TrimSpace(resp.Header.Get("X-Toob-Warning")); warn != "" {
		c.recordWarning(warn)
	}
	return resp.Body, nil
}

// SearchResult is one element from GET /api/v1/search.
type SearchResult struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Category      string `json:"category"`
	Description   string `json:"description,omitempty"`
	Author        string `json:"author,omitempty"`
	DownloadCount int64  `json:"download_count,omitempty"`
	Downloads     int    `json:"downloads,omitempty"`
}

// SearchResponse is the shape of GET /api/v1/search.
type SearchResponse struct {
	Results []SearchResult `json:"results"`
	HasMore bool           `json:"has_more"`
	Count   int            `json:"count,omitempty"`
}

// Search queries the registry for packages matching a query string.
func (c *Client) Search(ctx context.Context, query string) (*SearchResponse, error) {
	var resp SearchResponse
	path := "/api/v1/search?q=" + url.QueryEscape(query)
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	for i := range resp.Results {
		if resp.Results[i].Downloads == 0 && resp.Results[i].DownloadCount > 0 {
			if resp.Results[i].DownloadCount > math.MaxInt32 {
				resp.Results[i].Downloads = math.MaxInt32
			} else {
				resp.Results[i].Downloads = int(resp.Results[i].DownloadCount)
			}
		}
	}
	resp.Count = len(resp.Results)
	return &resp, nil
}

func (c *Client) newPublicRequest(ctx context.Context, method, path string) (*http.Request, error) {
	if c.transportErr != nil {
		return nil, c.transportErr
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(c.BaseURL); err != nil {
		return nil, fmt.Errorf("invalid registry URL %q: %w", c.BaseURL, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Toob-CLI")
	return req, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	if c.transportErr != nil {
		return nil, c.transportErr
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(c.BaseURL); err != nil {
		return nil, fmt.Errorf("invalid registry URL %q: %w", c.BaseURL, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Toob-CLI")
	if bearer := c.bearer(ctx); bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req, nil
}

func (c *Client) newSessionRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	if c.transportErr != nil {
		return nil, c.transportErr
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(c.BaseURL); err != nil {
		return nil, fmt.Errorf("invalid registry URL %q: %w", c.BaseURL, err)
	}
	bearer, err := c.sessionBearer(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Toob-CLI")
	req.Header.Set("Authorization", "Bearer "+bearer)
	return req, nil
}

const maxRetryAfter = 60 * time.Second

func isSafeToRetry5xx(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return req.Header.Get("Idempotency-Key") != "" && (req.Body == nil || req.GetBody != nil)
	}
}

// doWithRetry executes a request again after transient 5xx or Retry-After 429/503 responses,
// rewinding req.Body via req.GetBody on retries and refusing to retry non-rewindable bodies.
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	var wait time.Duration
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if req.Body != nil {
				if req.GetBody == nil {
					return nil, lastErr
				}
				freshBody, gbErr := req.GetBody()
				if gbErr != nil {
					return nil, fmt.Errorf("rewinding request body for retry: %w", gbErr)
				}
				req.Body = freshBody
			}

			if wait == 0 {
				wait = time.Duration(math.Pow(2, float64(attempt-1))) * 500 * time.Millisecond
			}
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				timer.Reset(wait)
			}
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-timer.C:
			}
			wait = 0
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("api request failed: %w", err)
			if req.Body != nil && (req.GetBody == nil || !isSafeToRetry5xx(req)) {
				return nil, lastErr
			}
			continue
		}

		canRewind := req.Body == nil || req.GetBody != nil
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) &&
			attempt < maxRetries && canRewind &&
			(resp.StatusCode == http.StatusTooManyRequests || isSafeToRetry5xx(req)) {
			if retryAfter, ok := retryAfterOf(resp); ok {
				_ = resp.Body.Close()
				wait = retryAfter
				lastErr = fmt.Errorf("server asked to retry after %s (HTTP %d, attempt %d/%d)", retryAfter, resp.StatusCode, attempt+1, maxRetries+1)
				continue
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return resp, nil
		}
		if resp.StatusCode >= 500 && attempt < maxRetries && isSafeToRetry5xx(req) {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("server returned HTTP %d (attempt %d/%d)", resp.StatusCode, attempt+1, maxRetries+1)
			continue
		}

		return resp, nil
	}
	return nil, lastErr
}

func retryAfterOf(resp *http.Response) (time.Duration, bool) {
	seconds, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After")))
	if err != nil || seconds < 0 {
		return 0, false
	}
	wait := min(time.Duration(seconds)*time.Second, maxRetryAfter)
	return wait, true
}

func (c *Client) getJSON(ctx context.Context, path string, target any) error {
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.doWithRetry(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return extractError(resp)
	}

	raw, err := httputil.ReadBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}
