// Package registry manages the local shallow-clone of the toob-registry.
//
// BOUNDARY TYPES: Struct types in this file are mirrored in internal/ports/ports.go.
// If you add, remove, or modify a struct field here, you MUST update ports.go
// and the assertions in internal/ports/assertions.go accordingly.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
)

type ChipSources struct {
	Startup  string   `json:"startup"`
	Platform string   `json:"platform"`
	Config   string   `json:"config"`
	Linker   string   `json:"linker"`
	Hardware string   `json:"hardware"`
	Drivers  []string `json:"drivers,omitempty"`
	Extra    []string `json:"extra,omitempty"`
}

// ChipInfo holds immutable metadata for a single chip.
type ChipInfo struct {
	Name             string       `json:"name"`
	Arch             string       `json:"arch"`
	CompilerPrefix   string       `json:"compiler_prefix"`
	Path             string       `json:"path"`
	Version          string       `json:"version"`
	CliCompatibility string       `json:"cli_compatibility"`
	Description      string       `json:"description,omitempty"`
	Verified         bool         `json:"verified"`
	Sources          *ChipSources `json:"sources,omitempty"`
	Includes         []string     `json:"includes,omitempty"`
}

// Removed VendorInfo

type ArchInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type ToolchainInfo struct {
	Path            string `json:"path"`
	Version         string `json:"version"`
	UpstreamVersion string `json:"upstream_version"`
}

type IntegrationInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// Index is the parsed content of registry.json.
type Index struct {
	FormatVersion    int                        `json:"format_version"`
	RegistryVersion  string                     `json:"registry_version"`
	CliCompatibility string                     `json:"cli_compatibility"`
	Chips            map[string]ChipInfo        `json:"chips"`
	Archs            map[string]ArchInfo        `json:"archs"`
	Toolchains       map[string]ToolchainInfo   `json:"toolchains"`
	Integrations     map[string]IntegrationInfo `json:"integrations"`
}

type MatrixDependencies struct {
	Toolchain string `json:"toolchain"`
	Arch      string `json:"arch"`
	Compiler  string `json:"compiler_container,omitempty"`
	CoreSDK   string `json:"core_sdk,omitempty"`
}

type MatrixVerifiedCli struct {
	Status     string `json:"status"`
	LastTested string `json:"last_tested"`
}

type MatrixVersion struct {
	EnvironmentHash     string                       `json:"environment_hash"`
	Dependencies        MatrixDependencies           `json:"dependencies"`
	VerifiedCliVersions map[string]MatrixVerifiedCli `json:"verified_cli_versions"`
}

type MatrixChip struct {
	Versions map[string]MatrixVersion `json:"versions"`
}

type Matrix map[string]MatrixChip

// Cache manages the local registry clone.
type Cache struct {
	rootDir string // Always ~/.toob/registry/ (never changes)
	dir     string // Active version directory (e.g. ~/.toob/registry/versions/main/)
	remote  string
	index   *Index
}

// NewCache creates a cache at the default or given directory.
// Automatically resolves the active version if one has been synced.
func NewCache(remoteOverride string) *Cache {
	rootDir, _ := paths.RegistryDir()
	remote := paths.DefaultRegistryURL
	if remoteOverride != "" {
		remote = remoteOverride
	}

	dir := rootDir

	// Resolve active version from persistent marker
	if activeVer, err := os.ReadFile(filepath.Join(rootDir, "active_version")); err == nil {
		ver := strings.TrimSpace(string(activeVer))
		if ver != "" {
			versionedDir := filepath.Join(rootDir, "versions", ver)
			if _, err := os.Stat(filepath.Join(versionedDir, "registry.json")); err == nil {
				dir = versionedDir
			}
		}
	}

	return &Cache{rootDir: rootDir, dir: dir, remote: remote}
}

// Dir returns the cache directory path.
func (c *Cache) Dir() string { return c.dir }

// IsInitialized returns true if the registry has been downloaded.
func (c *Cache) IsInitialized() bool {
	_, err := os.Stat(filepath.Join(c.dir, "registry.json"))
	return err == nil
}

func (c *Cache) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(c.rootDir), 0o755); err != nil {
		return nil, err
	}
	lockDir := filepath.Join(filepath.Dir(c.rootDir), "registry.lock")
	for i := 0; i < 100; i++ { // wait up to 10 seconds
		if err := os.Mkdir(lockDir, 0o755); err == nil {
			// Write PID file for stale-lock detection
			pidFile := filepath.Join(lockDir, "pid")
			_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)
			return func() { os.RemoveAll(lockDir) }, nil
		}

		// Check if the locking process is still alive
		if i%10 == 9 { // every ~1 second
			if c.tryCleanStaleLock(lockDir) {
				continue // Retry immediately after cleaning stale lock
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for registry lock. Is another toob process running? (If not, delete %s)", lockDir)
}

// tryCleanStaleLock reads the PID from the lock directory and checks if the process is alive.
// Returns true if a stale lock was cleaned up.
func (c *Cache) tryCleanStaleLock(lockDir string) bool {
	pidBytes, err := os.ReadFile(filepath.Join(lockDir, "pid"))
	if err != nil {
		return false
	}
	pid := 0
	if _, err := fmt.Sscanf(string(pidBytes), "%d", &pid); err != nil || pid == 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		// Process doesn't exist — stale lock
		ui.Muted("Cleaning stale registry lock (PID %d no longer running)", pid)
		os.RemoveAll(lockDir)
		return true
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to probe liveness.
	// On Windows, FindProcess fails for dead processes, so reaching here means alive.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		ui.Muted("Cleaning stale registry lock (PID %d no longer running)", pid)
		os.RemoveAll(lockDir)
		return true
	}
	return false
}

// getHubURL returns the URL of the Toob Hub API
func getHubURL() string {
	if url := os.Getenv("TOOB_HUB_URL"); url != "" {
		return url
	}
	return "https://ci.the-toob.com" // Default Hetzner CI Daemon (via Caddy)
}

// Sync updates the registry. If useDev is true, it syncs the bleeding-edge 'main' branch.
// Otherwise, it discovers the latest stable tag from version_index.json and syncs that.
func (c *Cache) Sync(useDev bool) error {
	if useDev {
		return c.Checkout("main")
	}

	latestVer, err := c.getLatestStableVersion()
	if err != nil {
		ui.Warn("Could not discover latest stable tag (%v). Falling back to 'main'.", err)
		return c.Checkout("main")
	}

	ui.Step("Discovered latest stable registry: %s", ui.Cyan(latestVer))
	return c.Checkout(latestVer)
}

// getLatestStableVersion fetches version_index.json from the Toob-Registry repository
// and returns the highest version listed under Official.Registry.
func (c *Cache) getLatestStableVersion() (string, error) {
	resp, err := http.Get("https://raw.githubusercontent.com/Toob-Boot/Toob-Registry/main/version_index.json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var index struct {
		Official struct {
			Registry []struct {
				Version string `json:"version"`
			} `json:"registry"`
		} `json:"official"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
		return "", err
	}

	if len(index.Official.Registry) == 0 {
		return "", fmt.Errorf("no official registry versions found in index")
	}

	return index.Official.Registry[0].Version, nil
}

// Checkout switches the registry to a specific version via the Toob Hub API.
func (c *Cache) Checkout(version string) error {
	hubURL := fmt.Sprintf("%s/api/v1/resolve/registry?version=%s", getHubURL(), version)

	resp, err := http.Get(hubURL)
	if err != nil {
		ui.Warn("Failed to reach Toob Hub API (Offline?).")
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Toob Hub API returned status %d for version %s", resp.StatusCode, version)
	}

	var result struct {
		Version     string `json:"version"`
		DownloadURL string `json:"download_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	targetDir := filepath.Join(c.rootDir, "versions", result.Version)

	// resolveCanonicalVersion reads registry_version from registry.json
	// and renames the directory to the canonical semver if the Hub returned
	// a branch name (e.g. "main") instead of a proper version.
	resolveCanonicalVersion := func(dir string) string {
		data, err := os.ReadFile(filepath.Join(dir, "registry.json"))
		if err != nil {
			return result.Version
		}
		var idx struct {
			RegistryVersion string `json:"registry_version"`
		}
		if json.Unmarshal(data, &idx) != nil || idx.RegistryVersion == "" {
			return result.Version
		}
		return idx.RegistryVersion
	}

	persistActive := func(ver string) {
		_ = os.WriteFile(filepath.Join(c.rootDir, "active_version"), []byte(ver), 0o644)
	}

	// If it already exists, resolve canonical version and activate
	if _, err := os.Stat(filepath.Join(targetDir, "registry.json")); err == nil {
		canonicalVer := resolveCanonicalVersion(targetDir)

		// Rename to canonical version directory if needed (e.g. "main" → "v1.0.10")
		if canonicalVer != result.Version {
			canonicalDir := filepath.Join(c.rootDir, "versions", canonicalVer)
			if _, err := os.Stat(canonicalDir); os.IsNotExist(err) {
				os.Rename(targetDir, canonicalDir)
				targetDir = canonicalDir
			}
		}

		c.dir = targetDir
		persistActive(canonicalVer)
		ui.Info("Registry Source: Local Cache (%s)", canonicalVer)
		return nil
	}

	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()

	// Double check after lock
	if _, err := os.Stat(filepath.Join(targetDir, "registry.json")); err == nil {
		c.dir = targetDir
		return nil
	}

	ui.Step("Downloading Registry %s from GitHub...", result.Version)
	if err := downloadAndExtractZip(result.DownloadURL, targetDir); err != nil {
		return fmt.Errorf("failed to extract registry: %w", err)
	}

	// Resolve canonical version and rename directory
	canonicalVer := resolveCanonicalVersion(targetDir)
	if canonicalVer != result.Version {
		canonicalDir := filepath.Join(c.rootDir, "versions", canonicalVer)
		if _, err := os.Stat(canonicalDir); os.IsNotExist(err) {
			os.Rename(targetDir, canonicalDir)
			targetDir = canonicalDir
		}
	}

	c.dir = targetDir
	c.index = nil
	persistActive(canonicalVer)

	return nil
}

// LoadIndex parses registry.json and returns a typed index.
func (c *Cache) LoadIndex() (*Index, error) {
	if c.index != nil {
		return c.index, nil
	}
	indexPath := filepath.Join(c.dir, "registry.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("registry not initialized. Run `toob registry sync` first")
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("failed to parse registry.json: %w", err)
	}
	c.index = &idx
	return &idx, nil
}

// ResolveChipLive fetches chip existence from the Hub API and returns the Registry Version it was found in.
func (c *Cache) ResolveChipLive(name string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/resolve/chip?name=%s", getHubURL(), name)

	client := http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Toob-CLI")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			var apiResp struct {
				FoundInRegistryVersion string `json:"found_in_registry_version"`
			}
			if json.Unmarshal(body, &apiResp) == nil {
				return apiResp.FoundInRegistryVersion, nil
			}
		} else if resp != nil && resp.StatusCode == 404 {
			return "", fmt.Errorf("chip not found on hub")
		}
	}
	return "", fmt.Errorf("failed to contact hub API")
}

// FetchLiveIntegrations fetches available integrations from the Hub API.
// It falls back to the local cached registry index if the API is offline.
func (c *Cache) FetchLiveIntegrations() ([]string, error) {
	url := fmt.Sprintf("%s/api/v1/resolve/integrations", getHubURL())

	client := http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Toob-CLI")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			var apiResp struct {
				Integrations []struct {
					Name    string `json:"name"`
				} `json:"integrations"`
			}
			if json.Unmarshal(body, &apiResp) == nil {
				var result []string
				for _, i := range apiResp.Integrations {
					result = append(result, i.Name)
				}
				return result, nil
			}
		}
	}

	// Fallback to local
	idx, err := c.LoadIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch live integrations and local fallback failed: %w", err)
	}

	var result []string
	for k := range idx.Integrations {
		result = append(result, k)
	}
	return result, nil
}

// FetchLiveMatrix downloads the compatibility matrix, prioritizing the Hub API
// (SQLite SSOT) over raw GitHub. Falls back to local copy if all network sources fail.
func (c *Cache) FetchLiveMatrix() (*Matrix, error) {
	matrix := make(Matrix)
	client := http.Client{Timeout: 5 * time.Second}

	// Tier 1: Hub API (SQLite SSOT, serves CLI-native shape)
	hubURL := fmt.Sprintf("%s/api/v1/resolve/matrix", getHubURL())
	if req, err := http.NewRequest("GET", hubURL, nil); err == nil {
		req.Header.Set("User-Agent", "Toob-CLI")
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				if json.Unmarshal(body, &matrix) == nil {
					return &matrix, nil
				}
			} else {
				ui.Muted("[registry] Hub API failed (status=%d), falling back to GitHub", resp.StatusCode)
			}
		}
	}

	// Tier 2: Raw GitHub (legacy compatibility_matrix.json)
	ghURL := "https://raw.githubusercontent.com/Toob-Boot/Toob-Registry/main/compatibility_matrix.json"
	if req, err := http.NewRequest("GET", ghURL, nil); err == nil {
		req.Header.Set("User-Agent", "Toob-CLI")
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				if json.Unmarshal(body, &matrix) == nil {
					return &matrix, nil
				}
			}
		}
	}

	// Tier 3: Local locked file
	localPath := filepath.Join(c.dir, "compatibility_matrix.json")
	data, err := os.ReadFile(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch live matrix (hub, github, local all failed): %w", err)
	}

	if err := json.Unmarshal(data, &matrix); err != nil {
		return nil, fmt.Errorf("failed to parse local matrix: %w", err)
	}

	return &matrix, nil
}

// GetChip looks up a single chip by name.
func (c *Cache) GetChip(name string) (*ChipInfo, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return nil, err
	}
	ci, ok := idx.Chips[name]
	if !ok {
		names := make([]string, 0, len(idx.Chips))
		for n := range idx.Chips {
			names = append(names, n)
		}
		return nil, fmt.Errorf("chip '%s' not found in registry. Available: %s",
			name, strings.Join(names, ", "))
	}
	return &ci, nil
}

// ChipSourcePath returns the absolute path to a chip's source in the cache.
func (c *Cache) ChipSourcePath(name string) (string, error) {
	ci, err := c.GetChip(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.dir, ci.Path), nil
}

// ArchSourcePath returns the absolute path to an architecture's source in the cache.
func (c *Cache) ArchSourcePath(arch string) (string, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return "", err
	}
	info, ok := idx.Archs[arch]
	if !ok || info.Path == "" {
		return filepath.Join(c.dir, "arch", arch), nil // fallback for backwards compatibility
	}
	return filepath.Join(c.dir, info.Path), nil
}

// Removed VendorSourcePath

// HeadCommit returns the version of the currently checked out registry.
func (c *Cache) HeadCommit() (string, error) {
	if !c.IsInitialized() {
		return "uninitialized", nil
	}
	return filepath.Base(c.dir), nil
}

// VerifyHead would normally verify git signatures. With ZIP downloads,
// this should verify the SHA256 sum of the zip file against the API.
func (c *Cache) VerifyHead() error {
	// TODO: Verify SHA256 from Toob Hub API
	return nil
}
