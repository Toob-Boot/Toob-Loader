// Package registry manages the local shallow-clone of the toob-registry.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/paths"
)

// ChipInfo holds immutable metadata for a single chip.
type ChipInfo struct {
	Name             string `json:"name"`
	Vendor           string `json:"vendor"`
	Arch             string `json:"arch"`
	CompilerPrefix   string `json:"compiler_prefix"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	CliCompatibility string `json:"cli_compatibility"`
	Description      string `json:"description,omitempty"`
	Verified         bool   `json:"verified"`
}

type VendorInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type ArchInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type ToolchainInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// Index is the parsed content of registry.json.
type Index struct {
	FormatVersion    int                      `json:"format_version"`
	RegistryVersion  string                   `json:"registry_version"`
	CliCompatibility string                   `json:"cli_compatibility"`
	Chips            map[string]ChipInfo      `json:"chips"`
	Vendors          map[string]VendorInfo    `json:"vendors"`
	Archs            map[string]ArchInfo      `json:"archs"`
	Toolchains       map[string]ToolchainInfo `json:"toolchains"`
}

type MatrixDependencies struct {
	Toolchain string `json:"toolchain"`
	Vendor    string `json:"vendor"`
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
	dir    string
	remote string
	index  *Index
}

// NewCache creates a cache at the default or given directory.
func NewCache(remoteOverride string) *Cache {
	dir, _ := paths.RegistryDir()
	remote := paths.DefaultRegistryURL
	if remoteOverride != "" {
		remote = remoteOverride
	}
	return &Cache{dir: dir, remote: remote}
}

// Dir returns the cache directory path.
func (c *Cache) Dir() string { return c.dir }

// IsInitialized returns true if the registry has been downloaded.
func (c *Cache) IsInitialized() bool {
	_, err := os.Stat(filepath.Join(c.dir, "registry.json"))
	return err == nil
}

func (c *Cache) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(c.dir), 0o755); err != nil {
		return nil, err
	}
	lockDir := filepath.Join(filepath.Dir(c.dir), "registry.lock")
	for i := 0; i < 100; i++ { // wait up to 10 seconds
		if err := os.Mkdir(lockDir, 0o755); err == nil {
			return func() { os.Remove(lockDir) }, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for registry lock. Is another toob process running? (If not, delete %s)", lockDir)
}

// getHubURL returns the URL of the Toob Hub API
func getHubURL() string {
	if url := os.Getenv("TOOB_HUB_URL"); url != "" {
		return url
	}
	return "http://178.105.106.59:9000" // Default Hetzner CI Daemon
}

// Sync updates the registry to the latest version.
func (c *Cache) Sync() error {
	return c.Checkout("latest")
}

// Checkout switches the registry to a specific version via the Toob Hub API.
func (c *Cache) Checkout(version string) error {
	hubURL := fmt.Sprintf("%s/api/v1/resolve/registry?version=%s", getHubURL(), version)
	
	resp, err := http.Get(hubURL)
	if err != nil {
		fmt.Printf("\n[toob] \033[33mWARN: Failed to reach Toob Hub API (Offline?).\033[0m\n")
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

	// We extract to a versioned subdirectory
	targetDir := filepath.Join(c.dir, "versions", result.Version)
	
	// If it already exists, just update our active directory
	if _, err := os.Stat(filepath.Join(targetDir, "registry.json")); err == nil {
		c.dir = targetDir
		fmt.Printf("[toob] Registry Source: Local Cache (%s)\n", result.Version)
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

	fmt.Printf("[toob] Downloading Registry %s from GitHub...\n", result.Version)
	if err := downloadAndExtractZip(result.DownloadURL, targetDir); err != nil {
		return fmt.Errorf("failed to extract registry: %w", err)
	}

	c.dir = targetDir
	c.index = nil // invalidate cache
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

// FetchLiveMatrix downloads the compatibility matrix directly from GitHub's main branch,
// bypassing the local locked registry. If offline, it falls back to the local copy.
func (c *Cache) FetchLiveMatrix() (*Matrix, error) {
	matrix := make(Matrix)

	url := "https://raw.githubusercontent.com/Toob-Boot/Toob-Registry/main/compatibility_matrix.json"

	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Toob-CLI")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if json.Unmarshal(body, &matrix) == nil {
				return &matrix, nil
			}
		}
	}

	// Fallback to local locked file if HTTP fails
	localPath := filepath.Join(c.dir, "compatibility_matrix.json")
	data, err := os.ReadFile(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch live matrix and local fallback failed: %w", err)
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

// VendorSourcePath returns the absolute path to a vendor's source in the cache.
func (c *Cache) VendorSourcePath(vendor string) (string, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return "", err
	}
	info, ok := idx.Vendors[vendor]
	if !ok || info.Path == "" {
		return filepath.Join(c.dir, "vendor", vendor), nil // fallback for backwards compatibility
	}
	return filepath.Join(c.dir, info.Path), nil
}

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
