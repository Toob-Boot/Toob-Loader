// Package registry manages the local shallow-clone of the toob-registry.
//
// BOUNDARY TYPES: Struct types in this file are mirrored in internal/ports/ports.go.
// If you add, remove, or modify a struct field here, you MUST update ports.go
// and the assertions in internal/ports/assertions.go accordingly.
package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/toob-boot/toob/internal/apiclient"
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
	Crypto           *ChipCrypto  `json:"crypto,omitempty"`
}

// ChipCrypto defines the default crypto package assignments for a chip.
type ChipCrypto struct {
	Backend string `json:"backend,omitempty"`
	Hash    string `json:"hash,omitempty"`
	Pqc     string `json:"pqc,omitempty"`
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

// CryptoInfo holds metadata for a crypto package from registry.json.
type CryptoInfo struct {
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	Version         string   `json:"version"`
	Description     string   `json:"description,omitempty"`
	Category        []string `json:"category"`
	License         string   `json:"license,omitempty"`
	MinCoreSdk      string   `json:"min_core_sdk,omitempty"`
	Wrapper         *string  `json:"wrapper,omitempty"`
	UpstreamSources []string `json:"upstream_sources,omitempty"`
	Cflags          []string `json:"cflags,omitempty"`
	Includes        []string `json:"includes,omitempty"`
	ChipBinding     []string `json:"chip_binding,omitempty"`
}

// DriverInfo holds metadata for a driver from registry.json.
type DriverInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
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
	Drivers          map[string]DriverInfo      `json:"drivers"`
	Crypto           map[string]CryptoInfo      `json:"crypto"`
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

// Sync updates the registry. If useDev is true, it syncs the bleeding-edge 'main' branch.
// Otherwise, it discovers the latest stable revision from the API and syncs that.
// If force is true, the local cache is bypassed and the version is re-downloaded.
func (c *Cache) Sync(useDev bool, force bool) error {
	client := apiclient.New()
	
	ui.Step("Fetching registry revision from API...")
	revResp, err := client.GetRevision(context.Background())
	if err != nil {
		if c.IsInitialized() {
			ui.Warn("Could not check for updates (%v). Using cached registry.", err)
			return nil
		}
		return fmt.Errorf("cannot discover registry version (offline?): %w", err)
	}

	latestVer := fmt.Sprintf("%d", revResp.Revision)
	ui.Step("Discovered latest stable registry revision: %s", ui.Cyan(latestVer))

	return c.checkoutAPI(latestVer, force)
}

// checkoutAPI downloads and activates a specific registry revision using the API.
func (c *Cache) checkoutAPI(version string, force bool) error {
	targetDir := filepath.Join(c.rootDir, "versions", version)

	if force {
		os.RemoveAll(targetDir)
	}

	previousVer, _ := c.HeadCommit()

	// Cache hit
	if _, err := os.Stat(filepath.Join(targetDir, "registry.json")); err == nil && !force {
		c.dir = targetDir
		c.persistActive(version)
		if previousVer == version {
			ui.Success("Registry is up to date (rev %s)", version)
		} else {
			ui.Info("Registry Source: Local Cache (rev %s)", version)
		}
		return nil
	}

	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := os.Stat(filepath.Join(targetDir, "registry.json")); err == nil {
		c.dir = targetDir
		c.persistActive(version)
		return nil
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}

	ui.Step("Downloading Registry Index from API...")
	client := apiclient.New()
	indexData, err := client.GetIndex(context.Background())
	if err != nil {
		return fmt.Errorf("failed to download registry index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(targetDir, "registry.json"), indexData, 0o644); err != nil {
		return err
	}

	// Fetch matrix to cache it
	ui.Step("Downloading Compatibility Matrix...")
	matrixData, err := client.GetMatrix(context.Background(), "")
	if err == nil {
		os.WriteFile(filepath.Join(targetDir, "compatibility_matrix.json"), matrixData, 0o644)
	}

	c.dir = targetDir
	c.index = nil
	c.persistActive(version)

	return nil
}

// resolveCanonicalVersion reads registry_version from the downloaded registry.json.
func resolveCanonicalVersion(dir, fallback string) string {
	data, err := os.ReadFile(filepath.Join(dir, "registry.json"))
	if err != nil {
		return fallback
	}
	var idx struct {
		RegistryVersion string `json:"registry_version"`
	}
	if json.Unmarshal(data, &idx) != nil || idx.RegistryVersion == "" {
		return fallback
	}
	return idx.RegistryVersion
}

func (c *Cache) persistActive(ver string) {
	_ = os.WriteFile(filepath.Join(c.rootDir, "active_version"), []byte(ver), 0o644)
}

// SwitchVersion activates a specific registry version (used by chip add/spawn).
func (c *Cache) SwitchVersion(version string) error {
	return c.checkoutAPI(version, false)
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

// ResolveChipLive queries the registry API for a chip and returns its version.
func (c *Cache) ResolveChipLive(name string) (string, error) {
	client := apiclient.New()
	client.HTTPClient.Timeout = 2 * time.Second

	resp, err := client.ResolveChip(context.Background(), name)
	if err != nil {
		return "", fmt.Errorf("failed to resolve chip via API: %w", err)
	}
	return resp.Version, nil
}

// FetchLiveIntegrations fetches available integrations from the API.
// Falls back to the local cached registry index if the API is offline.
func (c *Cache) FetchLiveIntegrations() ([]string, error) {
	client := apiclient.New()
	client.HTTPClient.Timeout = 3 * time.Second

	items, err := client.ListIntegrations(context.Background())
	if err == nil {
		var result []string
		for _, i := range items {
			result = append(result, i.Name)
		}
		return result, nil
	}

	// Fallback to local
	idx, idxErr := c.LoadIndex()
	if idxErr != nil {
		return nil, fmt.Errorf("api and local fallback both failed: %w", idxErr)
	}

	var result []string
	for k := range idx.Integrations {
		result = append(result, k)
	}
	return result, nil
}

// FetchLiveMatrix downloads the compatibility matrix from the API.
// Falls back to raw GitHub and then local copy if the API is offline.
func (c *Cache) FetchLiveMatrix() (*Matrix, error) {
	matrix := make(Matrix)
	client := apiclient.New()
	client.HTTPClient.Timeout = 5 * time.Second

	// Tier 1: Registry API (DB-backed, authoritative)
	data, err := client.GetMatrix(context.Background(), "")
	if err == nil {
		if json.Unmarshal(data, &matrix) == nil {
			return &matrix, nil
		}
	}

	// Tier 2: Local cached file
	localPath := filepath.Join(c.dir, "compatibility_matrix.json")
	localData, err := os.ReadFile(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch matrix (api and local both failed): %w", err)
	}

	if err := json.Unmarshal(localData, &matrix); err != nil {
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

// fetchPackage downloads the tarball for a package and extracts it if it doesn't exist.
func (c *Cache) fetchPackage(name, version, path string) error {
	destPath := filepath.Join(c.dir, path)
	if _, err := os.Stat(destPath); err == nil {
		return nil // already fetched
	}

	ui.Step("Downloading package %s@%s...", name, version)
	
	// Ensure parent directory exists before extraction
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	
	url := fmt.Sprintf("%s/api/v1/package/%s/%s/download", c.remote, name, version)
	if err := downloadAndExtractTarball(url, destPath); err != nil {
		return fmt.Errorf("failed to fetch package %s: %w", name, err)
	}

	return nil
}

// ChipSourcePath returns the absolute path to a chip's source in the cache.
func (c *Cache) ChipSourcePath(name string) (string, error) {
	ci, err := c.GetChip(name)
	if err != nil {
		return "", err
	}
	if err := c.fetchPackage(ci.Name, ci.Version, ci.Path); err != nil {
		return "", err
	}
	return filepath.Join(c.dir, ci.Path), nil
}

// GetCrypto looks up a single crypto package by name.
func (c *Cache) GetCrypto(name string) (*CryptoInfo, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return nil, err
	}
	ci, ok := idx.Crypto[name]
	if !ok {
		names := make([]string, 0, len(idx.Crypto))
		for n := range idx.Crypto {
			names = append(names, n)
		}
		return nil, fmt.Errorf("crypto package '%s' not found in registry. Available: %s",
			name, strings.Join(names, ", "))
	}
	return &ci, nil
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
	if err := c.fetchPackage(info.Name, info.Version, info.Path); err != nil {
		return "", err
	}
	return filepath.Join(c.dir, info.Path), nil
}

// Removed VendorSourcePath

// HeadCommit returns the version of the currently checked out registry.
func (c *Cache) HeadCommit() (string, error) {
	if !c.IsInitialized() {
		return "uninitialized", nil
	}
	ver := resolveCanonicalVersion(c.dir, "")
	if ver != "" {
		return ver, nil
	}
	return filepath.Base(c.dir), nil
}

// VerifyHead validates the cryptographic signature of the current registry revision.
func (c *Cache) VerifyHead() error {
	client := apiclient.New()
	
	revResp, err := client.GetRevision(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get registry revision for verification: %w", err)
	}

	if revResp.Signature == "" {
		return fmt.Errorf("registry server did not provide a signature")
	}

	// Read public key from environment (for dev/testing) or use hardcoded official key
	pubKeyHex := os.Getenv("TOOB_REGISTRY_PUBKEY")
	if pubKeyHex == "" {
		// Example official public key (placeholder)
		pubKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"
		ui.Warn("Using placeholder Ed25519 public key. Set TOOB_REGISTRY_PUBKEY for real verification.")
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid registry public key format")
	}

	sigBytes, err := hex.DecodeString(revResp.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid registry signature format")
	}

	hashBytes, err := hex.DecodeString(revResp.CommitSHA)
	if err != nil {
		hash := sha256.Sum256([]byte(revResp.CommitSHA))
		hashBytes = hash[:]
	}

	valid := ed25519.Verify(pubKeyBytes, hashBytes, sigBytes)
	if !valid {
		return fmt.Errorf("CRITICAL SECURITY ALERT: Registry signature verification failed! The registry data may have been tampered with")
	}

	ui.Success("Registry signature verified successfully (rev %d)", revResp.Revision)
	return nil
}
