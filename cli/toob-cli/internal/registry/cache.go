// Package registry manages the local shallow-clone of the toob-registry.
package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/toob-boot/toob/internal/paths"
)

// ChipInfo holds immutable metadata for a single chip.
type ChipInfo struct {
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Arch        string `json:"arch"`
	Toolchain   string `json:"toolchain"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// Index is the parsed content of registry.json.
type Index struct {
	Version           int                 `json:"version"`
	RegistryVersion   string              `json:"registry_version"`
	CoreCompatibility string              `json:"core_compatibility"`
	Chips             map[string]ChipInfo `json:"chips"`
}

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

// IsInitialized returns true if a git repo exists in the cache.
func (c *Cache) IsInitialized() bool {
	_, err := os.Stat(filepath.Join(c.dir, ".git"))
	return err == nil
}

// Sync clones or fast-forward pulls the registry.
func (c *Cache) Sync() error {
	c.index = nil
	if c.IsInitialized() {
		// Submodules shouldn't be pulled blindly, but caching repos should
		info, err := os.Stat(filepath.Join(c.dir, ".git"))
		if err == nil && !info.IsDir() {
			// It's a submodule (.git is a file). Do not git pull.
			return nil
		}
		return runGit(c.dir, "pull", "--ff-only")
	}
	if err := os.MkdirAll(filepath.Dir(c.dir), 0o755); err != nil {
		return err
	}
	return runGit(filepath.Dir(c.dir), "clone", c.remote, c.dir)
}

// Checkout switches the registry to a specific tag or commit.
func (c *Cache) Checkout(version string) error {
	info, err := os.Stat(filepath.Join(c.dir, ".git"))
	if err == nil && !info.IsDir() {
		// Submodule - skip checkout, assume the monorepo has it correct.
		return nil
	}
	c.index = nil
	// Fetch the specific tag or commit
	if err := runGit(c.dir, "fetch", "origin", version); err != nil {
		// Ignore error, might already have it locally
	}
	return runGit(c.dir, "checkout", version)
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
func (c *Cache) ArchSourcePath(arch string) string {
	return filepath.Join(c.dir, "arch", arch)
}

// VendorSourcePath returns the absolute path to a vendor's source in the cache.
func (c *Cache) VendorSourcePath(vendor string) string {
	return filepath.Join(c.dir, "vendor", vendor)
}

// ToolchainSourcePath returns the absolute path to a toolchain cmake file.
func (c *Cache) ToolchainSourcePath(filename string) string {
	return filepath.Join(c.dir, "toolchains", filename)
}

// HeadCommit returns the short SHA of the current HEAD.
func (c *Cache) HeadCommit() (string, error) {
	if !c.IsInitialized() {
		return "uninitialized", nil
	}
	out, err := exec.Command("git", "-C", c.dir, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s failed: %w", strings.Join(args, " "), err)
	}
	return nil
}
