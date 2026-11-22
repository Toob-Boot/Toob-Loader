package registry

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/filelock"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/paths"
)

const (
	downloadTimeout  = 120 * time.Second
	cacheLockTimeout = 60 * time.Second
	emptyFileSHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var versionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func validateVersionToken(label, ver string) error {
	if ver == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.Contains(ver, "..") || !versionTokenPattern.MatchString(ver) {
		return fmt.Errorf("invalid %s %q", label, ver)
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validateHexSHA256(label, digest string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(digest))
	if clean == "" {
		return "", nil
	}
	decoded, err := hex.DecodeString(clean)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("invalid sha256 digest %q for %s", digest, label)
	}
	if clean == emptyFileSHA256 {
		return "", fmt.Errorf("refusing placeholder empty-file sha256 digest for %s", label)
	}
	return clean, nil
}

// ParseFileURL parses a file:// URL into a native host path (handling Windows file:///C:/... cleanly).
func ParseFileURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid file URL %q: %w", raw, err)
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("expected file:// scheme in %q", raw)
	}
	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		return "", fmt.Errorf("UNC/remote host %q in file URL %q is not supported", u.Host, raw)
	}
	p := u.Path
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' &&
		((p[1] >= 'A' && p[1] <= 'Z') || (p[1] >= 'a' && p[1] <= 'z')) && p[2] == ':' {
		p = p[1:]
	}
	if p == "" {
		return "", fmt.Errorf("empty path in file URL %q", raw)
	}
	return filepath.Clean(filepath.FromSlash(p)), nil
}

// Cache manages the local package registry cache and remote synchronization.
type Cache struct {
	rootDir string
	dir     string
	remote  string

	mu    sync.Mutex
	index *Index
}

// NewCache creates a Cache at the configured registry directory and optional remote override.
func NewCache(remoteOverride string) *Cache {
	rootDir, err := paths.RegistryDir()
	if err != nil || rootDir == "" {
		rootDir = filepath.Join(os.TempDir(), "toob-registry-fallback")
	}

	remote := ""
	trimmedOverride := strings.TrimSpace(remoteOverride)
	if trimmedOverride != "" {
		clean := trimmedOverride
		if strings.HasPrefix(trimmedOverride, "file://") {
			if parsed, parseErr := ParseFileURL(trimmedOverride); parseErr == nil {
				clean = parsed
			}
		}
		if info, statErr := os.Stat(clean); statErr == nil && info.IsDir() {
			if _, idxErr := os.Stat(filepath.Join(clean, "registry.json")); idxErr == nil {
				return &Cache{rootDir: clean, dir: clean, remote: trimmedOverride}
			}
		}
		if strings.HasPrefix(trimmedOverride, "https://") || strings.HasPrefix(trimmedOverride, "http://") {
			remote = strings.TrimRight(trimmedOverride, "/")
		}
	}

	dir := rootDir
	if _, statErr := os.Stat(filepath.Join(rootDir, "registry.json")); statErr == nil {
		return &Cache{rootDir: rootDir, dir: rootDir, remote: remote}
	}

	if activeVer, readErr := os.ReadFile(filepath.Join(rootDir, "active_version")); readErr == nil {
		ver := strings.TrimSpace(string(activeVer))
		if validateVersionToken("active_version", ver) == nil {
			versionsRoot := filepath.Join(rootDir, "versions")
			if versionedDir, joinErr := archiveutil.SafeJoin(versionsRoot, ver); joinErr == nil {
				if verRoot, rootErr := os.OpenRoot(versionsRoot); rootErr == nil {
					_, statErr := verRoot.Stat(filepath.Join(ver, "registry.json"))
					_ = verRoot.Close()
					if statErr == nil {
						dir = versionedDir
					}
				}
			}
		}
	}

	return &Cache{rootDir: rootDir, dir: dir, remote: remote}
}

// OpenForProject opens and initializes a Cache honoring projectRoot's device.toml
// registry override, toob.lock pinned revision, and devMode / TOOB_REGISTRY_DIR overrides.
func OpenForProject(projectRoot string, devMode bool) (*Cache, error) {
	if devMode || paths.IsDevMode() || strings.TrimSpace(os.Getenv("TOOB_REGISTRY_DIR")) != "" {
		c := NewCache("")
		if c.IsLocalOverride() || c.IsInitialized() {
			return c, nil
		}
		if err := c.Sync(true, false); err != nil {
			return nil, err
		}
		return c, nil
	}

	var remoteOverride string
	var pinnedRev string

	if strings.TrimSpace(projectRoot) != "" {
		lf, err := lockfile.Load(paths.LockfilePath(projectRoot))
		if err != nil {
			return nil, err
		}
		remoteOverride = lf.Registry.URL
		pinnedRev = cmp.Or(lf.Registry.Revision, lf.Registry.Commit, lf.Registry.Version)

		if remoteOverride == "" {
			var dt struct {
				Build struct {
					Registry string `toml:"registry"`
				} `toml:"build"`
			}
			if raw, readErr := os.ReadFile(filepath.Join(projectRoot, "device.toml")); readErr == nil {
				if _, decErr := toml.Decode(string(raw), &dt); decErr == nil && strings.TrimSpace(dt.Build.Registry) != "" {
					remoteOverride = strings.TrimSpace(dt.Build.Registry)
				}
			}
		}
	}

	c := NewCache(remoteOverride)
	if c.IsLocalOverride() {
		return c, nil
	}
	if pinnedRev != "" {
		if err := c.SelectVersion(pinnedRev, true); err != nil {
			return nil, err
		}
		return c, nil
	}
	if !c.IsInitialized() {
		if err := c.Sync(false, false); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Dir returns the active cache directory path.
func (c *Cache) Dir() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dir
}

// Remote returns any explicit remote URL configured on this Cache.
func (c *Cache) Remote() string {
	return c.remote
}

// IsLocalOverride reports whether this Cache points at a direct local registry directory
// rather than the managed ~/.toob/registry/versions/<ver> cache.
func (c *Cache) IsLocalOverride() bool {
	if strings.TrimSpace(os.Getenv("TOOB_REGISTRY_DIR")) != "" {
		return true
	}
	_, err := os.Stat(filepath.Join(c.rootDir, "registry.json"))
	return err == nil
}

// IsInitialized returns true if registry.json exists in the active cache directory.
func (c *Cache) IsInitialized() bool {
	_, err := os.Stat(filepath.Join(c.Dir(), "registry.json"))
	return err == nil
}

func (c *Cache) apiClient(timeout time.Duration) *apiclient.Client {
	return apiclient.NewForBaseURL(c.remote, timeout)
}

func (c *Cache) lock(ctx context.Context) (func() error, error) {
	lockPath := filepath.Join(filepath.Dir(c.rootDir), "registry.lock")
	return filelock.Lock(ctx, lockPath)
}

// LoadIndex parses and memoizes registry.json from the active cache directory.
func (c *Cache) LoadIndex() (*Index, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.index != nil {
		return c.index, nil
	}
	indexPath := filepath.Join(c.dir, "registry.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, errors.New("registry not initialized. Run `toob registry sync` first")
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("failed to parse registry.json: %w", err)
	}
	c.index = &idx
	return &idx, nil
}
