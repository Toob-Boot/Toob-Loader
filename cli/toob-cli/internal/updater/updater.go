package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/paths"
)

const (
	cacheFileName = "update_check.json"
	checkInterval = 24 * time.Hour
)

var (
	ErrUnsupportedArch = errors.New("unsupported architecture for this release")
	ErrInsecureTLS     = errors.New("--insecure TLS bypass is disabled; configure custom CA roots via TOOB_CA_CERT")
)

// CacheData stores the last CLI update check bound to a specific canonical RegistryURL.
type CacheData struct {
	RegistryURL string    `json:"registry_url,omitempty"`
	LastCheck   time.Time `json:"last_check"`
	LatestVer   string    `json:"latest_ver"`
	DownloadURL string    `json:"download_url"`
	SigURL      string    `json:"sig_url"`
}

// CheckResult reports whether a newer CLI version is available.
type CheckResult struct {
	Available   bool
	Version     string
	DownloadURL string
	SigURL      string
}

func getCachePath() (string, error) {
	home, err := paths.ToobHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, cacheFileName), nil
}

func writeCache(cache CacheData) {
	cachePath, err := getCachePath()
	if err != nil {
		return
	}
	dir := filepath.Dir(cachePath)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".toob-update-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return
	}
	if runtime.GOOS != "windows" {
		_ = tmp.Chmod(0o600)
	}
	if tmp.Close() != nil {
		return
	}
	if os.Rename(tmpName, cachePath) == nil {
		cleanup = false
	}
}

func isSupportedPlatform() bool {
	if runtime.GOARCH == "" {
		return false
	}
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return true
	default:
		return false
	}
}

func normalizeSemVerTag(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsAny(trimmed, `/\?#`) || strings.Contains(trimmed, "..") {
		return "", false
	}
	if !strings.HasPrefix(trimmed, "v") {
		trimmed = "v" + trimmed
	}
	if !semver.IsValid(trimmed) {
		return "", false
	}
	return trimmed, true
}

func buildReleaseURLs(baseURL, canonicalVer string) (downloadURL, sigURL string, err error) {
	if _, err := httputil.CanonicalOrigin(baseURL); err != nil {
		return "", "", fmt.Errorf("invalid registry URL %q: %w", baseURL, err)
	}
	var archiveName string
	if runtime.GOOS == "windows" {
		archiveName = fmt.Sprintf("toob-windows-%s.zip", runtime.GOARCH)
	} else {
		archiveName = fmt.Sprintf("toob-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	}
	cleanVer := strings.TrimPrefix(canonicalVer, "v")
	cleanBase := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	downloadURL = fmt.Sprintf("%s/api/v1/releases/cli/%s/download/%s",
		cleanBase,
		url.PathEscape(cleanVer),
		url.PathEscape(archiveName),
	)
	sigURL = downloadURL + ".sig"
	return downloadURL, sigURL, nil
}

func cacheMatchesOrigin(c CacheData, canonicalOrigin string) bool {
	if c.RegistryURL == "" || c.RegistryURL != canonicalOrigin {
		return false
	}
	if _, ok := normalizeSemVerTag(c.LatestVer); !ok {
		return false
	}
	dlOrigin, err := httputil.CanonicalOrigin(c.DownloadURL)
	if err != nil || dlOrigin != canonicalOrigin {
		return false
	}
	sigOrigin, err := httputil.CanonicalOrigin(c.SigURL)
	return err == nil && sigOrigin == canonicalOrigin
}

// CheckForUpdate returns CheckResult from cache or spawns a background refresh.
// If forceNetwork is true (for manual 'toob update'), it fetches and verifies immediately.
func CheckForUpdate(currentVersion string, forceNetwork, insecure bool) (*CheckResult, error) {
	if insecure {
		return nil, ErrInsecureTLS
	}

	trimmedCur := strings.TrimSpace(currentVersion)
	if trimmedCur == "" || strings.EqualFold(trimmedCur, "dev") || strings.EqualFold(trimmedCur, "vdev") {
		return &CheckResult{Available: false}, nil
	}
	normCur, ok := normalizeSemVerTag(trimmedCur)
	if !ok {
		return &CheckResult{Available: false}, nil
	}

	if !forceNetwork && (paths.IsDevMode() || strings.TrimSpace(os.Getenv("CI")) != "" || strings.TrimSpace(os.Getenv("TOOB_NO_UPDATE_CHECK")) != "") {
		return &CheckResult{Available: false}, nil
	}

	client := apiclient.New()
	canonicalOrigin, err := httputil.CanonicalOrigin(client.BaseURL)
	if err != nil {
		if !forceNetwork {
			return &CheckResult{Available: false}, nil
		}
		return nil, fmt.Errorf("invalid registry URL %q: %w", client.BaseURL, err)
	}

	cachePath, err := getCachePath()
	if err != nil {
		return nil, err
	}

	var cache CacheData
	cacheValid := false
	if data, readErr := os.ReadFile(cachePath); readErr == nil {
		if json.Unmarshal(data, &cache) == nil &&
			time.Since(cache.LastCheck) < checkInterval &&
			cacheMatchesOrigin(cache, canonicalOrigin) {
			cacheValid = true
		}
	}

	if cacheValid && !forceNetwork {
		if semver.Compare(cache.LatestVer, normCur) > 0 {
			return &CheckResult{
				Available:   true,
				Version:     cache.LatestVer,
				DownloadURL: cache.DownloadURL,
				SigURL:      cache.SigURL,
			}, nil
		}
		return &CheckResult{Available: false}, nil
	}

	if !forceNetwork {
		go func() {
			_, _ = fetchUpdateFromRegistry(client, canonicalOrigin, normCur)
		}()
		return nil, nil
	}

	return fetchUpdateFromRegistry(client, canonicalOrigin, normCur)
}

// FetchReleaseByTag ignores cache and constructs verified URLs for a targeted update/rollback.
func FetchReleaseByTag(tag string, insecure bool) (*CheckResult, error) {
	if insecure {
		return nil, ErrInsecureTLS
	}
	normTag, ok := normalizeSemVerTag(tag)
	if !ok {
		return nil, fmt.Errorf("invalid release version tag %q (expected valid SemVer, e.g. v0.7.0)", tag)
	}
	if !isSupportedPlatform() {
		return nil, ErrUnsupportedArch
	}

	client := apiclient.New()
	downloadURL, sigURL, err := buildReleaseURLs(client.BaseURL, normTag)
	if err != nil {
		return nil, err
	}

	return &CheckResult{
		Available:   true,
		Version:     normTag,
		DownloadURL: downloadURL,
		SigURL:      sigURL,
	}, nil
}

func fetchUpdateFromRegistry(client *apiclient.Client, canonicalOrigin, currentVersion string) (*CheckResult, error) {
	if !isSupportedPlatform() {
		return nil, ErrUnsupportedArch
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	indexData, sigHeader, err := client.GetIndexWithMeta(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registry index: %w", err)
	}
	if sigHeader == "" && !paths.IsDevMode() {
		return nil, errors.New("refusing unsigned registry index during update check (missing X-Registry-Signature)")
	}
	if sigHeader != "" {
		if sigErr := VerifySignature(indexData, sigHeader); sigErr != nil {
			return nil, fmt.Errorf("registry index signature verification failed: %w", sigErr)
		}
	}

	var idx struct {
		Ecosystem *struct {
			CLI []string `json:"cli"`
		} `json:"ecosystem"`
	}
	if err = json.Unmarshal(indexData, &idx); err != nil {
		return nil, fmt.Errorf("failed to parse registry index: %w", err)
	}

	if idx.Ecosystem == nil || len(idx.Ecosystem.CLI) == 0 {
		return &CheckResult{Available: false}, nil
	}

	latestVer, ok := normalizeSemVerTag(idx.Ecosystem.CLI[0])
	if !ok {
		return nil, fmt.Errorf("registry index advertised invalid CLI version %q", idx.Ecosystem.CLI[0])
	}

	downloadURL, sigURL, err := buildReleaseURLs(client.BaseURL, latestVer)
	if err != nil {
		return nil, err
	}

	isNewer := semver.Compare(latestVer, currentVersion) > 0
	result := &CheckResult{
		Available:   isNewer,
		Version:     latestVer,
		DownloadURL: downloadURL,
		SigURL:      sigURL,
	}

	writeCache(CacheData{
		RegistryURL: canonicalOrigin,
		LastCheck:   time.Now(),
		LatestVer:   latestVer,
		DownloadURL: downloadURL,
		SigURL:      sigURL,
	})

	return result, nil
}
