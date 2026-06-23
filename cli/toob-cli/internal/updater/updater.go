package updater

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"golang.org/x/mod/semver"
)

const (
	cacheFileName = "update_check.json"
	checkInterval = 24 * time.Hour
)

var ErrUnsupportedArch = errors.New("unsupported architecture for this release")

type CacheData struct {
	LastCheck   time.Time `json:"last_check"`
	LatestVer   string    `json:"latest_ver"`
	DownloadURL string    `json:"download_url"`
	SigURL      string    `json:"sig_url"`
}

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

	_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)

	data, err := json.Marshal(cache)
	if err != nil {
		return
	}

	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err == nil {
		_ = os.Rename(tmpPath, cachePath)
	}
}

// CheckForUpdate returns CheckResult *instantly*. If cache is expired, it spawns a background fetch and returns nil.
// If forceNetwork is true (for manual `toob update`), it blocks and runs the fetch immediately.
func CheckForUpdate(currentVersion string, forceNetwork bool, insecure bool) (*CheckResult, error) {
	if !strings.HasPrefix(currentVersion, "v") {
		currentVersion = "v" + currentVersion
	}

	cachePath, err := getCachePath()
	if err != nil {
		return nil, err
	}

	var cache CacheData
	cacheValid := false
	if data, err := os.ReadFile(cachePath); err == nil {
		if err := json.Unmarshal(data, &cache); err == nil {
			if time.Since(cache.LastCheck) < checkInterval {
				cacheValid = true
			}
		}
	}

	if cacheValid && !forceNetwork {
		if semver.Compare(cache.LatestVer, currentVersion) > 0 {
			return &CheckResult{Available: true, Version: cache.LatestVer, DownloadURL: cache.DownloadURL, SigURL: cache.SigURL}, nil
		}
		return &CheckResult{Available: false}, nil
	}

	if !forceNetwork {
		go func() {
			_, _ = fetchUpdateFromRegistry(currentVersion, insecure)
		}()
		return nil, nil
	}

	// Manual force check
	return fetchUpdateFromRegistry(currentVersion, insecure)
}

// FetchReleaseByTag ignores cache and forcefully fetches a specific version for rollback/targeted update.
func FetchReleaseByTag(tag string, insecure bool) (*CheckResult, error) {
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}

	// Validate GOOS/GOARCH is supported
	supported := false
	for _, t := range []struct{ goos, goarch string }{
		{"windows", "amd64"},
		{"linux", "amd64"},
		{"darwin", "arm64"},
	} {
		if runtime.GOOS == t.goos && runtime.GOARCH == t.goarch {
			supported = true
			break
		}
	}
	if !supported {
		return nil, ErrUnsupportedArch
	}

	client := apiclient.New()
	var archiveName string
	if runtime.GOOS == "windows" {
		archiveName = fmt.Sprintf("toob-windows-%s.zip", runtime.GOARCH)
	} else {
		archiveName = fmt.Sprintf("toob-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	}

	downloadURL := fmt.Sprintf("%s/api/v1/releases/cli/%s/download/%s", client.BaseURL, strings.TrimPrefix(tag, "v"), archiveName)
	sigURL := downloadURL + ".sig"

	return &CheckResult{
		Available:   true,
		Version:     tag,
		DownloadURL: downloadURL,
		SigURL:      sigURL,
	}, nil
}

func fetchUpdateFromRegistry(currentVersion string, insecure bool) (*CheckResult, error) {
	// Validate GOOS/GOARCH is supported
	supported := false
	for _, t := range []struct{ goos, goarch string }{
		{"windows", "amd64"},
		{"linux", "amd64"},
		{"darwin", "arm64"},
	} {
		if runtime.GOOS == t.goos && runtime.GOARCH == t.goarch {
			supported = true
			break
		}
	}
	if !supported {
		return nil, ErrUnsupportedArch
	}

	client := apiclient.New()
	if insecure {
		transport := apiclient.BuildTransport()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.HTTPClient.Transport = transport
	}

	indexData, err := client.GetIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registry index: %w", err)
	}

	var idx registry.Index
	if err := json.Unmarshal(indexData, &idx); err != nil {
		return nil, fmt.Errorf("failed to parse registry index: %w", err)
	}

	if idx.Ecosystem == nil || len(idx.Ecosystem.CLI) == 0 {
		return &CheckResult{Available: false}, nil
	}

	latestVer := idx.Ecosystem.CLI[0]
	if !strings.HasPrefix(latestVer, "v") {
		latestVer = "v" + latestVer
	}

	var archiveName string
	if runtime.GOOS == "windows" {
		archiveName = fmt.Sprintf("toob-windows-%s.zip", runtime.GOARCH)
	} else {
		archiveName = fmt.Sprintf("toob-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	}

	downloadURL := fmt.Sprintf("%s/api/v1/releases/cli/%s/download/%s", client.BaseURL, strings.TrimPrefix(latestVer, "v"), archiveName)
	sigURL := downloadURL + ".sig"

	isNewer := semver.Compare(latestVer, currentVersion) > 0

	result := &CheckResult{
		Available:   isNewer,
		Version:     latestVer,
		DownloadURL: downloadURL,
		SigURL:      sigURL,
	}

	writeCache(CacheData{
		LastCheck:   time.Now(),
		LatestVer:   latestVer,
		DownloadURL: downloadURL,
		SigURL:      sigURL,
	})

	return result, nil
}
