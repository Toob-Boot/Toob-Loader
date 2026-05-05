package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/paths"
	"golang.org/x/mod/semver"
)

const (
	repoURL        = "https://api.github.com/repos/Toob-Boot/Toob-CLI-Release/releases/latest"
	cacheFileName  = "update_check.json"
	checkInterval  = 24 * time.Hour
)

type ReleaseInfo struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type CacheData struct {
	LastCheck   time.Time `json:"last_check"`
	LatestVer   string    `json:"latest_ver"`
	DownloadURL string    `json:"download_url"`
}

// CheckResult contains the outcome of an update check.
type CheckResult struct {
	Available   bool
	Version     string
	DownloadURL string
}

func getCachePath() (string, error) {
	home, err := paths.ToobHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, cacheFileName), nil
}

// CheckForUpdate returns CheckResult if an update is available.
func CheckForUpdate(currentVersion string) (*CheckResult, error) {
	if !strings.HasPrefix(currentVersion, "v") {
		currentVersion = "v" + currentVersion
	}

	cachePath, err := getCachePath()
	if err != nil {
		return nil, err
	}

	var cache CacheData
	if data, err := os.ReadFile(cachePath); err == nil {
		if err := json.Unmarshal(data, &cache); err == nil {
			// If we checked recently, just return cached result
			if time.Since(cache.LastCheck) < checkInterval {
				if semver.Compare(cache.LatestVer, currentVersion) > 0 {
					return &CheckResult{Available: true, Version: cache.LatestVer, DownloadURL: cache.DownloadURL}, nil
				}
				return &CheckResult{Available: false}, nil
			}
		}
	}

	// Fetch from GitHub API
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", repoURL, nil)
	if err != nil {
		return nil, err
	}
	// Important for GitHub API to receive JSON
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	// Find the correct asset for this OS/Arch
	expectedName := fmt.Sprintf("toob-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		expectedName += ".exe"
	}

	var downloadURL string
	for _, a := range release.Assets {
		if strings.EqualFold(a.Name, expectedName) {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		// No compatible asset found for our OS, we can't update
		return &CheckResult{Available: false}, nil
	}

	latestVer := release.TagName
	if !strings.HasPrefix(latestVer, "v") {
		latestVer = "v" + latestVer
	}

	// Save to cache
	cache = CacheData{
		LastCheck:   time.Now(),
		LatestVer:   latestVer,
		DownloadURL: downloadURL,
	}
	if data, err := json.Marshal(cache); err == nil {
		_ = os.WriteFile(cachePath, data, 0o644)
	}

	if semver.Compare(latestVer, currentVersion) > 0 {
		return &CheckResult{Available: true, Version: latestVer, DownloadURL: downloadURL}, nil
	}

	return &CheckResult{Available: false}, nil
}
