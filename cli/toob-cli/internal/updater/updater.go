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
	cooldownLimit  = 2 * time.Hour // Cooldown if HTTP 403 (Rate Limit) occurs
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

type CheckResult struct {
	Available   bool
	Version     string
	DownloadURL string
	ChecksumURL string
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
	
	// Gap 3: Missing directory
	_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)

	data, err := json.Marshal(cache)
	if err != nil {
		return
	}

	// Gap 2: Race Condition (Atomic Write)
	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err == nil {
		_ = os.Rename(tmpPath, cachePath)
	}
}

// CheckForUpdate returns CheckResult *instantly*. If cache is expired, it spawns a background fetch and returns nil.
// If forceNetwork is true (for manual `toob update`), it blocks and runs the fetch immediately.
func CheckForUpdate(currentVersion string, forceNetwork bool) (*CheckResult, error) {
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
			return &CheckResult{Available: true, Version: cache.LatestVer, DownloadURL: cache.DownloadURL}, nil
		}
		return &CheckResult{Available: false}, nil
	}

	if !forceNetwork {
		// Gap 6: Zero Blocking. Start background fetch and return immediately.
		go fetchUpdateFromGitHub(currentVersion)
		return nil, nil
	}

	// Manual force check
	return fetchUpdateFromGitHub(currentVersion)
}

func fetchUpdateFromGitHub(currentVersion string) (*CheckResult, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", repoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Gap 4: Rate Limiting
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			writeCache(CacheData{LastCheck: time.Now().Add(-checkInterval + cooldownLimit)}) // Retry in 2 hours
		}
		return nil, fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	// Gap 7: Robust Asset Matching
	osArchPart := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	var downloadURL, checksumURL string
	for _, a := range release.Assets {
		lowerName := strings.ToLower(a.Name)
		if strings.Contains(lowerName, osArchPart) && strings.HasSuffix(lowerName, ext) {
			downloadURL = a.BrowserDownloadURL
		}
		if strings.Contains(lowerName, osArchPart) && strings.HasSuffix(lowerName, ext+".sha256") {
			checksumURL = a.BrowserDownloadURL
		}
	}

	if downloadURL == "" {
		writeCache(CacheData{LastCheck: time.Now(), LatestVer: currentVersion}) // Prevents spam if no asset exists
		return &CheckResult{Available: false}, nil
	}

	latestVer := release.TagName
	if !strings.HasPrefix(latestVer, "v") {
		latestVer = "v" + latestVer
	}

	writeCache(CacheData{
		LastCheck:   time.Now(),
		LatestVer:   latestVer,
		DownloadURL: downloadURL,
	})

	if semver.Compare(latestVer, currentVersion) > 0 {
		return &CheckResult{Available: true, Version: latestVer, DownloadURL: downloadURL, ChecksumURL: checksumURL}, nil
	}

	return &CheckResult{Available: false}, nil
}
