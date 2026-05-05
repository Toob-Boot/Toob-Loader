package updater

import (
	"crypto/tls"
	"encoding/json"
	"errors"
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
	repoTagURL     = "https://api.github.com/repos/Toob-Boot/Toob-CLI-Release/releases/tags/%s"
	cacheFileName  = "update_check.json"
	checkInterval  = 24 * time.Hour
	cooldownLimit  = 2 * time.Hour // Cooldown if HTTP 403 (Rate Limit) occurs
)

var ErrUnsupportedArch = errors.New("unsupported architecture for this release")

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
			return &CheckResult{Available: true, Version: cache.LatestVer, DownloadURL: cache.DownloadURL}, nil
		}
		return &CheckResult{Available: false}, nil
	}

	if !forceNetwork {
		go fetchUpdateFromGitHub(currentVersion, repoURL, insecure)
		return nil, nil
	}

	// Manual force check
	return fetchUpdateFromGitHub(currentVersion, repoURL, insecure)
}

// FetchReleaseByTag ignores cache and forcefully fetches a specific version for rollback/targeted update.
func FetchReleaseByTag(tag string, insecure bool) (*CheckResult, error) {
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	url := fmt.Sprintf(repoTagURL, tag)
	// We pass empty string for currentVersion so semver comparison always returns true
	return fetchUpdateFromGitHub("", url, insecure)
}

func fetchUpdateFromGitHub(currentVersion, url string, insecure bool) (*CheckResult, error) {
	// Gap 6: Proxy/MITM support via ProxyFromEnvironment and InsecureSkipVerify
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest("GET", url, nil)
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
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			writeCache(CacheData{LastCheck: time.Now().Add(-checkInterval + cooldownLimit)}) // Retry in 2 hours
		}
		if resp.StatusCode == http.StatusNotFound && url != repoURL {
			return nil, fmt.Errorf("release not found (HTTP 404)")
		}
		return nil, fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

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
		if len(release.Assets) > 0 {
			// Gap 5: Fallback warning if release exists but arch is missing
			return nil, ErrUnsupportedArch
		}
		writeCache(CacheData{LastCheck: time.Now(), LatestVer: currentVersion}) 
		return &CheckResult{Available: false}, nil
	}

	latestVer := release.TagName
	if !strings.HasPrefix(latestVer, "v") {
		latestVer = "v" + latestVer
	}

	// Only update cache if we are fetching the latest release
	if url == repoURL {
		writeCache(CacheData{
			LastCheck:   time.Now(),
			LatestVer:   latestVer,
			DownloadURL: downloadURL,
		})
	}

	// If currentVersion is empty (FetchReleaseByTag), always return Available: true
	if currentVersion == "" || semver.Compare(latestVer, currentVersion) > 0 {
		return &CheckResult{Available: true, Version: latestVer, DownloadURL: downloadURL, ChecksumURL: checksumURL}, nil
	}

	return &CheckResult{Available: false}, nil
}
