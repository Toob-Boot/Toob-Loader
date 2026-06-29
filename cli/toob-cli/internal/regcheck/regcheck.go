// Package regcheck provides a non-blocking registry freshness check.
//
// Called once in PersistentPreRun (async) and consumed in PersistentPostRun
// to show a banner when the locked registry version is outdated.
package regcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/paths"
)

const (
	cacheFileName = "registry_check.json"
	checkInterval = 6 * time.Hour
)

// Result holds the outcome of a registry freshness check.
type Result struct {
	CurrentVersion string
	LatestVersion  string
	Outdated       bool
	ChipWarnings   []string // Chips in lockfile that are missing in the latest registry
}

type cacheData struct {
	LastCheck     time.Time `json:"last_check"`
	LatestVersion string    `json:"latest_version"`
}

func getCachePath() string {
	home, err := paths.ToobHome()
	if err != nil {
		return ""
	}
	return filepath.Join(home, cacheFileName)
}

func readCache() *cacheData {
	path := getCachePath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c cacheData
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	return &c
}

func writeCache(c cacheData) {
	path := getCachePath()
	if path == "" {
		return
	}
	data, _ := json.Marshal(c)
	tmpPath := path + ".tmp"
	if os.WriteFile(tmpPath, data, 0o644) == nil {
		os.Rename(tmpPath, path)
	}
}

// CheckAsync performs a non-blocking registry freshness check.
// Returns a channel that will receive the result when ready.
// If there's no lockfile or the cache is still fresh, returns nil.
func CheckAsync() <-chan *Result {
	ch := make(chan *Result, 1)

	// Find lockfile from CWD upward
	root, err := paths.FindProjectRoot("")
	if err != nil {
		close(ch)
		return ch
	}
	lf, err := lockfile.Load(paths.LockfilePath(root))
	if err != nil || lf.Registry.Version == "" {
		close(ch)
		return ch
	}

	lockedVersion := lf.Registry.Version
	chipNames := make([]string, len(lf.Chips))
	for i, c := range lf.Chips {
		chipNames[i] = c.Name
	}

	// Check cache first
	if cached := readCache(); cached != nil {
		if time.Since(cached.LastCheck) < checkInterval {
			if cached.LatestVersion != "" && normalizeVersion(cached.LatestVersion) != normalizeVersion(lockedVersion) {
				ch <- &Result{
					CurrentVersion: lockedVersion,
					LatestVersion:  cached.LatestVersion,
					Outdated:       true,
				}
			} else {
				close(ch)
			}
			return ch
		}
	}

	go func() {
		defer close(ch)
		result := fetchRegistryStatus(lockedVersion, chipNames)
		if result != nil {
			ch <- result
		}
	}()

	return ch
}

func fetchRegistryStatus(lockedVersion string, chipNames []string) *Result {
	client := apiclient.New()
	client.HTTPClient.Timeout = 3 * time.Second

	revResp, err := client.GetRevision(context.Background())
	if err != nil || revResp == nil {
		return nil
	}
	latestVersion := fmt.Sprintf("%d", revResp.Revision)



	writeCache(cacheData{
		LastCheck:     time.Now(),
		LatestVersion: latestVersion,
	})

	if normalizeVersion(latestVersion) == normalizeVersion(lockedVersion) {
		return nil
	}

	result := &Result{
		CurrentVersion: lockedVersion,
		LatestVersion:  latestVersion,
		Outdated:       true,
	}

	result.ChipWarnings = checkChipCompatibility(client, chipNames)

	return result
}

// checkChipCompatibility queries the API for each locked chip
// and returns warnings for any that don't exist in the latest registry.
func checkChipCompatibility(client *apiclient.Client, chipNames []string) []string {
	var warnings []string
	for _, name := range chipNames {
		_, err := client.ResolveChip(context.Background(), name)
		if err != nil {
			warnings = append(warnings, name)
		}
	}
	return warnings
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

