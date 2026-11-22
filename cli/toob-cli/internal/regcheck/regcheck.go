// Package regcheck provides a non-blocking registry freshness check.
package regcheck

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/httputil"
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
	ChipWarnings   []string
}

type cacheData struct {
	RegistryURL    string    `json:"registry_url,omitempty"`
	LastCheck      time.Time `json:"last_check"`
	LatestRevision string    `json:"latest_revision"`
	LatestIndexSHA string    `json:"latest_index_sha,omitempty"`
	CheckedChips   []string  `json:"checked_chips,omitempty"`
	ChipWarnings   []string  `json:"chip_warnings,omitempty"`
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
	dir := filepath.Dir(path)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".toob-regcheck-*.tmp")
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
	if os.Rename(tmpName, path) == nil {
		cleanup = false
	}
}

func isNumericRevision(s string) bool {
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

func collectLockedChips(lf *lockfile.Lockfile) []string {
	seen := make(map[string]string)
	for i := range lf.Chips {
		name := lf.Chips[i].Name
		if name != "" {
			seen[strings.ToLower(name)] = name
		}
	}
	for k, t := range lf.Targets {
		name := k
		if t.Chip != "" && t.Chip != "none" && !strings.HasPrefix(t.Chip, "local:") {
			if idx := strings.LastIndex(t.Chip, "@"); idx > 0 {
				name = t.Chip[:idx]
			} else {
				name = t.Chip
			}
		}
		if name != "" {
			seen[strings.ToLower(name)] = name
		}
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

func isOutdatedAgainst(lockedRev, lockedIndexSHA, latestRev, latestSHA string) bool {
	if isNumericRevision(lockedRev) && isNumericRevision(latestRev) {
		if lockedRev != latestRev {
			return true
		}
		if len(lockedIndexSHA) == 64 && len(latestSHA) == 64 && !strings.EqualFold(lockedIndexSHA, latestSHA) {
			return true
		}
		return false
	}
	if len(lockedIndexSHA) == 64 && len(latestSHA) == 64 {
		return !strings.EqualFold(lockedIndexSHA, latestSHA)
	}
	return false
}

// CheckAsync performs a non-blocking registry freshness check against numeric registry
// revisions / SHA-256 digests, skipping dev, local-registry, and CI runs cleanly.
func CheckAsync() <-chan *Result {
	ch := make(chan *Result, 1)

	if paths.IsDevMode() ||
		strings.TrimSpace(os.Getenv("TOOB_REGISTRY_DIR")) != "" ||
		strings.TrimSpace(os.Getenv("CI")) != "" ||
		strings.TrimSpace(os.Getenv("TOOB_NO_UPDATE_CHECK")) != "" {
		close(ch)
		return ch
	}

	root, err := paths.FindProjectRootStrict("")
	if err != nil {
		close(ch)
		return ch
	}
	lf, err := lockfile.Load(paths.LockfilePath(root))
	if err != nil {
		close(ch)
		return ch
	}

	// Compare strictly numeric Revision / Commit or 64-hex IndexSHA256 — never semver Version ("v1.2.2") vs integer revision ("42").
	lockedRev := strings.TrimSpace(cmp.Or(lf.Registry.Revision, lf.Registry.Commit))
	lockedIndexSHA := strings.TrimSpace(lf.Registry.IndexSHA256)
	if !isNumericRevision(lockedRev) && len(lockedIndexSHA) != 64 {
		close(ch)
		return ch
	}

	client := apiclient.NewForBaseURL(lf.Registry.URL, 3*time.Second)
	canonicalOrigin, err := httputil.CanonicalOrigin(client.BaseURL)
	if err != nil {
		close(ch)
		return ch
	}

	chipNames := collectLockedChips(lf)
	displayCur := cmp.Or(lockedRev, lockedIndexSHA[:min(len(lockedIndexSHA), 12)])

	if cached := readCache(); cached != nil &&
		cached.RegistryURL == canonicalOrigin &&
		time.Since(cached.LastCheck) < checkInterval &&
		slices.Equal(cached.CheckedChips, chipNames) {
		if cached.LatestRevision != "" && isOutdatedAgainst(lockedRev, lockedIndexSHA, cached.LatestRevision, cached.LatestIndexSHA) {
			ch <- &Result{
				CurrentVersion: displayCur,
				LatestVersion:  cached.LatestRevision,
				Outdated:       true,
				ChipWarnings:   slices.Clone(cached.ChipWarnings),
			}
		}
		close(ch)
		return ch
	}

	go func() {
		defer close(ch)
		result := fetchRegistryStatus(client, canonicalOrigin, lockedRev, lockedIndexSHA, displayCur, chipNames)
		if result != nil {
			ch <- result
		}
	}()

	return ch
}

func fetchRegistryStatus(client *apiclient.Client, canonicalOrigin, lockedRev, lockedIndexSHA, displayCur string, chipNames []string) *Result {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	revResp, err := client.GetRevision(ctx)
	if err != nil || revResp == nil || revResp.Revision <= 0 {
		return nil
	}
	latestRev := strconv.FormatInt(revResp.Revision, 10)
	latestSHA := strings.TrimSpace(revResp.CommitSHA)

	outdated := isOutdatedAgainst(lockedRev, lockedIndexSHA, latestRev, latestSHA)
	var warnings []string
	if outdated && len(chipNames) > 0 {
		warnings = checkChipCompatibility(ctx, client, chipNames)
	}

	writeCache(cacheData{
		RegistryURL:    canonicalOrigin,
		LastCheck:      time.Now(),
		LatestRevision: latestRev,
		LatestIndexSHA: latestSHA,
		CheckedChips:   slices.Clone(chipNames),
		ChipWarnings:   slices.Clone(warnings),
	})

	if !outdated {
		return nil
	}

	return &Result{
		CurrentVersion: displayCur,
		LatestVersion:  latestRev,
		Outdated:       true,
		ChipWarnings:   warnings,
	}
}

func checkChipCompatibility(ctx context.Context, client *apiclient.Client, chipNames []string) []string {
	var warnings []string
	for _, name := range chipNames {
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := client.ResolveChip(reqCtx, name)
		cancel()
		if err != nil {
			var apiErr *apiclient.APIError
			if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusGone) {
				warnings = append(warnings, name)
			}
		}
	}
	return warnings
}
