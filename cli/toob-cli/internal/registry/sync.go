package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/toob-boot/toob/internal/updater"
)

// Sync updates the registry. If useDev is true, it syncs the bleeding-edge 'main' index;
// otherwise it discovers the latest stable revision from the API and syncs that.
func (c *Cache) Sync(useDev, force bool) error {
	if useDev {
		ui.Step("Syncing bleeding-edge development registry ('main')...")
		return c.checkoutAPI("main", force)
	}

	client := c.apiClient(0)
	ui.Step("Fetching registry revision from API...")
	revResp, err := client.GetRevision(context.Background())
	if err != nil {
		if c.IsInitialized() {
			ui.Warn("Could not check for updates (%v). Using cached registry.", err)
			return nil
		}
		return fmt.Errorf("cannot discover registry version (offline?): %w", err)
	}

	latestVer := strconv.FormatInt(revResp.Revision, 10)
	ui.Step("Discovered latest stable registry revision: %s", ui.Cyan(latestVer))

	return c.checkoutAPI(latestVer, force)
}

func verifyIndexSignature(indexData []byte, sig string, requireSig bool) error {
	trimmed := strings.TrimSpace(sig)
	if trimmed == "" {
		if requireSig {
			return errors.New("CRITICAL SECURITY ALERT: registry index response is missing X-Registry-Signature header")
		}
		return nil
	}
	if err := updater.VerifySignature(indexData, trimmed); err != nil {
		return fmt.Errorf("CRITICAL SECURITY ALERT: X-Registry-Signature verification failed for registry.json: %w", err)
	}
	return nil
}

func verifyFetchedIndexVersion(ctx context.Context, client *apiclient.Client, requested string, idx *Index) error {
	if requested == "" || requested == "latest" || requested == "main" {
		return nil
	}
	if idx.RegistryVersion == requested || strings.TrimPrefix(idx.RegistryVersion, "v") == strings.TrimPrefix(requested, "v") {
		return nil
	}
	if isAllDigits(requested) {
		if revResp, err := client.GetRevision(ctx); err == nil && revResp != nil && strconv.FormatInt(revResp.Revision, 10) == requested {
			return nil
		}
	}
	return fmt.Errorf("requested registry version %q does not match remote index version %q", requested, idx.RegistryVersion)
}

func writeFileAtomic(targetDir, filename string, data []byte) error {
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(targetDir, "."+filename+".*.tmp")
	if err != nil {
		return err
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
		return err
	}
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(targetDir, filename)); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// checkoutAPI downloads and activates a specific registry revision using the API.
func (c *Cache) checkoutAPI(version string, force bool) error {
	if err := validateVersionToken("registry version", version); err != nil {
		return err
	}
	targetDir, err := archiveutil.SafeJoin(filepath.Join(c.rootDir, "versions"), version)
	if err != nil {
		return err
	}

	previousVer, _ := c.HeadCommit()

	if !force {
		if _, statErr := os.Stat(filepath.Join(targetDir, "registry.json")); statErr == nil {
			c.mu.Lock()
			c.dir = targetDir
			c.index = nil
			c.mu.Unlock()
			c.persistActive(version)
			if previousVer == version {
				ui.Success("Registry is up to date (rev %s)", version)
			} else {
				ui.Info("Registry Source: Local Cache (rev %s)", version)
			}
			return nil
		}
	}

	lockCtx, cancel := context.WithTimeout(context.Background(), cacheLockTimeout)
	defer cancel()

	unlock, err := c.lock(lockCtx)
	if err != nil {
		return fmt.Errorf("acquiring registry lock: %w", err)
	}
	defer func() { _ = unlock() }()

	if force {
		_ = os.RemoveAll(targetDir)
	} else if _, statErr := os.Stat(filepath.Join(targetDir, "registry.json")); statErr == nil {
		c.mu.Lock()
		c.dir = targetDir
		c.index = nil
		c.mu.Unlock()
		c.persistActive(version)
		return nil
	}

	if err := c.downloadIndexToDir(context.Background(), version, targetDir); err != nil {
		return err
	}

	c.mu.Lock()
	c.dir = targetDir
	c.index = nil
	c.mu.Unlock()
	c.persistActive(version)
	return nil
}

func (c *Cache) downloadIndexToDir(ctx context.Context, version, targetDir string) error {
	ui.Step("Downloading Registry Index from API...")
	client := c.apiClient(downloadTimeout)
	indexData, sigHeader, err := client.GetIndexWithMeta(ctx, version)
	if err != nil {
		return fmt.Errorf("failed to download registry index: %w", err)
	}
	if err := verifyIndexSignature(indexData, sigHeader, !paths.IsDevMode()); err != nil {
		return err
	}
	var parsed Index
	if err := json.Unmarshal(indexData, &parsed); err != nil {
		return fmt.Errorf("downloaded registry index is invalid JSON: %w", err)
	}
	if err := verifyFetchedIndexVersion(ctx, client, version, &parsed); err != nil {
		return err
	}

	if err := writeFileAtomic(targetDir, "registry.json", indexData); err != nil {
		return err
	}

	ui.Step("Downloading Compatibility Matrix...")
	if matrixData, mErr := client.GetMatrix(ctx, ""); mErr == nil {
		if raw, mJSONErr := json.Marshal(matrixData); mJSONErr == nil {
			_ = writeFileAtomic(targetDir, "compatibility_matrix.json", raw)
		}
	}
	return nil
}

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
	if validateVersionToken("active_version", ver) != nil {
		return
	}
	_ = writeFileAtomic(c.rootDir, "active_version", []byte(ver))
}

// SwitchVersion activates and persists a specific registry version.
func (c *Cache) SwitchVersion(version string) error {
	return c.checkoutAPI(version, false)
}

// SelectVersion sets the active directory for this Cache instance without modifying active_version.
func (c *Cache) SelectVersion(version string, downloadIfMissing bool) error {
	if err := validateVersionToken("registry version", version); err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(c.rootDir, "registry.json")); err == nil {
		c.mu.Lock()
		c.dir = c.rootDir
		c.index = nil
		c.mu.Unlock()
		return nil
	}

	if strings.TrimSpace(os.Getenv("TOOB_REGISTRY_DIR")) != "" {
		c.mu.Lock()
		c.dir = c.rootDir
		c.index = nil
		c.mu.Unlock()
		return nil
	}

	targetDir, err := archiveutil.SafeJoin(filepath.Join(c.rootDir, "versions"), version)
	if err != nil {
		return err
	}

	if _, statErr := os.Stat(filepath.Join(targetDir, "registry.json")); statErr == nil {
		c.mu.Lock()
		c.dir = targetDir
		c.index = nil
		c.mu.Unlock()
		return nil
	}

	if !downloadIfMissing {
		return fmt.Errorf("registry version %s is not cached", version)
	}

	lockCtx, cancel := context.WithTimeout(context.Background(), cacheLockTimeout)
	defer cancel()

	unlock, err := c.lock(lockCtx)
	if err != nil {
		return fmt.Errorf("acquiring registry lock: %w", err)
	}
	defer func() { _ = unlock() }()

	if _, statErr := os.Stat(filepath.Join(targetDir, "registry.json")); statErr == nil {
		c.mu.Lock()
		c.dir = targetDir
		c.index = nil
		c.mu.Unlock()
		return nil
	}

	if dlErr := c.downloadIndexToDir(context.Background(), version, targetDir); dlErr != nil {
		return dlErr
	}

	c.mu.Lock()
	c.dir = targetDir
	c.index = nil
	c.mu.Unlock()
	return nil
}

// HeadCommit returns the version of the currently checked out registry.
func (c *Cache) HeadCommit() (string, error) {
	if !c.IsInitialized() {
		return "uninitialized", nil
	}
	dir := c.Dir()
	ver := resolveCanonicalVersion(dir, "")
	if ver != "" {
		return ver, nil
	}
	return filepath.Base(dir), nil
}

func (c *Cache) activeRevisionToken() string {
	dir := c.Dir()
	versionsDir := filepath.Clean(filepath.Join(c.rootDir, "versions"))
	if filepath.Clean(filepath.Dir(dir)) == versionsDir {
		return filepath.Base(dir)
	}
	return ""
}

// VerifyHead verifies the Ed25519 signature and digest of the currently active registry revision.
func (c *Cache) VerifyHead() error {
	return c.VerifyHeadForRevision(c.activeRevisionToken())
}

// VerifyHeadForRevision validates the Ed25519 signature of the remote revision AND verifies
// that the local on-disk registry.json matches the signed upstream payload for revision.
func (c *Cache) VerifyHeadForRevision(revision string) error {
	if _, err := updater.GetUpdatePublicKey(); err != nil {
		return fmt.Errorf("registry trust-root key unavailable: %w", err)
	}

	localIndexPath := filepath.Join(c.Dir(), "registry.json")
	localData, err := os.ReadFile(localIndexPath)
	if err != nil {
		return fmt.Errorf("cannot read local registry.json for integrity check: %w", err)
	}
	localSum := sha256.Sum256(localData)

	ctx := context.Background()
	client := c.apiClient(downloadTimeout)

	revResp, err := client.GetRevision(ctx)
	if err != nil {
		return fmt.Errorf("failed to get registry revision for verification: %w", err)
	}
	if strings.TrimSpace(revResp.Signature) == "" {
		return errors.New("registry server did not provide a revision signature")
	}
	if strings.TrimSpace(revResp.CommitSHA) == "" {
		return errors.New("registry server returned empty commit_sha")
	}

	commitDigest, decodeErr := hex.DecodeString(strings.TrimSpace(revResp.CommitSHA))
	if decodeErr != nil || len(commitDigest) != sha256.Size {
		// Server hashes non-hex CommitSHA messages (such as format bumps) with SHA-256 before signing.
		hashed := sha256.Sum256([]byte(revResp.CommitSHA))
		commitDigest = hashed[:]
	}

	if err = updater.VerifyHashSignature(commitDigest, revResp.Signature); err != nil {
		return fmt.Errorf("CRITICAL SECURITY ALERT: registry revision signature verification failed: %w", err)
	}

	remoteData, indexSig, err := client.GetIndexWithMeta(ctx, strings.TrimSpace(revision))
	if err != nil {
		return fmt.Errorf("failed to fetch remote registry index for integrity verification: %w", err)
	}
	if sigErr := verifyIndexSignature(remoteData, indexSig, true); sigErr != nil {
		return sigErr
	}

	remoteSum := sha256.Sum256(remoteData)
	if !bytes.Equal(localSum[:], remoteSum[:]) {
		return fmt.Errorf("CRITICAL SECURITY ALERT: local registry.json SHA-256 (%x) does not match verified upstream index (%x)",
			localSum, remoteSum)
	}

	ui.Success("Registry signature and on-disk index digest verified (rev %d)", revResp.Revision)
	return nil
}
