package registry

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
)

const pkgMetaFileName = ".toob_pkg_meta.json"

type packageMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256,omitempty"`
}

func cachedPackageMatchesMeta(destPath, name, version, cleanExpectedSHA string) bool {
	raw, err := os.ReadFile(filepath.Join(destPath, pkgMetaFileName))
	if err != nil {
		return false
	}
	var meta packageMeta
	if json.Unmarshal(raw, &meta) != nil {
		return false
	}
	if meta.Name != name || meta.Version != version {
		return false
	}
	if cleanExpectedSHA != "" && !strings.EqualFold(meta.SHA256, cleanExpectedSHA) {
		return false
	}
	return true
}

// fetchPackage validates containment, verifies any existing cached package metadata
// (.toob_pkg_meta.json), downloads the package tarball when missing or stale, checks
// its SHA-256 digest before unpacking, and commits the directory atomically.
func (c *Cache) fetchPackage(name, version, relPath, expectedSHA string) error {
	activeDir := c.Dir()
	destPath, err := archiveutil.SafeJoin(activeDir, relPath)
	if err != nil {
		return fmt.Errorf("unsafe registry path %q for package %s: %w", relPath, name, err)
	}

	if c.IsLocalOverride() {
		if st, statErr := os.Stat(destPath); statErr == nil && st.IsDir() {
			return nil
		}
		return fmt.Errorf("package '%s@%s' not found locally at %s (offline/local registry)", name, version, destPath)
	}

	cleanExpectedSHA, err := validateHexSHA256(name+"@"+version, expectedSHA)
	if err != nil {
		return err
	}

	if st, statErr := os.Stat(destPath); statErr == nil && st.IsDir() {
		if cachedPackageMatchesMeta(destPath, name, version, cleanExpectedSHA) {
			return nil
		}
	}

	if cleanExpectedSHA == "" && !paths.IsDevMode() {
		return fmt.Errorf("refusing unverified remote download for package %s@%s: registry index has no sha256 digest", name, version)
	}

	lockCtx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()

	unlock, err := c.lock(lockCtx)
	if err != nil {
		return fmt.Errorf("acquiring registry lock for %s: %w", name, err)
	}
	defer func() { _ = unlock() }()

	if st, statErr := os.Stat(destPath); statErr == nil && st.IsDir() {
		if cachedPackageMatchesMeta(destPath, name, version, cleanExpectedSHA) {
			return nil
		}
	}

	ui.Step("Downloading package %s@%s...", name, version)

	if mkdirErr := os.MkdirAll(filepath.Dir(destPath), 0o750); mkdirErr != nil {
		return mkdirErr
	}
	nonce := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	tempDestPath := destPath + ".tmp-" + nonce
	tempTarPath := destPath + ".tar-" + nonce + ".tgz"
	defer func() {
		_ = os.Remove(tempTarPath)
	}()

	client := c.apiClient(downloadTimeout)
	body, err := client.DownloadPackage(lockCtx, name, version)
	if err != nil {
		return fmt.Errorf("failed to fetch package %s: %w", name, err)
	}

	tarFile, err := os.OpenFile(tempTarPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = body.Close()
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tarFile, hasher), io.LimitReader(body, archiveutil.PackageSizeLimit+1))
	bodyCloseErr := body.Close()
	fileCloseErr := tarFile.Close()
	if copyErr != nil {
		return fmt.Errorf("failed downloading package %s: %w", name, copyErr)
	}
	if bodyCloseErr != nil {
		return fmt.Errorf("failed closing response stream for %s: %w", name, bodyCloseErr)
	}
	if fileCloseErr != nil {
		return fmt.Errorf("failed flushing downloaded archive for %s: %w", name, fileCloseErr)
	}
	if written > archiveutil.PackageSizeLimit {
		return fmt.Errorf("package %s@%s archive exceeds %d byte limit", name, version, archiveutil.PackageSizeLimit)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if cleanExpectedSHA != "" && actualSHA != cleanExpectedSHA {
		return fmt.Errorf("SHA256 mismatch for package %s@%s: expected %s, got %s", name, version, cleanExpectedSHA, actualSHA)
	}

	archiveReader, err := os.Open(tempTarPath)
	if err != nil {
		return err
	}
	extractErr := ExtractTarball(archiveReader, tempDestPath)
	_ = archiveReader.Close()
	if extractErr != nil {
		_ = os.RemoveAll(tempDestPath)
		return fmt.Errorf("failed to extract package %s: %w", name, extractErr)
	}

	metaBytes, err := json.Marshal(packageMeta{
		Name:    name,
		Version: version,
		SHA256:  actualSHA,
	})
	if err != nil {
		_ = os.RemoveAll(tempDestPath)
		return err
	}
	if err := os.WriteFile(filepath.Join(tempDestPath, pkgMetaFileName), metaBytes, 0o600); err != nil {
		_ = os.RemoveAll(tempDestPath)
		return fmt.Errorf("writing package metadata for %s: %w", name, err)
	}

	_ = os.RemoveAll(destPath)
	if err := os.Rename(tempDestPath, destPath); err != nil {
		_ = os.RemoveAll(tempDestPath)
		if st, statErr := os.Stat(destPath); statErr == nil && st.IsDir() && cachedPackageMatchesMeta(destPath, name, version, cleanExpectedSHA) {
			return nil
		}
		return fmt.Errorf("failed to finalize atomic package extraction: %w", err)
	}

	return nil
}

// GetChip looks up a single chip by name.
func (c *Cache) GetChip(name string) (*ChipInfo, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return nil, err
	}
	ci, ok := idx.Chips[name]
	if !ok {
		names := slices.Sorted(maps.Keys(idx.Chips))
		return nil, fmt.Errorf("chip '%s' not found in registry. Available: %s",
			name, strings.Join(names, ", "))
	}
	return &ci, nil
}

// GetCrypto looks up a single crypto package by name.
func (c *Cache) GetCrypto(name string) (*CryptoInfo, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return nil, err
	}
	ci, ok := idx.Crypto[name]
	if !ok {
		names := slices.Sorted(maps.Keys(idx.Crypto))
		return nil, fmt.Errorf("crypto package '%s' not found in registry. Available: %s",
			name, strings.Join(names, ", "))
	}
	return &ci, nil
}

// GetPort looks up a single port package by name.
func (c *Cache) GetPort(name string) (*PortInfo, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return nil, err
	}
	pi, ok := idx.Ports[name]
	if !ok {
		names := slices.Sorted(maps.Keys(idx.Ports))
		return nil, fmt.Errorf("port package '%s' not found in registry. Available: %s",
			name, strings.Join(names, ", "))
	}
	return &pi, nil
}

func stripDriverCategoryPrefix(p string) string {
	if after, ok := strings.CutPrefix(p, "drivers/"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(p, "driver/"); ok {
		return after
	}
	return p
}

// GetDriver looks up a driver package in registry.json by exact package name,
// scoped name (@scope/pkg), relative driver path ("driver/..." or "drivers/..."),
// or leaf directory name.
func (c *Cache) GetDriver(ref string) (*DriverInfo, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return nil, err
	}
	slashRef := strings.Trim(strings.TrimPrefix(filepath.ToSlash(ref), "./"), "/")
	if info, ok := idx.Drivers[slashRef]; ok {
		return &info, nil
	}
	strippedRef := stripDriverCategoryPrefix(slashRef)
	if info, ok := idx.Drivers[strippedRef]; ok {
		return &info, nil
	}

	sortedKeys := slices.Sorted(maps.Keys(idx.Drivers))
	for _, k := range sortedKeys {
		info := idx.Drivers[k]
		normPath := strings.Trim(strings.TrimPrefix(filepath.ToSlash(info.Path), "./"), "/")
		if normPath == slashRef || stripDriverCategoryPrefix(normPath) == strippedRef {
			cp := info
			return &cp, nil
		}
	}
	if !strings.HasPrefix(strippedRef, "@") {
		base := filepath.Base(strippedRef)
		if info, ok := idx.Drivers[base]; ok {
			return &info, nil
		}
	}
	return nil, fmt.Errorf("driver '%s' not found in registry index. Available: %s",
		ref, strings.Join(sortedKeys, ", "))
}

// ChipSourcePath returns the absolute path to a chip's source in the cache.
func (c *Cache) ChipSourcePath(name string) (string, error) {
	ci, err := c.GetChip(name)
	if err != nil {
		return "", err
	}
	destPath, err := archiveutil.SafeJoin(c.Dir(), ci.Path)
	if err != nil {
		return "", fmt.Errorf("chip '%s' registry path: %w", name, err)
	}
	if err := c.fetchPackage(cmp.Or(ci.Name, name), ci.Version, ci.Path, cmp.Or(ci.SHA256, ci.TarballSHA)); err != nil {
		return "", err
	}
	return destPath, nil
}

// ArchSourcePath returns the absolute path to an architecture's source in the cache.
func (c *Cache) ArchSourcePath(arch string) (string, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return "", err
	}
	info, ok := idx.Archs[arch]
	if !ok || info.Path == "" {
		return "", fmt.Errorf("architecture '%s' not found in registry index", arch)
	}
	destPath, err := archiveutil.SafeJoin(c.Dir(), info.Path)
	if err != nil {
		return "", fmt.Errorf("architecture '%s' registry path: %w", arch, err)
	}
	if err := c.fetchPackage(cmp.Or(info.Name, arch), info.Version, info.Path, cmp.Or(info.SHA256, info.TarballSHA)); err != nil {
		return "", err
	}
	return destPath, nil
}

// DriverSourcePath resolves a driver via the active registry index (GetDriver) first
// so revoked or stale cached directories are never returned without index verification.
func (c *Cache) DriverSourcePath(driverDir string) (string, error) {
	activeDir := c.Dir()
	if c.IsInitialized() {
		info, err := c.GetDriver(driverDir)
		if err == nil {
			destPath, joinErr := archiveutil.SafeJoin(activeDir, info.Path)
			if joinErr != nil {
				return "", fmt.Errorf("driver '%s' registry path: %w", driverDir, joinErr)
			}
			if fetchErr := c.fetchPackage(cmp.Or(info.Name, driverDir), info.Version, info.Path, cmp.Or(info.SHA256, info.TarballSHA)); fetchErr != nil {
				return "", fetchErr
			}
			return destPath, nil
		}
		if !c.IsLocalOverride() {
			return "", err
		}
	}

	if c.IsLocalOverride() {
		for _, cand := range []string{
			driverDir,
			filepath.ToSlash(filepath.Join("drivers", filepath.FromSlash(driverDir))),
			filepath.ToSlash(filepath.Join("driver", filepath.FromSlash(driverDir))),
		} {
			if destPath, joinErr := archiveutil.SafeJoin(activeDir, cand); joinErr == nil {
				if st, statErr := os.Stat(destPath); statErr == nil && st.IsDir() {
					return destPath, nil
				}
			}
		}
	}

	info, err := c.GetDriver(driverDir)
	if err != nil {
		return "", err
	}
	destPath, err := archiveutil.SafeJoin(activeDir, info.Path)
	if err != nil {
		return "", fmt.Errorf("driver '%s' registry path: %w", driverDir, err)
	}
	if err := c.fetchPackage(cmp.Or(info.Name, driverDir), info.Version, info.Path, cmp.Or(info.SHA256, info.TarballSHA)); err != nil {
		return "", err
	}
	return destPath, nil
}

// CryptoSourcePath returns the absolute path to a crypto package in the cache.
func (c *Cache) CryptoSourcePath(name string) (string, error) {
	ci, err := c.GetCrypto(name)
	if err != nil {
		return "", err
	}
	destPath, err := archiveutil.SafeJoin(c.Dir(), ci.Path)
	if err != nil {
		return "", fmt.Errorf("crypto '%s' registry path: %w", name, err)
	}
	if err := c.fetchPackage(cmp.Or(ci.Name, name), ci.Version, ci.Path, cmp.Or(ci.SHA256, ci.TarballSHA)); err != nil {
		return "", err
	}
	return destPath, nil
}

// ToolchainConfigPath returns the absolute path to a toolchain's CMake config directory.
func (c *Cache) ToolchainConfigPath(toolchainName string) (string, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return "", err
	}
	info, ok := idx.Toolchains[toolchainName]
	if !ok || info.Path == "" {
		return "", fmt.Errorf("toolchain '%s' not found in registry index", toolchainName)
	}
	destPath, err := archiveutil.SafeJoin(c.Dir(), info.Path)
	if err != nil {
		return "", fmt.Errorf("toolchain '%s' registry path: %w", toolchainName, err)
	}
	if err := c.fetchPackage(toolchainName, info.Version, info.Path, info.TarballSHA); err != nil {
		return "", err
	}
	return destPath, nil
}

func (c *Cache) matchSoCEntry(rawRef string) (socKey string, info SoCInfo, subRel string, err error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return "", SoCInfo{}, "", err
	}
	if len(idx.SoCs) == 0 {
		return "", SoCInfo{}, "", fmt.Errorf("SoC package '%s' not found in registry index (no SoC section)", rawRef)
	}

	slashRef := strings.Trim(strings.TrimPrefix(filepath.ToSlash(rawRef), "./"), "/")
	if slashRef == "" || strings.Contains(slashRef, "..") {
		return "", SoCInfo{}, "", fmt.Errorf("invalid SoC reference %q", rawRef)
	}

	if exact, ok := idx.SoCs[slashRef]; ok {
		return slashRef, exact, "", nil
	}

	// Longest info.Path prefix match (supports modular soc/<vendor> and @scope/soc packages).
	sortedKeys := slices.Sorted(maps.Keys(idx.SoCs))
	bestLen := -1
	for _, k := range sortedKeys {
		cand := idx.SoCs[k]
		normPath := strings.Trim(strings.TrimPrefix(filepath.ToSlash(cand.Path), "./"), "/")
		if normPath == "" {
			continue
		}
		if slashRef == normPath {
			return k, cand, "", nil
		}
		if strings.HasPrefix(slashRef, normPath+"/") && len(normPath) > bestLen {
			bestLen = len(normPath)
			socKey = k
			info = cand
			subRel = strings.TrimPrefix(slashRef, normPath+"/")
		}
	}
	if bestLen >= 0 {
		return socKey, info, subRel, nil
	}

	// Segment match under "soc/<pkg>[/<subpath>]" without hardcoding a single "soc" key.
	if afterSoc, ok := strings.CutPrefix(slashRef, "soc/"); ok {
		if exact, exists := idx.SoCs[afterSoc]; exists {
			return afterSoc, exact, "", nil
		}
		firstSeg, rest, _ := strings.Cut(afterSoc, "/")
		if firstSeg != "" {
			if segMatch, exists := idx.SoCs[firstSeg]; exists {
				return firstSeg, segMatch, rest, nil
			}
		}
	}

	return "", SoCInfo{}, "", fmt.Errorf("SoC package '%s' not found in registry index", rawRef)
}

// ResolveSoCInclude resolves a chip manifest SoC reference or include path (e.g.
// "soc/esp/include", "esp", or "@vendor/riscv_soc/include") against Index.SoCs,
// fetches the matched SoC package if needed, and returns both the package root
// directory, the resolved include subdirectory, and the matched SoC package name.
func (c *Cache) ResolveSoCInclude(inc string) (pkgRoot, includeDir, socName string, err error) {
	socKey, info, subRel, err := c.matchSoCEntry(inc)
	if err != nil {
		return "", "", "", err
	}
	activeDir := c.Dir()
	pkgRoot, err = archiveutil.SafeJoin(activeDir, info.Path)
	if err != nil {
		return "", "", "", fmt.Errorf("SoC '%s' registry path: %w", socKey, err)
	}
	pkgName := cmp.Or(info.Name, socKey)
	if fetchErr := c.fetchPackage(pkgName, info.Version, info.Path, cmp.Or(info.SHA256, info.TarballSHA)); fetchErr != nil {
		return "", "", "", fetchErr
	}
	includeDir = pkgRoot
	if subRel != "" {
		includeDir, err = archiveutil.SafeJoin(pkgRoot, subRel)
		if err != nil {
			return "", "", "", fmt.Errorf("SoC '%s' subpath %q: %w", pkgName, subRel, err)
		}
	}
	return pkgRoot, includeDir, pkgName, nil
}

// SoCSourcePath returns the absolute path to a SoC package's root directory in the cache.
func (c *Cache) SoCSourcePath(socDir string) (string, error) {
	pkgRoot, _, _, err := c.ResolveSoCInclude(socDir)
	return pkgRoot, err
}

// IntegrationSourcePath returns the absolute path to an integration framework directory.
func (c *Cache) IntegrationSourcePath(framework string) (string, error) {
	idx, err := c.LoadIndex()
	if err != nil {
		return "", err
	}
	info, ok := idx.Integrations[framework]
	if !ok || info.Path == "" {
		return "", fmt.Errorf("integration '%s' not found in registry index", framework)
	}
	destPath, err := archiveutil.SafeJoin(c.Dir(), info.Path)
	if err != nil {
		return "", fmt.Errorf("integration '%s' registry path: %w", framework, err)
	}
	if err := c.fetchPackage(cmp.Or(info.Name, framework), info.Version, info.Path, cmp.Or(info.SHA256, info.TarballSHA)); err != nil {
		return "", err
	}
	return destPath, nil
}

// PortSourcePath returns the absolute path to a port package directory in the cache.
func (c *Cache) PortSourcePath(name string) (string, error) {
	pi, err := c.GetPort(name)
	if err != nil {
		return "", err
	}
	destPath, err := archiveutil.SafeJoin(c.Dir(), pi.Path)
	if err != nil {
		return "", fmt.Errorf("port '%s' registry path: %w", name, err)
	}
	if err := c.fetchPackage(cmp.Or(pi.Name, name), pi.Version, pi.Path, cmp.Or(pi.SHA256, pi.TarballSHA)); err != nil {
		return "", err
	}
	return destPath, nil
}

// ClassifyTier resolves the trust tier ("official", "partner", "community", "local")
// strictly from local status, verified @scope/ namespace, and index metadata.
func ClassifyTier(name, author, explicitTier string, local bool) string {
	if local {
		return "local"
	}
	normTier := strings.ToLower(strings.TrimSpace(explicitTier))
	if strings.HasPrefix(name, "@toob/") {
		return "official"
	}
	if strings.HasPrefix(name, "@partner/") {
		return "partner"
	}
	if strings.HasPrefix(name, "@") {
		if normTier == "partner" {
			return "partner"
		}
		return "community"
	}
	switch normTier {
	case "official", "partner", "community":
		return normTier
	}
	if strings.EqualFold(strings.TrimSpace(author), "toob-core-team") {
		return "official"
	}
	return "community"
}
