// Package installer manages registry and locally spawned HAL packages across
// all eight package categories and keeps toob.lock v2 and device.toml in sync.
package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

// Canonical registry package categories managed by Installer.
const (
	CategoryChip        = "chip"
	CategoryArch        = "arch"
	CategoryDriver      = "driver"
	CategoryCrypto      = "crypto"
	CategorySoC         = "soc"
	CategoryIntegration = "integration"
	CategoryToolchain   = "toolchain"
	CategoryPort        = "port"
)

const matrixTimeout = 2 * time.Second

var validCategories = map[string]string{
	"chip":         CategoryChip,
	"chips":        CategoryChip,
	"arch":         CategoryArch,
	"archs":        CategoryArch,
	"driver":       CategoryDriver,
	"drivers":      CategoryDriver,
	"crypto":       CategoryCrypto,
	"soc":          CategorySoC,
	"socs":         CategorySoC,
	"integration":  CategoryIntegration,
	"integrations": CategoryIntegration,
	"toolchain":    CategoryToolchain,
	"toolchains":   CategoryToolchain,
	"port":         CategoryPort,
	"ports":        CategoryPort,
}

// InstalledPackage describes a locked or locally spawned package entry.
type InstalledPackage struct {
	Category    string
	Name        string
	Version     string
	Source      string
	SHA256      string
	BaseVersion string
	BaseSHA256  string
	Trait       string
	LocalPath   string
}

// PackageDetails aggregates registry, lockfile, and workspace status for Info.
type PackageDetails struct {
	Category    string
	Name        string
	Version     string
	Description string
	Author      string
	Tier        string
	Path        string
	SHA256      string
	Locked      bool
	Source      string
	Trait       string
	SpawnedPath string
	Verified    bool
}

// Installer orchestrates package installation, spawning, listing, info, and removal.
type Installer struct {
	root     string
	hal      string
	lockPath string
	lock     *lockfile.Lockfile
	cache    *registry.Cache
}

// New creates an installer for the given project root and fails fast on
// malformed or unreadable lockfiles instead of ignoring Load errors (CRIT-60).
func New(root string, cache *registry.Cache) (*Installer, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("project root must not be empty")
	}
	if cache == nil {
		return nil, errors.New("registry cache must not be nil")
	}
	lockPath := paths.LockfilePath(root)
	lf, err := lockfile.Load(lockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load lockfile %s: %w", lockPath, err)
	}
	if lf.FormatVersion == 0 && len(lf.Packages) == 0 && len(lf.Targets) == 0 && len(lf.Chips) == 0 {
		lf.FormatVersion = lockfile.FormatVersionV2
	}
	return &Installer{
		root:     root,
		hal:      paths.HALDir(root),
		lockPath: lockPath,
		lock:     lf,
		cache:    cache,
	}, nil
}

// NormalizeCategory maps singular/plural category names to canonical form.
func NormalizeCategory(raw string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(raw))
	cat, ok := validCategories[key]
	if !ok {
		return "", fmt.Errorf("unknown package category %q (expected chip, arch, driver, crypto, soc, integration, toolchain, or port)", raw)
	}
	return cat, nil
}

// ParsePackageRef parses "<name>[@<version>]" using LastIndex so scoped
// packages such as "@scope/pkg@1.2.3" preserve their scope prefix cleanly.
func ParsePackageRef(arg string) (name, version string, err error) {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return "", "", errors.New("package reference must not be empty")
	}

	lastAt := strings.LastIndex(trimmed, "@")
	switch lastAt {
	case -1:
		name = trimmed
	case 0:
		if !strings.Contains(trimmed, "/") {
			return "", "", fmt.Errorf("invalid scoped package reference %q (expected @scope/name)", arg)
		}
		name = trimmed
	default:
		name = trimmed[:lastAt]
		version = trimmed[lastAt+1:]
		if version == "" {
			return "", "", fmt.Errorf("empty version in package reference %q", arg)
		}
	}

	if validateErr := validatePackageIdentifier(name); validateErr != nil {
		return "", "", validateErr
	}
	if version != "" {
		if verErr := validatePackageVersionSpec(version); verErr != nil {
			return "", "", verErr
		}
	}
	return name, version, nil
}

func validatePackageIdentifier(name string) error {
	if strings.HasPrefix(name, "@") {
		return manifestpkg.ValidatePackageRef("package", name)
	}
	if strings.Contains(name, "/") {
		if strings.Contains(name, `\`) {
			return fmt.Errorf("invalid package name %q: backslashes are not allowed", name)
		}
		for _, seg := range strings.Split(name, "/") {
			if err := manifestpkg.ValidateName("package", seg); err != nil {
				return fmt.Errorf("%w (in %q)", err, name)
			}
		}
		return nil
	}
	return manifestpkg.ValidatePackageRef("package", name)
}

func validatePackageVersionSpec(ver string) error {
	if strings.Contains(ver, "..") || strings.ContainsAny(ver, "/\\ \t\r\n;") {
		return fmt.Errorf("invalid package version %q", ver)
	}
	clean := strings.TrimPrefix(ver, "v")
	if _, err := semver.NewVersion(clean); err != nil {
		return fmt.Errorf("invalid semantic version %q: %w", ver, err)
	}
	return nil
}

// List returns all locked/installed packages, optionally filtered by category.
func (inst *Installer) List(category string) ([]InstalledPackage, error) {
	var filterCat string
	if strings.TrimSpace(category) != "" {
		var err error
		filterCat, err = NormalizeCategory(category)
		if err != nil {
			return nil, err
		}
	}

	var out []InstalledPackage
	seen := make(map[string]bool)
	for i := range inst.lock.Packages {
		p := &inst.lock.Packages[i]
		if filterCat != "" && p.Category != filterCat {
			continue
		}
		localPath := ""
		if p.Source == "spawned" || p.Source == "local" {
			if cand, ok := inst.existingLocalPackageDir(p.Category, p.Name, ""); ok {
				localPath = cand
			}
		}
		seen[strings.ToLower(p.Category+"\x00"+p.Name)] = true
		out = append(out, InstalledPackage{
			Category:    p.Category,
			Name:        p.Name,
			Version:     p.Version,
			Source:      p.Source,
			SHA256:      p.SHA256,
			BaseVersion: p.BaseVersion,
			BaseSHA256:  p.BaseSHA256,
			Trait:       p.Trait,
			LocalPath:   localPath,
		})
	}

	if filterCat == "" || filterCat == CategoryToolchain {
		for _, tcName := range slices.Sorted(maps.Keys(inst.lock.Toolchains)) {
			if seen[CategoryToolchain+"\x00"+strings.ToLower(tcName)] {
				continue
			}
			tc := inst.lock.Toolchains[tcName]
			out = append(out, InstalledPackage{
				Category: CategoryToolchain,
				Name:     tcName,
				Version:  tc.Version,
				Source:   "registry",
			})
		}
	}

	slices.SortFunc(out, func(a, b InstalledPackage) int {
		if c := strings.Compare(a.Category, b.Category); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// Info resolves registry and lockfile metadata for a package in any of the 8 categories.
func (inst *Installer) Info(category, arg string) (*PackageDetails, error) {
	cat, err := NormalizeCategory(category)
	if err != nil {
		return nil, err
	}
	name, reqVer, err := ParsePackageRef(arg)
	if err != nil {
		return nil, err
	}
	idx, err := inst.cache.LoadIndex()
	if err != nil {
		return nil, err
	}
	meta, err := lookupIndexPackage(idx, cat, name, reqVer)
	if err != nil {
		return nil, err
	}

	details := &PackageDetails{
		Category:    cat,
		Name:        meta.name,
		Version:     meta.version,
		Description: meta.description,
		Author:      meta.author,
		Tier:        registry.ClassifyTier(meta.name, meta.author, meta.tier, false),
		Path:        meta.relPath,
		SHA256:      meta.sha256,
		Trait:       meta.trait,
		Verified:    meta.verified,
	}
	if lp := inst.lock.FindPackage(cat, meta.name, ""); lp != nil {
		details.Locked = true
		details.Source = lp.Source
		if lp.SHA256 != "" {
			details.SHA256 = lp.SHA256
		}
	} else if cat == CategoryToolchain {
		if tc, ok := inst.lock.Toolchains[meta.name]; ok && tc.Version != "" {
			details.Locked = true
			details.Source = "registry"
		}
	}
	if localDir, ok := inst.existingLocalPackageDir(cat, meta.name, meta.relPath); ok {
		details.SpawnedPath = localDir
	}
	return details, nil
}

// Add locks a registry package of any category without copying sources into the project.
func (inst *Installer) Add(category, arg string) error {
	cat, err := NormalizeCategory(category)
	if err != nil {
		return err
	}
	name, version, err := ParsePackageRef(arg)
	if err != nil {
		return err
	}
	if cat == CategoryChip {
		return inst.addChip(name, version)
	}
	return inst.addNonChipPackage(cat, name, version)
}

// Spawn copies a package of any category into toobloader/hal/ so it is locally editable
// and pins source="spawned" plus base_version/base_sha256 in Lockfile v2.
func (inst *Installer) Spawn(category, arg string) error {
	cat, err := NormalizeCategory(category)
	if err != nil {
		return err
	}
	name, version, err := ParsePackageRef(arg)
	if err != nil {
		return err
	}
	if cat == CategoryChip {
		return inst.spawnChip(name, version)
	}
	return inst.spawnNonChipPackage(cat, name, version)
}

// Remove deletes a package of any category from toob.lock and moves any unshared
// spawned workspace directory to external <ToobHome>/trash/.
func (inst *Installer) Remove(category, name string) error {
	cat, err := NormalizeCategory(category)
	if err != nil {
		return err
	}
	pkgName, _, err := ParsePackageRef(name)
	if err != nil {
		return err
	}
	if cat == CategoryChip {
		return inst.removeChip(pkgName)
	}
	return inst.removeNonChipPackage(cat, pkgName)
}

// Ergonomic category wrappers.

func (inst *Installer) AddChip(arg string) error        { return inst.Add(CategoryChip, arg) }
func (inst *Installer) SpawnChip(arg string) error      { return inst.Spawn(CategoryChip, arg) }
func (inst *Installer) RemoveChip(name string) error    { return inst.Remove(CategoryChip, name) }
func (inst *Installer) AddArch(arg string) error        { return inst.Add(CategoryArch, arg) }
func (inst *Installer) SpawnArch(arg string) error      { return inst.Spawn(CategoryArch, arg) }
func (inst *Installer) RemoveArch(name string) error    { return inst.Remove(CategoryArch, name) }
func (inst *Installer) AddDriver(arg string) error      { return inst.Add(CategoryDriver, arg) }
func (inst *Installer) SpawnDriver(arg string) error    { return inst.Spawn(CategoryDriver, arg) }
func (inst *Installer) RemoveDriver(name string) error  { return inst.Remove(CategoryDriver, name) }
func (inst *Installer) AddCrypto(arg string) error      { return inst.Add(CategoryCrypto, arg) }
func (inst *Installer) SpawnCrypto(arg string) error    { return inst.Spawn(CategoryCrypto, arg) }
func (inst *Installer) RemoveCrypto(name string) error  { return inst.Remove(CategoryCrypto, name) }
func (inst *Installer) AddSoC(arg string) error         { return inst.Add(CategorySoC, arg) }
func (inst *Installer) SpawnSoC(arg string) error       { return inst.Spawn(CategorySoC, arg) }
func (inst *Installer) RemoveSoC(name string) error     { return inst.Remove(CategorySoC, name) }
func (inst *Installer) AddIntegration(arg string) error { return inst.Add(CategoryIntegration, arg) }

func (inst *Installer) SpawnIntegration(arg string) error {
	return inst.Spawn(CategoryIntegration, arg)
}

func (inst *Installer) RemoveIntegration(name string) error {
	return inst.Remove(CategoryIntegration, name)
}

func (inst *Installer) AddToolchain(arg string) error { return inst.Add(CategoryToolchain, arg) }

func (inst *Installer) SpawnToolchain(arg string) error { return inst.Spawn(CategoryToolchain, arg) }

func (inst *Installer) RemoveToolchain(name string) error {
	return inst.Remove(CategoryToolchain, name)
}
func (inst *Installer) AddPort(arg string) error     { return inst.Add(CategoryPort, arg) }
func (inst *Installer) SpawnPort(arg string) error   { return inst.Spawn(CategoryPort, arg) }
func (inst *Installer) RemovePort(name string) error { return inst.Remove(CategoryPort, name) }

// UseCrypto binds slot ("backend", "hash", or "pqc") to arg in device.toml and
// pins the package in toob.lock v2 (unless arg is "none").
func (inst *Installer) UseCrypto(slot, arg string) error {
	normSlot := strings.ToLower(strings.TrimSpace(slot))
	switch normSlot {
	case "backend", "hash", "pqc":
	default:
		return fmt.Errorf("invalid crypto slot %q (expected backend, hash, or pqc)", slot)
	}

	trimmed := strings.TrimSpace(arg)
	if strings.EqualFold(trimmed, "none") {
		if err := inst.updateDeviceTomlSection("crypto", normSlot, "none", false); err != nil {
			return err
		}
		for tName, tLock := range inst.lock.Targets {
			if tLock.Crypto != nil {
				tLock.Crypto[normSlot] = "none"
				inst.lock.Targets[tName] = tLock
			}
		}
		return inst.saveLockfile()
	}

	name, reqVer, err := ParsePackageRef(trimmed)
	if err != nil {
		return err
	}
	idx, err := inst.cache.LoadIndex()
	if err != nil {
		return err
	}
	meta, err := lookupIndexPackage(idx, CategoryCrypto, name, reqVer)
	if err != nil {
		return err
	}
	if len(meta.categories) > 0 && !slices.ContainsFunc(meta.categories, func(c string) bool {
		return strings.EqualFold(c, normSlot)
	}) {
		return fmt.Errorf("crypto package %q declares category %v, cannot bind to slot %q", meta.name, meta.categories, normSlot)
	}

	if err := inst.addNonChipPackage(CategoryCrypto, name, reqVer); err != nil {
		return err
	}
	if err := inst.updateDeviceTomlSection("crypto", normSlot, meta.name, false); err != nil {
		return err
	}
	for tName, tLock := range inst.lock.Targets {
		if tLock.Crypto == nil {
			tLock.Crypto = make(map[string]string)
		}
		tLock.Crypto[normSlot] = meta.name + "@" + meta.version
		inst.lock.Targets[tName] = tLock
	}
	return inst.saveLockfile()
}

func fetchMatrixChannel(cache *registry.Cache) <-chan *registry.Matrix {
	if paths.IsDevMode() || cache.IsLocalOverride() {
		return nil
	}
	ch := make(chan *registry.Matrix, 1)
	go func() {
		m, _ := cache.FetchLiveMatrix()
		ch <- m
	}()
	return ch
}

func (inst *Installer) waitMatrixCompatibility(ctx context.Context, ch <-chan *registry.Matrix, chipName, chipVersion string, verified bool) {
	if ch == nil {
		return
	}
	var matrix *registry.Matrix
	select {
	case matrix = <-ch:
	case <-ctx.Done():
	}
	printMatrixCompatibility(matrix, chipName, chipVersion, verified)
}

func (inst *Installer) addChip(name, reqVer string) error {
	if existing := inst.lock.GetChip(name); existing != nil {
		if existing.Spawned {
			return fmt.Errorf("chip '%s' is already spawned. Use `toob chip remove` first", name)
		}
		return fmt.Errorf("chip '%s' is already installed", name)
	}
	if _, exists := inst.lock.Targets[name]; exists {
		if lp := inst.lock.FindPackage(CategoryChip, name, ""); lp != nil && lp.Source == "spawned" {
			return fmt.Errorf("chip '%s' is already spawned. Use `toob chip remove` first", name)
		}
		return fmt.Errorf("chip '%s' is already installed", name)
	}

	idx, err := inst.cache.LoadIndex()
	if err != nil {
		return err
	}
	ci, err := inst.lookupChipAndCheckVersion(idx, name, reqVer)
	if err != nil {
		return err
	}

	matrixChan := fetchMatrixChannel(inst.cache)
	ctx, cancel := context.WithTimeout(context.Background(), matrixTimeout)
	defer cancel()

	if err := inst.recordChipV2Lock(idx, ci, false); err != nil {
		return err
	}
	if err := inst.saveLockfile(); err != nil {
		return err
	}
	ui.Success("Added chip '%s' (v%s) to lockfile [arch=%s].", name, ci.Version, ci.Arch)

	inst.waitMatrixCompatibility(ctx, matrixChan, ci.Name, ci.Version, ci.Verified)
	ui.Tip("Registry link established. Run `toob build` to compile.")
	return nil
}

func (inst *Installer) spawnChip(name, reqVer string) error {
	if existing := inst.lock.GetChip(name); existing != nil {
		if !existing.Spawned {
			return fmt.Errorf("chip '%s' is already added. Use `toob chip remove` first, then `toob chip spawn`", name)
		}
		return fmt.Errorf("chip '%s' is already spawned", name)
	}
	if _, exists := inst.lock.Targets[name]; exists {
		if lp := inst.lock.FindPackage(CategoryChip, name, ""); lp == nil || lp.Source == "registry" {
			return fmt.Errorf("chip '%s' is already added. Use `toob chip remove` first, then `toob chip spawn`", name)
		}
		return fmt.Errorf("chip '%s' is already spawned", name)
	}

	idx, err := inst.cache.LoadIndex()
	if err != nil {
		return err
	}
	ci, err := inst.lookupChipAndCheckVersion(idx, name, reqVer)
	if err != nil {
		return err
	}

	matrixChan := fetchMatrixChannel(inst.cache)
	ctx, cancel := context.WithTimeout(context.Background(), matrixTimeout)
	defer cancel()

	var rollback []string
	var spawnErr error
	defer func() {
		if spawnErr != nil {
			ui.Warn("Spawn failed. Rolling back created directories...")
			for _, dir := range rollback {
				inst.moveDirToTrash(dir)
			}
		}
	}()

	createdChip, err := inst.installChip(ci)
	rollback = append(rollback, createdChip...)
	if err != nil {
		spawnErr = err
		return err
	}

	createdDeps, err := inst.installDeps(idx, ci)
	rollback = append(rollback, createdDeps...)
	if err != nil {
		spawnErr = err
		return err
	}

	if err := inst.recordChipV2Lock(idx, ci, true); err != nil {
		spawnErr = err
		return err
	}
	if err := inst.saveLockfile(); err != nil {
		spawnErr = err
		return err
	}
	ui.Success("Spawned chip '%s' (v%s) [locally editable]", name, ci.Version)
	inst.waitMatrixCompatibility(ctx, matrixChan, ci.Name, ci.Version, ci.Verified)
	return nil
}

func (inst *Installer) lookupChipAndCheckVersion(idx *registry.Index, name, reqVer string) (*registry.ChipInfo, error) {
	ci, err := inst.cache.GetChip(name)
	if err != nil {
		if !paths.IsDevMode() && !inst.cache.IsLocalOverride() {
			if liveVer, liveErr := inst.cache.ResolveChipLive(name); liveErr == nil {
				return nil, fmt.Errorf("chip '%s' is locally unknown (exists in remote registry v%s; run `toob registry sync`)", name, liveVer)
			}
		}
		return nil, err
	}
	if reqVer != "" && !versionsMatch(ci.Version, reqVer) {
		return nil, fmt.Errorf("chip %q version %q not found in local registry index (available: %q); run `toob registry sync`",
			name, reqVer, ci.Version)
	}
	if idx != nil {
		if idxChip, ok := idx.Chips[ci.Name]; ok && ci.SHA256 == "" {
			ci.SHA256 = firstNonEmpty(idxChip.SHA256, idxChip.TarballSHA)
		}
	}
	return ci, nil
}

func (inst *Installer) recordChipV2Lock(idx *registry.Index, ci *registry.ChipInfo, spawned bool) error {
	inst.updateRegistryLockHeader(idx)

	chipSrc, _ := inst.cache.ChipSourcePath(ci.Name)
	chipSHA, err := inst.resolveDigest(firstNonEmpty(ci.SHA256, ci.TarballSHA), chipSrc)
	if err != nil {
		return fmt.Errorf("chip '%s': %w", ci.Name, err)
	}
	pkgSource := "registry"
	var baseVer, baseSHA string
	if spawned {
		pkgSource = "spawned"
		baseVer = ci.Version
		baseSHA = chipSHA
	}
	inst.lock.UpsertPackage(lockfile.LockedPackage{
		Category:    CategoryChip,
		Name:        ci.Name,
		Version:     ci.Version,
		Source:      pkgSource,
		SHA256:      chipSHA,
		BaseVersion: baseVer,
		BaseSHA256:  baseSHA,
	})

	target := lockfile.TargetLock{
		Chip:            ci.Name + "@" + ci.Version,
		Drivers:         make(map[string]string),
		Crypto:          make(map[string]string),
		RecoveryDrivers: make(map[string]string),
		RecoveryCrypto:  make(map[string]string),
	}

	var aVer, tcName, tcVer string
	if idx != nil {
		if aInfo, ok := idx.Archs[ci.Arch]; ok {
			aVer = firstNonEmpty(aInfo.Version, "1.0.0")
			archSrc, _ := inst.cache.ArchSourcePath(ci.Arch)
			archSHA, aErr := inst.resolveDigest(firstNonEmpty(aInfo.SHA256, aInfo.TarballSHA), archSrc)
			if aErr != nil {
				return fmt.Errorf("arch '%s': %w", ci.Arch, aErr)
			}
			var aBaseVer, aBaseSHA string
			if spawned {
				aBaseVer, aBaseSHA = aVer, archSHA
			}
			inst.lock.UpsertPackage(lockfile.LockedPackage{
				Category:    CategoryArch,
				Name:        ci.Arch,
				Version:     aVer,
				Source:      pkgSource,
				SHA256:      archSHA,
				BaseVersion: aBaseVer,
				BaseSHA256:  aBaseSHA,
			})
			target.Arch = ci.Arch + "@" + aVer
		}

		tcName = strings.TrimSuffix(ci.CompilerPrefix, "-")
		if tcName == "" {
			for k := range idx.Toolchains {
				if strings.Contains(strings.ToLower(k), "clang") || strings.Contains(strings.ToLower(k), "llvm") {
					tcName = k
					break
				}
			}
		}
		if tcInfo, ok := idx.Toolchains[tcName]; ok && tcName != "" {
			tcVer = tcInfo.Version
			inst.lock.Toolchains[tcName] = lockfile.ToolchainEntry{
				Version: tcVer,
				SHA256:  maps.Clone(tcInfo.Sha256),
			}
			target.Toolchain = tcName + "@" + tcVer
		}

		for trait, drvRef := range ci.HalBindings {
			if drvRef == "" || strings.EqualFold(drvRef, "none") {
				continue
			}
			if dInfo, ok := lookupDriverInIndex(idx, drvRef); ok {
				dVer := firstNonEmpty(dInfo.Version, "1.0.0")
				drvSrc, _ := inst.cache.DriverSourcePath(drvRef)
				dSHA, dErr := inst.resolveDigest(firstNonEmpty(dInfo.SHA256, dInfo.TarballSHA), drvSrc)
				if dErr != nil {
					return fmt.Errorf("driver '%s': %w", dInfo.Name, dErr)
				}
				var dBaseVer, dBaseSHA string
				if spawned {
					dBaseVer, dBaseSHA = dVer, dSHA
				}
				inst.lock.UpsertPackage(lockfile.LockedPackage{
					Category:    CategoryDriver,
					Name:        dInfo.Name,
					Version:     dVer,
					Source:      pkgSource,
					SHA256:      dSHA,
					BaseVersion: dBaseVer,
					BaseSHA256:  dBaseSHA,
					Trait:       trait,
				})
				target.Drivers[trait] = dInfo.Name + "@" + dVer
			}
		}

		if ci.Crypto != nil {
			for _, pair := range []struct{ slot, name string }{
				{"backend", ci.Crypto.Backend},
				{"hash", ci.Crypto.Hash},
				{"pqc", ci.Crypto.Pqc},
			} {
				if pair.name == "" || strings.EqualFold(pair.name, "none") {
					continue
				}
				if cInfo, ok := idx.Crypto[pair.name]; ok {
					cVer := firstNonEmpty(cInfo.Version, "1.0.0")
					cSrc, _ := inst.cache.CryptoSourcePath(pair.name)
					cSHA, cErr := inst.resolveDigest(firstNonEmpty(cInfo.SHA256, cInfo.TarballSHA), cSrc)
					if cErr != nil {
						return fmt.Errorf("crypto '%s': %w", cInfo.Name, cErr)
					}
					var cBaseVer, cBaseSHA string
					if spawned {
						cBaseVer, cBaseSHA = cVer, cSHA
					}
					inst.lock.UpsertPackage(lockfile.LockedPackage{
						Category:    CategoryCrypto,
						Name:        cInfo.Name,
						Version:     cVer,
						Source:      pkgSource,
						SHA256:      cSHA,
						BaseVersion: cBaseVer,
						BaseSHA256:  cBaseSHA,
						Trait:       pair.slot,
					})
					target.Crypto[pair.slot] = cInfo.Name + "@" + cVer
				}
			}
		}

		if ci.Recovery != nil {
			if ci.Recovery.Crypto != nil {
				if ci.Recovery.Crypto.Backend != "" {
					b := strings.TrimSpace(ci.Recovery.Crypto.Backend)
					switch {
					case strings.EqualFold(b, "none"):
						target.RecoveryCrypto["backend"] = "none"
					case strings.EqualFold(b, "rom"):
						target.RecoveryCrypto["backend"] = "rom@builtin"
					default:
						if cInfo, ok := idx.Crypto[b]; ok {
							target.RecoveryCrypto["backend"] = cInfo.Name + "@" + firstNonEmpty(cInfo.Version, "1.0.0")
						}
					}
				}
				if ci.Recovery.Crypto.Hash != "" {
					h := strings.TrimSpace(ci.Recovery.Crypto.Hash)
					if strings.EqualFold(h, "none") {
						target.RecoveryCrypto["hash"] = "none"
					} else if cInfo, ok := idx.Crypto[h]; ok {
						target.RecoveryCrypto["hash"] = cInfo.Name + "@" + firstNonEmpty(cInfo.Version, "1.0.0")
					}
				}
			}
			for _, role := range []struct{ trait, ref string }{
				{"console", ci.Recovery.Console},
				{"flash", ci.Recovery.Flash},
				{"wdt", ci.Recovery.WDT},
				{"clock", ci.Recovery.Clock},
				{"confirm", ci.Recovery.RTC},
			} {
				if role.ref == "" {
					continue
				}
				if dInfo, ok := lookupDriverInIndex(idx, role.ref); ok {
					dVer := firstNonEmpty(dInfo.Version, "1.0.0")
					target.RecoveryDrivers[role.trait] = dInfo.Name + "@" + dVer
				}
			}
		}

		for _, key := range slices.Sorted(maps.Keys(idx.SoCs)) {
			soc := idx.SoCs[key]
			if slices.ContainsFunc(soc.Chips, func(c string) bool { return strings.EqualFold(c, ci.Name) }) {
				socName := firstNonEmpty(soc.Name, key)
				sVer := firstNonEmpty(soc.Version, "1.0.0")
				sSrc, _ := inst.cache.SoCSourcePath(socName)
				sSHA, sErr := inst.resolveDigest(firstNonEmpty(soc.SHA256, soc.TarballSHA), sSrc)
				if sErr == nil && sSHA != "" {
					var sBaseVer, sBaseSHA string
					if spawned {
						sBaseVer, sBaseSHA = sVer, sSHA
					}
					inst.lock.UpsertPackage(lockfile.LockedPackage{
						Category:    CategorySoC,
						Name:        socName,
						Version:     sVer,
						Source:      pkgSource,
						SHA256:      sSHA,
						BaseVersion: sBaseVer,
						BaseSHA256:  sBaseSHA,
					})
					target.SoC = socName + "@" + sVer
				}
				break
			}
		}
	}

	if target.Arch != "" || target.Toolchain != "" {
		inst.lock.Targets[ci.Name] = target
	}

	var cBackend, cHash, cPqc string
	if ci.Crypto != nil {
		cBackend, cHash, cPqc = ci.Crypto.Backend, ci.Crypto.Hash, ci.Crypto.Pqc
	}
	chipEntry := lockfile.ChipEntry{
		Name:             ci.Name,
		Version:          ci.Version,
		Arch:             ci.Arch,
		ArchVersion:      aVer,
		Toolchain:        tcName,
		ToolchainVersion: tcVer,
		CryptoBackend:    cBackend,
		CryptoHash:       cHash,
		CryptoPqc:        cPqc,
		Spawned:          spawned,
	}
	replaced := false
	for i := range inst.lock.Chips {
		if inst.lock.Chips[i].Name == ci.Name {
			inst.lock.Chips[i] = chipEntry
			replaced = true
			break
		}
	}
	if !replaced {
		inst.lock.Chips = append(inst.lock.Chips, chipEntry)
	}
	return nil
}

func (inst *Installer) addNonChipPackage(cat, name, reqVer string) error {
	idx, err := inst.cache.LoadIndex()
	if err != nil {
		return err
	}
	meta, err := lookupIndexPackage(idx, cat, name, reqVer)
	if err != nil {
		return err
	}

	srcDir, srcErr := inst.sourcePathForCategory(cat, meta.name, meta.relPath)
	digest, digErr := inst.resolveDigest(meta.sha256, srcDir)
	if digErr != nil {
		if srcErr != nil {
			return fmt.Errorf("%s '%s': %w", cat, meta.name, srcErr)
		}
		return fmt.Errorf("%s '%s': %w", cat, meta.name, digErr)
	}

	inst.updateRegistryLockHeader(idx)
	inst.lock.UpsertPackage(lockfile.LockedPackage{
		Category: cat,
		Name:     meta.name,
		Version:  meta.version,
		Source:   "registry",
		SHA256:   digest,
		Trait:    meta.trait,
	})
	if cat == CategoryToolchain {
		tc := idx.Toolchains[meta.name]
		inst.lock.Toolchains[meta.name] = lockfile.ToolchainEntry{
			Version: meta.version,
			SHA256:  maps.Clone(tc.Sha256),
		}
	}

	if cat == CategoryDriver && meta.trait != "" {
		if err := inst.updateDeviceTomlSection("drivers", meta.trait, meta.name, true); err != nil {
			return err
		}
	}
	if err := inst.saveLockfile(); err != nil {
		return err
	}
	ui.Success("Added %s '%s' (v%s) to lockfile.", cat, meta.name, meta.version)
	return nil
}

func (inst *Installer) spawnNonChipPackage(cat, name, reqVer string) error {
	idx, err := inst.cache.LoadIndex()
	if err != nil {
		return err
	}
	meta, err := lookupIndexPackage(idx, cat, name, reqVer)
	if err != nil {
		return err
	}

	srcDir, err := inst.sourcePathForCategory(cat, meta.name, meta.relPath)
	if err != nil {
		return err
	}
	digest, err := inst.resolveDigest(meta.sha256, srcDir)
	if err != nil {
		return fmt.Errorf("%s '%s': %w", cat, meta.name, err)
	}

	relDst := inst.defaultLocalRelPath(cat, meta.name, meta.trait, meta.relPath)
	dstDir, err := archiveutil.SafeJoin(inst.hal, relDst)
	if err != nil {
		return fmt.Errorf("unsafe spawn destination for %s '%s': %w", cat, meta.name, err)
	}

	if err := copyTree(srcDir, inst.hal, relDst); err != nil {
		return err
	}

	rollbackOnErr := true
	defer func() {
		if rollbackOnErr {
			inst.moveDirToTrash(dstDir)
		}
	}()

	inst.updateRegistryLockHeader(idx)
	inst.lock.UpsertPackage(lockfile.LockedPackage{
		Category:    cat,
		Name:        meta.name,
		Version:     meta.version,
		Source:      "spawned",
		SHA256:      digest,
		BaseVersion: meta.version,
		BaseSHA256:  digest,
		Trait:       meta.trait,
	})
	if cat == CategoryToolchain {
		tc := idx.Toolchains[meta.name]
		inst.lock.Toolchains[meta.name] = lockfile.ToolchainEntry{
			Version: meta.version,
			SHA256:  maps.Clone(tc.Sha256),
		}
	}
	if cat == CategoryDriver && meta.trait != "" {
		if err := inst.updateDeviceTomlSection("drivers", meta.trait, meta.name, true); err != nil {
			return err
		}
	}
	if err := inst.saveLockfile(); err != nil {
		return err
	}

	rollbackOnErr = false
	ui.Success("Spawned %s '%s' (v%s) -> %s [locally editable]", cat, meta.name, meta.version, dstDir)
	return nil
}

func (inst *Installer) removeChip(name string) error {
	legacy := inst.lock.GetChip(name)
	target, hasTarget := inst.lock.Targets[name]
	lpChip := inst.lock.FindPackage(CategoryChip, name, "")
	if legacy == nil && !hasTarget && lpChip == nil {
		return fmt.Errorf("chip '%s' is not installed", name)
	}

	chipSpawned := (legacy != nil && legacy.Spawned) || (lpChip != nil && lpChip.Source == "spawned")
	if chipSpawned {
		if chipDir, err := archiveutil.SafeJoin(inst.hal, path.Join("chips", filepath.ToSlash(name))); err == nil {
			inst.moveDirToTrash(chipDir)
		}
	}

	archName := ""
	if legacy != nil && legacy.Arch != "" {
		archName = legacy.Arch
	} else if hasTarget && target.Arch != "" {
		archName = splitName(target.Arch)
	}
	if archName != "" && !inst.lock.IsSpawnedPackageShared(CategoryArch, archName, name) && !inst.lock.IsArchShared(archName, name) {
		if archDir, err := archiveutil.SafeJoin(inst.hal, path.Join("arch", filepath.ToSlash(archName))); err == nil {
			inst.moveDirToTrash(archDir)
		}
	}

	if hasTarget {
		if target.SoC != "" {
			socName := splitName(target.SoC)
			if socName != "" && !inst.lock.IsSpawnedPackageShared(CategorySoC, socName, name) {
				if socDir, ok := inst.existingLocalPackageDir(CategorySoC, socName, ""); ok {
					inst.moveDirToTrash(socDir)
				}
			}
		}
		for _, drvMap := range []map[string]string{target.Drivers, target.RecoveryDrivers} {
			for _, ref := range drvMap {
				dName := splitName(ref)
				if dName != "" && !inst.lock.IsSpawnedPackageShared(CategoryDriver, dName, name) {
					if dDir, ok := inst.existingLocalPackageDir(CategoryDriver, dName, ""); ok {
						inst.moveDirToTrash(dDir)
					}
				}
			}
		}
		for _, cryMap := range []map[string]string{target.Crypto, target.RecoveryCrypto} {
			for _, ref := range cryMap {
				cName := splitName(ref)
				if cName != "" && cName != "rom" && !inst.lock.IsSpawnedPackageShared(CategoryCrypto, cName, name) {
					if cDir, ok := inst.existingLocalPackageDir(CategoryCrypto, cName, ""); ok {
						inst.moveDirToTrash(cDir)
					}
				}
			}
		}
	}

	inst.cleanEmptyHALDirs()
	inst.lock.RemoveTarget(name)
	inst.prunePackageFromLock(CategoryChip, name)

	if err := inst.saveLockfile(); err != nil {
		return err
	}
	ui.Success("Removed chip '%s'.", name)
	return nil
}

func (inst *Installer) removeNonChipPackage(cat, name string) error {
	lp := inst.lock.FindPackage(cat, name, "")
	_, hasTC := inst.lock.Toolchains[name]
	localDir, hasLocal := inst.existingLocalPackageDir(cat, name, "")

	if lp == nil && (cat != CategoryToolchain || !hasTC) && !hasLocal {
		return fmt.Errorf("%s '%s' is not installed", cat, name)
	}
	if inst.lock.IsSpawnedPackageShared(cat, name, "") {
		return fmt.Errorf("cannot remove %s '%s': still referenced by an active target in toob.lock", cat, name)
	}

	if hasLocal {
		inst.moveDirToTrash(localDir)
		inst.cleanEmptyHALDirs()
	}

	trait := ""
	if lp != nil {
		trait = lp.Trait
	}
	inst.prunePackageFromLock(cat, name)
	if cat == CategoryToolchain {
		delete(inst.lock.Toolchains, name)
	}

	if cat == CategoryDriver && trait != "" {
		if err := inst.removeDeviceTomlMatchingValue("drivers", name); err != nil {
			return err
		}
	}
	if cat == CategoryCrypto {
		if err := inst.removeDeviceTomlMatchingValue("crypto", name); err != nil {
			return err
		}
	}

	if err := inst.saveLockfile(); err != nil {
		return err
	}
	ui.Success("Removed %s '%s'.", cat, name)
	return nil
}

func (inst *Installer) prunePackageFromLock(cat, name string) {
	kept := make([]lockfile.LockedPackage, 0, len(inst.lock.Packages))
	for i := range inst.lock.Packages {
		p := inst.lock.Packages[i]
		if strings.EqualFold(p.Category, cat) && strings.EqualFold(p.Name, name) {
			continue
		}
		kept = append(kept, p)
	}
	inst.lock.Packages = kept
}

func (inst *Installer) installChip(ci *registry.ChipInfo) ([]string, error) {
	src, err := inst.cache.ChipSourcePath(ci.Name)
	if err != nil {
		return nil, err
	}
	rel := path.Join("chips", filepath.ToSlash(ci.Name))
	dst, err := archiveutil.SafeJoin(inst.hal, rel)
	if err != nil {
		return nil, fmt.Errorf("unsafe chip destination %q: %w", ci.Name, err)
	}
	if err := copyTree(src, inst.hal, rel); err != nil {
		return nil, err
	}
	return []string{dst}, nil
}

func (inst *Installer) installDeps(idx *registry.Index, ci *registry.ChipInfo) ([]string, error) {
	var created []string

	archRel := path.Join("arch", filepath.ToSlash(ci.Arch))
	archDst, err := archiveutil.SafeJoin(inst.hal, archRel)
	if err != nil {
		return created, fmt.Errorf("unsafe arch path %q: %w", ci.Arch, err)
	}
	if _, statErr := os.Stat(archDst); errors.Is(statErr, fs.ErrNotExist) {
		archSrc, srcErr := inst.cache.ArchSourcePath(ci.Arch)
		if srcErr != nil {
			return created, srcErr
		}
		if copyErr := copyTree(archSrc, inst.hal, archRel); copyErr != nil {
			return created, copyErr
		}
		created = append(created, archDst)
	} else if statErr == nil && inst.lock.Registry.Version != "" {
		ui.Warn("Shared dependency '%s' already exists. Not overwriting to preserve local edits.", archDst)
	}

	copyDriver := func(ref, explicitRel string) error {
		rel := explicitRel
		if rel == "" && idx != nil {
			if dInfo, ok := lookupDriverInIndex(idx, ref); ok {
				rel = dInfo.Path
			}
		}
		if rel == "" {
			rel = path.Join("drivers", filepath.ToSlash(ref))
		}
		dst, safeErr := archiveutil.SafeJoin(inst.hal, rel)
		if safeErr != nil {
			return fmt.Errorf("unsafe driver path %q: %w", rel, safeErr)
		}
		if _, statErr := os.Stat(dst); !errors.Is(statErr, fs.ErrNotExist) {
			return nil
		}
		src, srcErr := inst.cache.DriverSourcePath(ref)
		if srcErr != nil {
			return srcErr
		}
		if copyErr := copyTree(src, inst.hal, rel); copyErr != nil {
			return copyErr
		}
		created = append(created, dst)
		return nil
	}

	for _, drvRef := range ci.HalBindings {
		if drvRef == "" || strings.EqualFold(drvRef, "none") {
			continue
		}
		if err := copyDriver(drvRef, ""); err != nil {
			return created, err
		}
	}

	if ci.Sources != nil {
		for _, driverFile := range ci.Sources.Drivers {
			if strings.HasPrefix(driverFile, "drivers/") {
				drvDir := path.Dir(filepath.ToSlash(driverFile))
				if err := copyDriver(drvDir, drvDir); err != nil {
					return created, err
				}
			}
		}
	}

	if ci.Recovery != nil {
		for _, drvName := range []string{ci.Recovery.Console, ci.Recovery.Flash, ci.Recovery.WDT, ci.Recovery.Clock, ci.Recovery.RTC} {
			if drvName == "" || strings.EqualFold(drvName, "none") {
				continue
			}
			if idx != nil {
				if dInfo, ok := lookupDriverInIndex(idx, drvName); ok {
					if err := copyDriver(dInfo.Path, dInfo.Path); err != nil {
						return created, err
					}
					continue
				}
			}
			if err := copyDriver(drvName, ""); err != nil {
				return created, err
			}
		}
	}

	copiedSoCRoots := make(map[string]bool)
	for _, inc := range ci.Includes {
		switch {
		case strings.HasPrefix(inc, "soc/"):
			pkgRoot, _, socName, socErr := inst.cache.ResolveSoCInclude(inc)
			if socErr != nil {
				return created, fmt.Errorf("resolving SoC include %q: %w", inc, socErr)
			}
			if copiedSoCRoots[pkgRoot] {
				continue
			}
			copiedSoCRoots[pkgRoot] = true
			relDst := "soc"
			if socName != "" && socName != "soc" {
				relDst = path.Join("soc", socName)
			}
			socDst, safeErr := archiveutil.SafeJoin(inst.hal, relDst)
			if safeErr != nil {
				return created, fmt.Errorf("unsafe SoC destination %q: %w", relDst, safeErr)
			}
			if _, statErr := os.Stat(socDst); errors.Is(statErr, fs.ErrNotExist) {
				if copyErr := copyTree(pkgRoot, inst.hal, relDst); copyErr != nil {
					return created, copyErr
				}
				created = append(created, socDst)
			}
		case strings.HasPrefix(inc, "drivers/") || strings.HasPrefix(inc, "shared/"):
			incDst, safeErr := archiveutil.SafeJoin(inst.hal, inc)
			if safeErr != nil {
				return created, fmt.Errorf("unsafe include path %q: %w", inc, safeErr)
			}
			if _, statErr := os.Stat(incDst); !errors.Is(statErr, fs.ErrNotExist) {
				continue
			}
			incSrc, fetchErr := inst.cache.DriverSourcePath(inc)
			if fetchErr != nil {
				return created, fetchErr
			}
			if copyErr := copyTree(incSrc, inst.hal, inc); copyErr != nil {
				return created, copyErr
			}
			created = append(created, incDst)
		}
	}

	return created, nil
}

type indexPkgMeta struct {
	name        string
	version     string
	relPath     string
	sha256      string
	description string
	author      string
	tier        string
	trait       string
	categories  []string
	verified    bool
}

func lookupDriverInIndex(idx *registry.Index, ref string) (registry.DriverInfo, bool) {
	if idx == nil {
		return registry.DriverInfo{}, false
	}
	if d, ok := idx.Drivers[ref]; ok {
		return d, true
	}
	if !strings.HasPrefix(ref, "@") {
		if d, ok := idx.Drivers[path.Base(filepath.ToSlash(ref))]; ok {
			return d, true
		}
	}
	return registry.DriverInfo{}, false
}

func lookupIndexPackage(idx *registry.Index, cat, name, reqVer string) (indexPkgMeta, error) {
	if idx == nil {
		return indexPkgMeta{}, errors.New("registry index is nil")
	}

	var meta indexPkgMeta
	found := false
	switch cat {
	case CategoryChip:
		if p, ok := idx.Chips[name]; ok {
			meta = indexPkgMeta{
				name: firstNonEmpty(p.Name, name), version: p.Version, relPath: p.Path,
				sha256: firstNonEmpty(p.SHA256, p.TarballSHA), description: p.Description,
				author: p.Author, tier: p.Tier, verified: p.Verified,
			}
			found = true
		}
	case CategoryArch:
		if p, ok := idx.Archs[name]; ok {
			meta = indexPkgMeta{
				name: firstNonEmpty(p.Name, name), version: p.Version, relPath: p.Path,
				sha256: firstNonEmpty(p.SHA256, p.TarballSHA), description: p.Description,
				author: p.Author, tier: p.Tier,
			}
			found = true
		}
	case CategoryDriver:
		if p, ok := lookupDriverInIndex(idx, name); ok {
			meta = indexPkgMeta{
				name: firstNonEmpty(p.Name, name), version: p.Version, relPath: p.Path,
				sha256: firstNonEmpty(p.SHA256, p.TarballSHA), description: p.Description,
				author: p.Author, tier: p.Tier, trait: p.Trait,
			}
			found = true
		}
	case CategoryCrypto:
		if p, ok := idx.Crypto[name]; ok {
			meta = indexPkgMeta{
				name: firstNonEmpty(p.Name, name), version: p.Version, relPath: p.Path,
				sha256: firstNonEmpty(p.SHA256, p.TarballSHA), description: p.Description,
				author: p.Author, tier: p.Tier, categories: p.Category,
			}
			found = true
		}
	case CategorySoC:
		if p, ok := idx.SoCs[name]; ok {
			meta = indexPkgMeta{
				name: firstNonEmpty(p.Name, name), version: p.Version, relPath: p.Path,
				sha256: firstNonEmpty(p.SHA256, p.TarballSHA), description: p.Description,
				author: p.Author, tier: p.Tier,
			}
			found = true
		}
	case CategoryIntegration:
		if p, ok := idx.Integrations[name]; ok {
			meta = indexPkgMeta{
				name: firstNonEmpty(p.Name, name), version: p.Version, relPath: p.Path,
				sha256: firstNonEmpty(p.SHA256, p.TarballSHA), description: p.Description,
				author: p.Author, tier: p.Tier,
			}
			found = true
		}
	case CategoryToolchain:
		if p, ok := idx.Toolchains[name]; ok {
			meta = indexPkgMeta{
				name: name, version: p.Version, relPath: p.Path, sha256: p.TarballSHA,
			}
			found = true
		}
	case CategoryPort:
		if p, ok := idx.Ports[name]; ok {
			meta = indexPkgMeta{
				name: firstNonEmpty(p.Name, name), version: p.Version, relPath: p.Path,
				sha256: firstNonEmpty(p.SHA256, p.TarballSHA), description: p.Description,
				author: p.Author, tier: p.Tier,
			}
			found = true
		}
	}

	if !found {
		return indexPkgMeta{}, fmt.Errorf("%s '%s' not found in registry index", cat, name)
	}
	if reqVer != "" && !versionsMatch(meta.version, reqVer) {
		return indexPkgMeta{}, fmt.Errorf("%s '%s' version %q not found in local registry index (available: %q); run `toob registry sync`",
			cat, name, reqVer, meta.version)
	}
	if meta.version == "" {
		meta.version = "1.0.0"
	}
	return meta, nil
}

func (inst *Installer) sourcePathForCategory(cat, name, relPath string) (string, error) {
	switch cat {
	case CategoryChip:
		return inst.cache.ChipSourcePath(name)
	case CategoryArch:
		return inst.cache.ArchSourcePath(name)
	case CategoryDriver:
		if relPath != "" {
			if p, err := inst.cache.DriverSourcePath(relPath); err == nil {
				return p, nil
			}
		}
		return inst.cache.DriverSourcePath(name)
	case CategoryCrypto:
		return inst.cache.CryptoSourcePath(name)
	case CategorySoC:
		if relPath != "" {
			if p, err := inst.cache.SoCSourcePath(relPath); err == nil {
				return p, nil
			}
		}
		return inst.cache.SoCSourcePath(name)
	case CategoryIntegration:
		return inst.cache.IntegrationSourcePath(name)
	case CategoryToolchain:
		return inst.cache.ToolchainConfigPath(name)
	case CategoryPort:
		return inst.cache.PortSourcePath(name)
	default:
		return "", fmt.Errorf("unsupported package category %q", cat)
	}
}

func (inst *Installer) defaultLocalRelPath(cat, name, trait, relPath string) string {
	if relPath != "" {
		return filepath.ToSlash(relPath)
	}
	slashName := filepath.ToSlash(name)
	switch cat {
	case CategoryChip:
		return path.Join("chips", slashName)
	case CategoryArch:
		return path.Join("arch", slashName)
	case CategoryDriver:
		if trait != "" {
			return path.Join("drivers", trait, slashName)
		}
		return path.Join("drivers", slashName)
	case CategoryCrypto:
		return path.Join("crypto", slashName)
	case CategorySoC:
		if name == "soc" {
			return "soc"
		}
		return path.Join("soc", slashName)
	case CategoryIntegration:
		return path.Join("integrations", slashName)
	case CategoryToolchain:
		return path.Join("toolchains", slashName)
	case CategoryPort:
		return path.Join("ports", slashName)
	default:
		return path.Join(cat, slashName)
	}
}

func (inst *Installer) existingLocalPackageDir(cat, name, relPath string) (string, bool) {
	candidates := []string{
		inst.defaultLocalRelPath(cat, name, "", relPath),
	}
	if cat == CategorySoC && name == "soc" {
		candidates = append(candidates, "soc")
	}
	if cat == CategoryDriver || cat == CategoryCrypto {
		catRoot, err := archiveutil.SafeJoin(inst.hal, cat)
		if err == nil {
			if entries, rdErr := os.ReadDir(catRoot); rdErr == nil {
				for _, e := range entries {
					if e.IsDir() {
						candidates = append(candidates, path.Join(cat, e.Name(), filepath.ToSlash(name)))
					}
				}
			}
		}
	}
	for _, rel := range candidates {
		joined, err := archiveutil.SafeJoin(inst.hal, rel)
		if err != nil {
			continue
		}
		if st, statErr := os.Stat(joined); statErr == nil && st.IsDir() {
			return joined, true
		}
	}
	return "", false
}

func (inst *Installer) updateRegistryLockHeader(idx *registry.Index) {
	inst.lock.FormatVersion = lockfile.FormatVersionV2
	if inst.lock.Registry.URL == "" {
		inst.lock.Registry.URL = inst.cache.Remote()
	}
	if commit, err := inst.cache.HeadCommit(); err == nil && commit != "" {
		inst.lock.Registry.Commit = commit
	}
	if idx != nil && idx.RegistryVersion != "" {
		inst.lock.Registry.Version = idx.RegistryVersion
	}
	for _, idxCand := range []string{
		filepath.Join(inst.cache.Dir(), "registry.json"),
		filepath.Join(inst.cache.Dir(), "packages", "registry.json"),
	} {
		if sum, err := sha256File(idxCand); err == nil {
			inst.lock.Registry.IndexSHA256 = sum
			break
		}
	}
}

func (inst *Installer) saveLockfile() error {
	inst.lock.FormatVersion = lockfile.FormatVersionV2
	return inst.lock.Save(inst.lockPath)
}

func (inst *Installer) resolveDigest(explicitSHA, srcDir string) (string, error) {
	if explicitSHA != "" {
		return explicitSHA, nil
	}
	if srcDir == "" {
		return "", errors.New("package has neither registry sha256 nor source directory")
	}
	return hashDirDeterministic(srcDir)
}

func sha256File(p string) (string, error) {
	f, err := os.Open(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashDirDeterministic(rootDir string) (string, error) {
	var files []string
	err := filepath.WalkDir(rootDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, relErr := filepath.Rel(rootDir, p)
		if relErr != nil {
			return relErr
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("package directory %s contains no regular files", rootDir)
	}
	slices.Sort(files)

	h := sha256.New()
	for _, rel := range files {
		_, _ = fmt.Fprintf(h, "%s\n", rel)
		f, openErr := os.Open(filepath.Join(rootDir, filepath.FromSlash(rel)))
		if openErr != nil {
			return "", openErr
		}
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func versionsMatch(actual, requested string) bool {
	if actual == requested {
		return true
	}
	vA, errA := semver.NewVersion(strings.TrimPrefix(actual, "v"))
	vR, errR := semver.NewVersion(strings.TrimPrefix(requested, "v"))
	if errA == nil && errR == nil {
		return vA.Equal(vR)
	}
	return false
}

func splitName(ref string) string {
	if ref == "" || ref == "none" || strings.HasPrefix(ref, "local:") {
		return ""
	}
	idx := strings.LastIndex(ref, "@")
	if idx <= 0 {
		return ref
	}
	return ref[:idx]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Atomic device.toml section updates (never touch .gitignore or cmake/toolchain.cmake).

func (inst *Installer) updateDeviceTomlSection(section, key, value string, onlyIfMissing bool) error {
	tomlPath := filepath.Join(inst.root, "device.toml")
	raw, err := os.ReadFile(filepath.Clean(tomlPath))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	updated, changed := upsertTOMLSectionKey(string(raw), section, key, value, onlyIfMissing)
	if !changed {
		return nil
	}
	return atomicWriteValidatedTOML(tomlPath, []byte(updated), 0o644)
}

func (inst *Installer) removeDeviceTomlMatchingValue(section, value string) error {
	tomlPath := filepath.Join(inst.root, "device.toml")
	raw, err := os.ReadFile(filepath.Clean(tomlPath))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	updated, changed := deleteTOMLSectionMatchingValue(string(raw), section, value)
	if !changed {
		return nil
	}
	return atomicWriteValidatedTOML(tomlPath, []byte(updated), 0o644)
}

func atomicWriteValidatedTOML(dst string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-device-*.toml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()
		return writeErr
	}
	if chmodErr := tmp.Chmod(mode); chmodErr != nil {
		_ = tmp.Close()
		return chmodErr
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return closeErr
	}
	if _, parseErr := manifestpkg.ParseToml(tmpPath); parseErr != nil {
		return fmt.Errorf("aborting device.toml update due to invalid resulting TOML: %w", parseErr)
	}
	if renameErr := os.Rename(tmpPath, dst); renameErr != nil {
		return renameErr
	}
	cleanup = false
	return nil
}

func upsertTOMLSectionKey(src, section, key, val string, onlyIfMissing bool) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	secHeader := "[" + section + "]"
	quotedVal := fmt.Sprintf("%q", val)
	inSection := false
	foundSection := false
	insertAt := -1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "[[") {
			if inSection {
				insertAt = i
				break
			}
			inSection = strings.EqualFold(trimmed, secHeader)
			if inSection {
				foundSection = true
				insertAt = i + 1
			}
			continue
		}
		if inSection && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if lhs, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(lhs) == key {
				if onlyIfMissing {
					return src, false
				}
				lines[i] = key + " = " + quotedVal
				return strings.Join(lines, "\n"), true
			}
			insertAt = i + 1
		}
	}

	if foundSection {
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[:insertAt]...)
		out = append(out, key+" = "+quotedVal)
		out = append(out, lines[insertAt:]...)
		return strings.Join(out, "\n"), true
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(strings.ReplaceAll(src, "\r\n", "\n"), "\n"))
	b.WriteString("\n\n")
	b.WriteString(secHeader)
	b.WriteString("\n")
	b.WriteString(key)
	b.WriteString(" = ")
	b.WriteString(quotedVal)
	b.WriteString("\n")
	return b.String(), true
}

func deleteTOMLSectionMatchingValue(src, section, val string) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	secHeader := "[" + section + "]"
	inSection := false
	changed := false
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "[[") {
			inSection = strings.EqualFold(trimmed, secHeader)
			out = append(out, line)
			continue
		}
		if inSection && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if _, rhs, ok := strings.Cut(trimmed, "="); ok {
				unquoted := strings.Trim(strings.TrimSpace(rhs), `"'`)
				if unquoted == val {
					changed = true
					continue
				}
			}
		}
		out = append(out, line)
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

// Trash & filesystem helpers: deleted HAL directories always move to external
// <ToobHome>/trash/, never into toobloader/hal/.trash/.

func (inst *Installer) moveDirToTrash(dir string) {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return
	}
	home, err := paths.ToobHome()
	if err != nil || home == "" {
		_ = os.RemoveAll(dir)
		return
	}

	rel := filepath.Base(dir)
	if r, relErr := filepath.Rel(inst.hal, dir); relErr == nil && !strings.HasPrefix(r, "..") {
		rel = r
	}
	projectHash := sha256.Sum256([]byte(filepath.Clean(inst.root)))
	trashRoot := filepath.Join(home, "trash", hex.EncodeToString(projectHash[:8]))
	relTrash := filepath.ToSlash(rel) + "-" + time.Now().UTC().Format("20060102T150405Z")
	trashDst, safeErr := archiveutil.SafeJoin(trashRoot, relTrash)
	if safeErr != nil {
		_ = os.RemoveAll(dir)
		return
	}

	if mkErr := os.MkdirAll(filepath.Dir(trashDst), 0o750); mkErr != nil {
		_ = os.RemoveAll(dir)
		return
	}
	if renErr := os.Rename(dir, trashDst); renErr != nil {
		// Cross-volume moves fall back cleanly to copy + remove.
		if copyErr := copyTree(dir, trashRoot, relTrash); copyErr != nil {
			ui.Warn("Could not move %s to trash (%v); deleting directory directly.", dir, copyErr)
		}
		_ = os.RemoveAll(dir)
	}
	purgeOldTrash(filepath.Join(home, "trash"), 7*24*time.Hour)
}

func (inst *Installer) cleanEmptyHALDirs() {
	for _, sub := range []string{"chips", "arch", "drivers", "crypto", "soc", "integrations", "toolchains", "ports", "include"} {
		removeIfEmpty(filepath.Join(inst.hal, sub))
	}
	removeIfEmpty(inst.hal)
}

func removeIfEmpty(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	if len(entries) == 0 {
		_ = os.Remove(dir)
	}
}

func purgeOldTrash(trashRoot string, maxAge time.Duration) {
	entries, err := os.ReadDir(trashRoot)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, bucket := range entries {
		if !bucket.IsDir() {
			continue
		}
		bucketPath := filepath.Join(trashRoot, bucket.Name())
		subEntries, rdErr := os.ReadDir(bucketPath)
		if rdErr != nil {
			continue
		}
		for _, entry := range subEntries {
			info, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				_ = os.RemoveAll(filepath.Join(bucketPath, entry.Name()))
			}
		}
		removeIfEmpty(bucketPath)
	}
}

func printMatrixCompatibility(matrix *registry.Matrix, chipName, chipVersion string, verified bool) {
	if matrix == nil {
		if verified {
			ui.Info("Compatibility status: verified in local index (live matrix unavailable offline).")
		}
		return
	}
	chipMat, ok := (*matrix)[chipName]
	if !ok {
		return
	}
	verMat, ok := chipMat.Versions[chipVersion]
	if !ok {
		return
	}
	if verMat.Dependencies.Toolchain != "" || verMat.Dependencies.CoreSDK != "" {
		ui.Info("Verified Compatibility Matrix for %s@%s (toolchain=%s, core_sdk=%s).",
			chipName, chipVersion, verMat.Dependencies.Toolchain, verMat.Dependencies.CoreSDK)
	}
}

// copyTree copies regular files from src into baseDir/relDst using *os.Root
// handle confinement, never hardlinking into editable workspace directories.
func copyTree(src, baseDir, relDst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("registry source does not exist: %s (run `toob registry sync`)", src)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}

	cleanBase := filepath.Clean(baseDir)
	if mkErr := os.MkdirAll(cleanBase, 0o750); mkErr != nil {
		return mkErr
	}
	baseRoot, err := os.OpenRoot(cleanBase)
	if err != nil {
		return err
	}
	defer func() { _ = baseRoot.Close() }()

	_, relTargetOS, safeErr := archiveutil.SafeRelPath(cleanBase, relDst)
	if safeErr != nil {
		return safeErr
	}
	if parent := filepath.Dir(relTargetOS); parent != "." {
		if parentErr := archiveutil.RootMkdirAll(baseRoot, parent); parentErr != nil {
			return parentErr
		}
	}
	if mkErr := baseRoot.Mkdir(relTargetOS, 0o750); mkErr != nil {
		if errors.Is(mkErr, fs.ErrExist) {
			return fmt.Errorf("directory %s already exists; remove it first to respawn or update", filepath.Join(cleanBase, relTargetOS))
		}
		return mkErr
	}

	dstRoot, err := baseRoot.OpenRoot(relTargetOS)
	if err != nil {
		return err
	}
	defer func() { _ = dstRoot.Close() }()

	dstAbs := filepath.Join(cleanBase, relTargetOS)
	return filepath.WalkDir(src, func(srcPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(src, srcPath)
		if relErr != nil {
			return relErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink %q inside registry package %s", rel, src)
		}
		if rel == "." {
			return nil
		}
		_, relOS, entrySafeErr := archiveutil.SafeRelPath(dstAbs, rel)
		if entrySafeErr != nil {
			return entrySafeErr
		}
		if d.IsDir() {
			return archiveutil.RootMkdirAll(dstRoot, relOS)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFileIntoRootWithRetry(srcPath, dstRoot, relOS)
	})
}

func copyFileIntoRootWithRetry(src string, dstRoot *os.Root, relOS string) error {
	if parent := filepath.Dir(relOS); parent != "." {
		if err := archiveutil.RootMkdirAll(dstRoot, parent); err != nil {
			return err
		}
	}
	stat, err := os.Stat(src)
	if err != nil {
		return err
	}
	origMode := stat.Mode().Perm()

	delays := []time.Duration{0, 10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond}
	var lastErr error
	for _, d := range delays {
		if d > 0 {
			time.Sleep(d)
		}
		lastErr = copyRegularFileToRoot(src, dstRoot, relOS, origMode)
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func copyRegularFileToRoot(src string, dstRoot *os.Root, relOS string, mode fs.FileMode) error {
	srcFile, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	dstFile, err := dstRoot.OpenFile(relOS, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dstFile, srcFile)
	closeErr := dstFile.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
