package resolve

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
)

// Crypto slot names, in resolution and rendering order.
const (
	slotBackend = "backend"
	slotHash    = "hash"
	slotPQC     = "pqc"
)

const (
	driverManifestFile = "driver_manifest.json"
	cryptoManifestFile = "crypto_manifest.json"
)

func firstNonEmpty(candidates ...string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.Mode().IsRegular()
}

func loadOptionalDriverManifest(dir string) (*ports.DriverManifest, error) {
	mPath, err := Contain(dir, driverManifestFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(mPath); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var dm ports.DriverManifest
	if err := decodeStrictManifestJSON(mPath, &dm); err != nil {
		return nil, err
	}
	if dm.Name != "" {
		if err := manifestpkg.ValidatePackageRef("driver", dm.Name); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	if dm.Trait != "" {
		if err := manifestpkg.ValidateName("driver trait", dm.Trait); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	if dm.Version != "" {
		if err := manifestpkg.ValidateName("driver version", dm.Version); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	if dm.AbiVersion != "" {
		if err := manifestpkg.ValidateName("driver abi_version", dm.AbiVersion); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	for _, h := range dm.Headers {
		if err := validateHeaderRel(h); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(dm.Symbols)) {
		if err := manifestpkg.ValidateName("driver symbol key", k); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
		if !isCSymbol(dm.Symbols[k]) {
			return nil, fmt.Errorf("%s: invalid C symbol %q for %q", mPath, dm.Symbols[k], k)
		}
	}
	if _, err := containAll(dir, dm.Sources); err != nil {
		return nil, fmt.Errorf("%s sources: %w", mPath, err)
	}
	if _, err := containAll(dir, dm.MockSources); err != nil {
		return nil, fmt.Errorf("%s mock_sources: %w", mPath, err)
	}
	return &dm, nil
}

// selectPackageSources selects the C/ASM translation units for a driver package,
// enforcing strict mutual exclusion between real and mock TUs.
func selectPackageSources(dir string, dm *ports.DriverManifest, mocked bool, fallbackRelFiles []string) ([]string, error) {
	if dm != nil && (len(dm.Sources) > 0 || len(dm.MockSources) > 0) {
		if mocked {
			if len(dm.MockSources) > 0 {
				return containAll(dir, dm.MockSources)
			}
			out := make([]string, 0, len(dm.Sources))
			for _, rel := range dm.Sources {
				resolved, err := Contain(dir, rel)
				if err != nil {
					return nil, err
				}
				if strings.HasSuffix(rel, "_real.c") {
					candRel := strings.TrimSuffix(rel, "_real.c") + "_mock.c"
					cand, err := Contain(dir, candRel)
					if err != nil {
						return nil, err
					}
					if fileExists(cand) {
						resolved = cand
					}
				} else if strings.HasSuffix(rel, ".c") && !strings.HasSuffix(rel, "_mock.c") {
					candRel := strings.TrimSuffix(rel, ".c") + "_mock.c"
					cand, err := Contain(dir, candRel)
					if err != nil {
						return nil, err
					}
					if fileExists(cand) {
						resolved = cand
					}
				}
				out = append(out, resolved)
			}
			return out, nil
		}
		return containAll(dir, dm.Sources)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return containAll(dir, fallbackRelFiles)
	}

	var files []string
	containedByName := make(map[string]string)
	mockByStem := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".c") && !strings.HasSuffix(name, ".S") && !strings.HasSuffix(name, ".s") {
			continue
		}
		contained, err := Contain(dir, name)
		if err != nil {
			return nil, err
		}
		containedByName[name] = contained
		files = append(files, name)
		if strings.HasSuffix(name, "_mock.c") {
			mockByStem[strings.TrimSuffix(name, "_mock.c")] = name
		}
	}
	slices.Sort(files)
	var out []string
	for _, name := range files {
		if mocked {
			if strings.HasSuffix(name, "_real.c") {
				if _, hasMock := mockByStem[strings.TrimSuffix(name, "_real.c")]; hasMock {
					continue
				}
			} else if strings.HasSuffix(name, ".c") && !strings.HasSuffix(name, "_mock.c") {
				if _, hasMock := mockByStem[strings.TrimSuffix(name, ".c")]; hasMock {
					continue
				}
			}
			out = append(out, containedByName[name])
		} else {
			if strings.HasSuffix(name, "_mock.c") {
				continue
			}
			out = append(out, containedByName[name])
		}
	}
	if len(out) == 0 && len(fallbackRelFiles) > 0 {
		return containAll(dir, fallbackRelFiles)
	}
	return out, nil
}

func resolveLocalDriverDir(root string, idx *registry.Index, trait, ref string) (string, bool, error) {
	halBase := filepath.Join(root, localHalDir)
	var relCandidates []string
	if idx != nil {
		if info, ok := idx.Drivers[ref]; ok && info.Path != "" {
			relCandidates = append(relCandidates, info.Path)
		}
	}
	slashRef := filepath.ToSlash(ref)
	if strings.HasPrefix(slashRef, "drivers/") {
		relCandidates = append(relCandidates, slashRef)
	} else {
		if trait != "" {
			relCandidates = append(relCandidates, path.Join("drivers", trait, slashRef))
		}
		relCandidates = append(relCandidates, path.Join("drivers", slashRef))
	}
	for _, relCand := range relCandidates {
		c, err := Contain(halBase, relCand)
		if err != nil {
			return "", false, fmt.Errorf("local driver path %q: %w", relCand, err)
		}
		ok, err := isDir(c)
		if err != nil {
			return "", false, err
		}
		if ok {
			return c, true, nil
		}
	}
	return "", false, nil
}

func inferTraitFromRelPath(rel string) string {
	parts := strings.Split(strings.TrimPrefix(filepath.ToSlash(rel), "drivers/"), "/")
	if len(parts) >= 2 {
		return parts[0]
	}
	return ""
}

func resolveDriverDirAndManifest(in Input, trait, ref, role string) (string, bool, *ports.DriverManifest, error) {
	dir, local, err := resolveLocalDriverDir(in.Root, in.Index, trait, ref)
	if err != nil {
		return "", false, nil, err
	}
	if !local {
		if in.Registry == nil {
			return "", false, nil, errors.New("registry source is nil")
		}
		if dir, err = in.Registry.DriverSourcePath(ref); err != nil {
			return "", false, nil, fmt.Errorf("failed to resolve %s: %w", role, err)
		}
	}
	dm, err := loadOptionalDriverManifest(dir)
	if err != nil {
		return "", false, nil, err
	}
	return dir, local, dm, nil
}

// resolveDriverPackages merges chip hal_bindings, device.toml [drivers] overrides,
// and legacy sources.drivers, resolving local overrides, trust tiers, and mock/real TUs.
func resolveDriverPackages(in Input, chip *Chip, mode buildMode) ([]string, []ResolvedDriver, []string, error) {
	bindings := make(map[string]string, len(chip.halBindings)+len(in.Device.Drivers))
	for _, trait := range slices.Sorted(maps.Keys(chip.halBindings)) {
		if err := manifestpkg.ValidateName("driver trait", trait); err != nil {
			return nil, nil, nil, fmt.Errorf("chip '%s' hal_bindings: %w", chip.Name, err)
		}
		bindings[trait] = chip.halBindings[trait]
	}

	replacedDefaults := make(map[string]bool)
	for _, trait := range slices.Sorted(maps.Keys(in.Device.Drivers)) {
		if err := manifestpkg.ValidateName("driver trait", trait); err != nil {
			return nil, nil, nil, fmt.Errorf("device.toml [drivers]: %w", err)
		}
		ref := strings.TrimSpace(in.Device.Drivers[trait])
		if prev := bindings[trait]; prev != "" && prev != ref {
			replacedDefaults[prev] = true
			replacedDefaults[path.Base(filepath.ToSlash(prev))] = true
		}
		if ref == "" || strings.EqualFold(ref, "none") {
			delete(bindings, trait)
			continue
		}
		if err := validatePackageOrRelName("driver", ref); err != nil {
			return nil, nil, nil, fmt.Errorf("device.toml [drivers.%s]: %w", trait, err)
		}
		bindings[trait] = ref
	}

	var dirs []string
	var pkgs []ResolvedDriver
	var allSources []string
	appendUnique := func(dst []string, items ...string) []string {
		for _, it := range items {
			if it != "" && !slices.Contains(dst, it) {
				dst = append(dst, it)
			}
		}
		return dst
	}

	for _, trait := range slices.Sorted(maps.Keys(bindings)) {
		ref := bindings[trait]
		if err := validatePackageOrRelName("driver", ref); err != nil {
			return nil, nil, nil, err
		}
		dir, local, dm, err := resolveDriverDirAndManifest(in, trait, ref, fmt.Sprintf("driver '%s' (trait '%s')", ref, trait))
		if err != nil {
			return nil, nil, nil, err
		}
		var idxInfo registry.DriverInfo
		if in.Index != nil && !local {
			if info, ok := in.Index.Drivers[ref]; ok {
				idxInfo = info
			} else if !strings.HasPrefix(ref, "@") {
				if info, ok := in.Index.Drivers[path.Base(filepath.ToSlash(ref))]; ok {
					idxInfo = info
				}
			}
		}

		var dmName, dmTrait, dmVer string
		if dm != nil {
			dmName, dmTrait, dmVer = dm.Name, dm.Trait, dm.Version
		}
		if dmTrait != "" && dmTrait != trait {
			return nil, nil, nil, fmt.Errorf("driver %q declares trait %q in %s, cannot bind to trait %q", ref, dmTrait, driverManifestFile, trait)
		}
		if !local && idxInfo.Trait != "" && idxInfo.Trait != trait {
			return nil, nil, nil, fmt.Errorf("driver %q has registry trait %q, cannot bind to trait %q", ref, idxInfo.Trait, trait)
		}
		if !local && dmName != "" && idxInfo.Name != "" && dmName != idxInfo.Name {
			return nil, nil, nil, fmt.Errorf("driver %q manifest name %q does not match registry index name %q", ref, dmName, idxInfo.Name)
		}

		mocked := mode.shouldMock(trait)
		srcs, err := selectPackageSources(dir, dm, mocked, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("driver '%s' sources: %w", ref, err)
		}

		var pkgName string
		if local {
			pkgName = firstNonEmpty(dmName, ref)
		} else {
			pkgName = firstNonEmpty(idxInfo.Name, ref)
		}
		tier := registry.ClassifyTier(pkgName, idxInfo.Author, idxInfo.Tier, local)
		pkgs = append(pkgs, ResolvedDriver{
			Trait:   trait,
			Name:    pkgName,
			Dir:     dir,
			Version: firstNonEmpty(idxInfo.Version, dmVer),
			Tier:    tier,
			Local:   local,
			Mocked:  mocked,
			Sources: srcs,
		})
		dirs = appendUnique(dirs, dir)
		allSources = appendUnique(allSources, srcs...)
	}

	type legacyDriverGroup struct {
		rel   string
		files []string
	}
	var legacyGroups []legacyDriverGroup
	groupIdx := make(map[string]int)
	for _, file := range chip.driverFiles {
		if strings.Contains(file, `\`) {
			return nil, nil, nil, fmt.Errorf("invalid driver name %q: backslashes are not permitted", file)
		}
		slashFile := filepath.ToSlash(file)
		rel := path.Dir(slashFile)
		if rel == "." {
			return nil, nil, nil, fmt.Errorf("driver source '%s' must be located inside a driver directory", file)
		}
		if err := validateRelName("driver", rel); err != nil {
			return nil, nil, nil, err
		}
		baseFile := path.Base(slashFile)
		if err := manifestpkg.ValidateName("driver", baseFile); err != nil {
			return nil, nil, nil, fmt.Errorf("%w (in %q)", err, file)
		}
		leaf := path.Base(rel)
		if replacedDefaults[rel] || replacedDefaults[leaf] {
			continue
		}
		i, exists := groupIdx[rel]
		if !exists {
			i = len(legacyGroups)
			groupIdx[rel] = i
			legacyGroups = append(legacyGroups, legacyDriverGroup{rel: rel})
		}
		legacyGroups[i].files = append(legacyGroups[i].files, baseFile)
	}

	for _, grp := range legacyGroups {
		leaf := path.Base(grp.rel)
		boundIdx := -1
		for i := range pkgs {
			if pkgs[i].Name == leaf || pkgs[i].Name == grp.rel || filepath.ToSlash(pkgs[i].Dir) == filepath.ToSlash(grp.rel) {
				boundIdx = i
				break
			}
		}
		if boundIdx >= 0 {
			if len(pkgs[boundIdx].Sources) == 0 {
				fallback, err := containAll(pkgs[boundIdx].Dir, grp.files)
				if err != nil {
					return nil, nil, nil, err
				}
				pkgs[boundIdx].Sources = fallback
				allSources = appendUnique(allSources, fallback...)
			}
			continue
		}

		dir, local, dm, err := resolveDriverDirAndManifest(in, "", grp.rel, fmt.Sprintf("driver '%s'", grp.rel))
		if err != nil {
			return nil, nil, nil, err
		}
		var idxInfo registry.DriverInfo
		if in.Index != nil && !local {
			if info, ok := in.Index.Drivers[leaf]; ok {
				idxInfo = info
			}
		}
		var dmName, dmTrait, dmVer string
		if dm != nil {
			dmName, dmTrait, dmVer = dm.Name, dm.Trait, dm.Version
		}
		if !local && dmName != "" && idxInfo.Name != "" && dmName != idxInfo.Name {
			return nil, nil, nil, fmt.Errorf("driver %q manifest name %q does not match registry index name %q", grp.rel, dmName, idxInfo.Name)
		}
		effectiveTrait := firstNonEmpty(idxInfo.Trait, dmTrait, inferTraitFromRelPath(grp.rel))
		mocked := mode.shouldMock(effectiveTrait)
		srcs, err := selectPackageSources(dir, dm, mocked, grp.files)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("driver '%s' sources: %w", grp.rel, err)
		}
		var pkgName string
		if local {
			pkgName = firstNonEmpty(dmName, leaf)
		} else {
			pkgName = firstNonEmpty(idxInfo.Name, leaf)
		}
		tier := registry.ClassifyTier(pkgName, idxInfo.Author, idxInfo.Tier, local)
		pkgs = append(pkgs, ResolvedDriver{
			Trait:   effectiveTrait,
			Name:    pkgName,
			Dir:     dir,
			Version: firstNonEmpty(idxInfo.Version, dmVer),
			Tier:    tier,
			Local:   local,
			Mocked:  mocked,
			Sources: srcs,
		})
		dirs = appendUnique(dirs, dir)
		allSources = appendUnique(allSources, srcs...)
	}

	return dirs, pkgs, allSources, nil
}

// resolveChipSources resolves chip-owned translation units (startup, platform,
// and extra sources) applying per-trait *_real.c <-> *_mock.c mutual exclusion.
func resolveChipSources(chip *Chip, mode buildMode) ([]string, error) {
	if chip.Spec == nil || chip.Spec.Sources == nil {
		return nil, nil
	}
	var out []string
	appendUnique := func(p string) {
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if chip.Spec.Sources.Startup != "" {
		s, err := Contain(chip.Dir, chip.Spec.Sources.Startup)
		if err != nil {
			return nil, fmt.Errorf("startup source of chip '%s': %w", chip.Name, err)
		}
		appendUnique(s)
	}
	if chip.Spec.Sources.Platform != "" {
		p, err := Contain(chip.Dir, chip.Spec.Sources.Platform)
		if err != nil {
			return nil, fmt.Errorf("platform source of chip '%s': %w", chip.Name, err)
		}
		appendUnique(p)
	}
	for _, extra := range chip.Spec.Sources.Extra {
		ePath, err := Contain(chip.Dir, extra)
		if err != nil {
			return nil, fmt.Errorf("extra source of chip '%s': %w", chip.Name, err)
		}
		baseName := filepath.Base(extra)
		if stem, ok := strings.CutSuffix(baseName, "_real.c"); ok {
			if mode.mockAll || mode.shouldMock(stem) {
				candRel := strings.TrimSuffix(extra, "_real.c") + "_mock.c"
				cand, err := Contain(chip.Dir, candRel)
				if err != nil {
					return nil, fmt.Errorf("extra mock source of chip '%s': %w", chip.Name, err)
				}
				if fileExists(cand) {
					ePath = cand
				}
			}
		} else if stem, ok := strings.CutSuffix(baseName, "_mock.c"); ok {
			if !mode.mockAll && !mode.shouldMock(stem) {
				candRel := strings.TrimSuffix(extra, "_mock.c") + "_real.c"
				cand, err := Contain(chip.Dir, candRel)
				if err != nil {
					return nil, fmt.Errorf("extra real source of chip '%s': %w", chip.Name, err)
				}
				if fileExists(cand) {
					ePath = cand
				} else {
					continue
				}
			}
		}
		appendUnique(ePath)
	}
	return out, nil
}

// resolveCrypto resolves the backend, hash and pqc slots.
func resolveCrypto(in Input, chip *Chip, coreSDK string) ([]CryptoSlot, error) {
	var chipCrypto ports.ChipCrypto
	if chip.Spec.Crypto != nil {
		chipCrypto = *chip.Spec.Crypto
	}
	dt := in.Device.Crypto
	selection := []struct{ slot, name string }{
		{slotBackend, firstNonEmpty(dt.Backend, chipCrypto.Backend)},
		{slotHash, firstNonEmpty(dt.Hash, chipCrypto.Hash)},
		{slotPQC, firstNonEmpty(dt.Pqc, chipCrypto.Pqc)},
	}

	slots := make([]CryptoSlot, 0, len(selection))
	emitted := map[string]bool{}
	for _, s := range selection {
		if s.name == "" {
			slots = append(slots, CryptoSlot{Slot: s.slot})
			continue
		}
		resolved, err := resolveCryptoPackage(in, chip, coreSDK, s.slot, s.name)
		if err != nil {
			return nil, err
		}
		resolved.Reused = emitted[s.name]
		emitted[s.name] = true
		slots = append(slots, resolved)
	}
	return slots, nil
}

var (
	cryptoWarnFlagPattern   = regexp.MustCompile(`^-W[A-Za-z0-9_+=-]+$`)
	cryptoMacroNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	cryptoMacroValuePattern = regexp.MustCompile(`^[A-Za-z0-9_+-]+$`)

	allowedCryptoExactCflags = map[string]bool{
		"-O0": true, "-O1": true, "-O2": true, "-O3": true, "-Os": true, "-Oz": true, "-Og": true,
		"-fstrict-aliasing": true, "-fno-strict-aliasing": true,
		"-ffunction-sections": true, "-fdata-sections": true,
		"-fno-common": true, "-fomit-frame-pointer": true, "-fno-omit-frame-pointer": true,
		"-fno-builtin": true, "-fvisibility=hidden": true, "-ffreestanding": true,
		"-fPIC": true, "-fno-pic": true,
		"-std=c99": true, "-std=c11": true, "-std=c17": true, "-std=c23": true,
		"-std=gnu99": true, "-std=gnu11": true, "-std=gnu17": true,
	}
)

func validateCryptoCflag(flag string) error {
	if flag == "" || !strings.HasPrefix(flag, "-") {
		return fmt.Errorf("invalid compiler flag %q", flag)
	}
	if allowedCryptoExactCflags[flag] {
		return nil
	}
	if strings.HasPrefix(flag, "-W") {
		if strings.HasPrefix(flag, "-Wa,") || strings.HasPrefix(flag, "-Wl,") || strings.HasPrefix(flag, "-Wp,") {
			return fmt.Errorf("pass-through compiler flag %q is forbidden", flag)
		}
		if cryptoWarnFlagPattern.MatchString(flag) {
			return nil
		}
		return fmt.Errorf("disallowed warning flag %q", flag)
	}
	if def, ok := strings.CutPrefix(flag, "-D"); ok {
		name, val, hasVal := strings.Cut(def, "=")
		if !cryptoMacroNamePattern.MatchString(name) || reservedCWords[name] {
			return fmt.Errorf("invalid -D macro name in %q", flag)
		}
		upper := strings.ToUpper(name)
		if strings.HasPrefix(name, "_") || strings.HasPrefix(upper, "TOOB_") || strings.HasPrefix(upper, "BOOT_") || strings.HasPrefix(upper, "CHIP_") {
			return fmt.Errorf("reserved macro namespace in %q is forbidden", flag)
		}
		if hasVal && (val == "" || !cryptoMacroValuePattern.MatchString(val)) {
			return fmt.Errorf("unsafe -D macro value in %q", flag)
		}
		return nil
	}
	return fmt.Errorf("disallowed compiler flag %q", flag)
}

func loadOptionalCryptoManifest(dir string) (*ports.CryptoManifest, error) {
	mPath, err := Contain(dir, cryptoManifestFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(mPath); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var cm ports.CryptoManifest
	if err := decodeStrictManifestJSON(mPath, &cm); err != nil {
		return nil, err
	}
	if cm.Name != "" {
		if err := manifestpkg.ValidatePackageRef("crypto package", cm.Name); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	if cm.Version != "" {
		if err := manifestpkg.ValidateName("crypto version", cm.Version); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	if cm.AbiVersion != "" {
		if err := manifestpkg.ValidateName("crypto abi_version", cm.AbiVersion); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	for _, cat := range cm.Category {
		if err := manifestpkg.ValidateName("crypto category", cat); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	if cm.ChipBinding != "" {
		if err := manifestpkg.ValidateName("crypto chip_binding", cm.ChipBinding); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	for _, h := range cm.Headers {
		if err := validateHeaderRel(h); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(cm.Symbols)) {
		if err := manifestpkg.ValidateName("crypto symbol key", k); err != nil {
			return nil, fmt.Errorf("%s: %w", mPath, err)
		}
		sym := cm.Symbols[k]
		if !isCSymbol(sym) {
			return nil, fmt.Errorf("%s: invalid C symbol %q for %q", mPath, sym, k)
		}
	}
	return &cm, nil
}

func resolveLocalCryptoDir(root string, idx *registry.Index, slot, name string) (string, bool, error) {
	halBase := filepath.Join(root, localHalDir)
	slashName := filepath.ToSlash(name)
	var relCandidates []string
	relCandidates = append(relCandidates, path.Join("crypto", slashName))
	if slot != "" {
		relCandidates = append(relCandidates, path.Join("crypto", slot, slashName))
	}
	if idx != nil {
		if info, ok := idx.Crypto[name]; ok && info.Path != "" && !slices.Contains(relCandidates, info.Path) {
			relCandidates = append(relCandidates, info.Path)
		}
	}
	for _, relCand := range relCandidates {
		c, err := Contain(halBase, relCand)
		if err != nil {
			return "", false, fmt.Errorf("local crypto override '%s': %w", name, err)
		}
		ok, err := isDir(c)
		if err != nil {
			return "", false, err
		}
		if ok {
			return c, true, nil
		}
	}
	return "", false, nil
}

func resolveCryptoPackage(in Input, chip *Chip, coreSDK, slot, name string) (CryptoSlot, error) {
	if err := manifestpkg.ValidatePackageRef("crypto package", name); err != nil {
		return CryptoSlot{}, fmt.Errorf("crypto slot '%s': %w", slot, err)
	}

	dir, local, err := resolveLocalCryptoDir(in.Root, in.Index, slot, name)
	if err != nil {
		return CryptoSlot{}, err
	}

	var pkg registry.CryptoInfo
	var inIndex bool
	if in.Index != nil {
		pkg, inIndex = in.Index.Crypto[name]
	}

	if !local {
		if in.Index == nil {
			return CryptoSlot{}, errors.New("registry index is nil")
		}
		if !inIndex {
			return CryptoSlot{}, fmt.Errorf("crypto package '%s' (slot: %s) not found in the registry index", name, slot)
		}
		if in.Registry == nil {
			return CryptoSlot{}, errors.New("registry source is nil")
		}
		dir, err = in.Registry.CryptoSourcePath(name)
		if err != nil {
			return CryptoSlot{}, fmt.Errorf("crypto package '%s' (slot: %s) is not available: %w", name, slot, err)
		}
	}

	cm, err := loadOptionalCryptoManifest(dir)
	if err != nil {
		return CryptoSlot{}, err
	}
	// build.Load unconditionally requires crypto_manifest.json on disk for local overrides.
	if local && cm == nil {
		return CryptoSlot{}, fmt.Errorf("local crypto override '%s' (slot: %s) is missing %s", name, slot, cryptoManifestFile)
	}
	if !local && cm != nil && cm.Name != "" && pkg.Name != "" && cm.Name != pkg.Name {
		return CryptoSlot{}, fmt.Errorf("crypto package '%s' manifest name %q does not match registry index name %q", name, cm.Name, pkg.Name)
	}

	var (
		minCoreSDK      string
		chipBindings    []string
		cflags          []string
		upstreamSources []string
		includes        []string
		wrapperRel      string
	)
	if cm != nil {
		minCoreSDK = cm.MinCoreSdk
		if cm.ChipBinding != "" {
			chipBindings = []string{cm.ChipBinding}
		}
		cflags = cm.Cflags
		upstreamSources = cm.UpstreamSources
		includes = cm.Includes
		wrapperRel = cm.Wrapper
	} else {
		minCoreSDK = pkg.MinCoreSdk
		chipBindings = pkg.ChipBinding
		cflags = pkg.Cflags
		upstreamSources = pkg.UpstreamSources
		includes = pkg.Includes
		if pkg.Wrapper != nil {
			wrapperRel = *pkg.Wrapper
		}
	}

	if err := checkMinCoreSDK(fmt.Sprintf("crypto package '%s'", name), coreSDK, minCoreSDK); err != nil {
		return CryptoSlot{}, err
	}
	if len(chipBindings) > 0 && !slices.Contains(chipBindings, chip.Name) {
		return CryptoSlot{}, fmt.Errorf("crypto package '%s' is chip-bound to %v, but target chip is '%s'",
			name, chipBindings, chip.Name)
	}
	for _, flag := range cflags {
		if err := validateCryptoCflag(flag); err != nil {
			return CryptoSlot{}, fmt.Errorf("crypto package '%s' cflags: %w", name, err)
		}
	}

	// Never trust self-declared tier or author from inside an untrusted tarball.
	tier := registry.ClassifyTier(name, pkg.Author, pkg.Tier, local)
	out := CryptoSlot{Slot: slot, Name: name, Dir: dir, Tier: tier, Local: local, Cflags: cflags}
	if out.Sources, err = containAll(dir, upstreamSources); err != nil {
		return CryptoSlot{}, fmt.Errorf("crypto package '%s' upstream_sources: %w", name, err)
	}
	if out.Includes, err = containAll(dir, includes); err != nil {
		return CryptoSlot{}, fmt.Errorf("crypto package '%s' includes: %w", name, err)
	}
	if wrapperRel != "" {
		if out.Wrapper, err = Contain(dir, wrapperRel); err != nil {
			return CryptoSlot{}, fmt.Errorf("crypto package '%s' wrapper: %w", name, err)
		}
	}
	return out, nil
}

func resolveRecoveryWithMode(in Input, chip *Chip, mode buildMode, archDir, socDir string) (Recovery, error) {
	dt := in.Device
	var chipRecoveryCrypto ports.RecoveryCrypto
	if chip.recovery != nil && chip.recovery.Crypto != nil {
		chipRecoveryCrypto = *chip.recovery.Crypto
	}
	var chipCrypto ports.ChipCrypto
	if chip.Spec.Crypto != nil {
		chipCrypto = *chip.Spec.Crypto
	}

	rec := Recovery{
		Backend: firstNonEmpty(dt.Recovery.Crypto.Backend, chipRecoveryCrypto.Backend, dt.Crypto.Backend, chipCrypto.Backend),
		Hash:    firstNonEmpty(dt.Recovery.Crypto.Hash, chipRecoveryCrypto.Hash, dt.Crypto.Hash, chipCrypto.Hash),
	}
	for _, c := range []struct{ field, value string }{{"backend", rec.Backend}, {"hash", rec.Hash}} {
		if c.value == "" {
			continue
		}
		if err := manifestpkg.ValidatePackageRef("recovery crypto "+c.field, c.value); err != nil {
			return Recovery{}, err
		}
	}

	spec := chip.recovery
	if spec == nil {
		return rec, nil
	}
	rec.Declared = true

	console := firstNonEmpty(dt.Recovery.Console, spec.Console)
	flash := firstNonEmpty(dt.Recovery.Flash, spec.Flash)
	if console == "" {
		return Recovery{}, fmt.Errorf("chip '%s' manifest is missing required recovery 'console' driver mapping", chip.Name)
	}
	if flash == "" {
		return Recovery{}, fmt.Errorf("chip '%s' manifest is missing required recovery 'flash' driver mapping", chip.Name)
	}
	var err error
	rec.Drivers, rec.DriverSources, err = resolveRecoveryDrivers(in, mode,
		recoveryRole{"console", console},
		recoveryRole{"flash", flash},
		recoveryRole{"wdt", firstNonEmpty(dt.Recovery.WDT, spec.WDT)},
		recoveryRole{"clock", firstNonEmpty(dt.Recovery.Clock, spec.Clock)},
		recoveryRole{"rtc", firstNonEmpty(dt.Recovery.RTC, spec.RTC)},
	)
	if err != nil {
		return Recovery{}, err
	}
	if rec.Sources, err = recoverySources(in, chip, spec); err != nil {
		return Recovery{}, err
	}
	if rec.Includes, err = recoveryIncludes(in, chip, spec, archDir, socDir); err != nil {
		return Recovery{}, err
	}
	return rec, nil
}

type recoveryRole struct {
	trait string
	name  string
}

func resolveRecoveryDrivers(in Input, mode buildMode, roles ...recoveryRole) ([]string, []string, error) {
	var dirs []string
	var drvSources []string
	for _, role := range roles {
		if role.name == "" {
			continue
		}
		if err := validatePackageOrRelName("recovery driver", role.name); err != nil {
			return nil, nil, err
		}
		dir, _, dm, err := resolveDriverDirAndManifest(in, role.trait, role.name, fmt.Sprintf("recovery driver '%s'", role.name))
		if err != nil {
			return nil, nil, err
		}
		if !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
		mocked := mode.shouldMock(role.trait) || (dm != nil && dm.Trait != "" && mode.shouldMock(dm.Trait))
		srcs, err := selectPackageSources(dir, dm, mocked, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("recovery driver '%s' sources: %w", role.name, err)
		}
		for _, s := range srcs {
			if !slices.Contains(drvSources, s) {
				drvSources = append(drvSources, s)
			}
		}
	}
	return dirs, drvSources, nil
}

func recoverySources(in Input, chip *Chip, spec *ports.ChipRecovery) ([]string, error) {
	fromChip, err := containAll(chip.Dir, spec.Sources)
	if err != nil {
		return nil, fmt.Errorf("recovery sources of chip '%s': %w", chip.Name, err)
	}
	fromProject, err := containAll(in.Root, in.Device.Recovery.Sources)
	if err != nil {
		return nil, fmt.Errorf("device.toml [recovery] sources: %w", err)
	}
	return append(fromChip, fromProject...), nil
}

func recoveryIncludes(in Input, chip *Chip, spec *ports.ChipRecovery, archDir, socDir string) ([]string, error) {
	shared, err := chipIncludesWithFallback(in, chip, archDir, socDir)
	if err != nil {
		return nil, err
	}
	fromChip, err := containAll(chip.Dir, spec.Includes)
	if err != nil {
		return nil, fmt.Errorf("recovery includes of chip '%s': %w", chip.Name, err)
	}
	fromProject, err := containAll(in.Root, in.Device.Recovery.Includes)
	if err != nil {
		return nil, fmt.Errorf("device.toml [recovery] includes: %w", err)
	}
	return slices.Concat(shared, fromChip, fromProject), nil
}

// chipIncludesWithFallback resolves includes of chip_manifest.json. When a chip
// is spawned locally (<root>/toobloader/hal/chips/<chip>), soc/, arch/, and drivers/
// entries that were not spawned locally fall back cleanly to the registry cache.
func chipIncludesWithFallback(in Input, chip *Chip, archDir, socDir string) ([]string, error) {
	halRoot := filepath.Join(chip.Dir, "..", "..")
	out := make([]string, 0, len(chip.Spec.Includes))
	for _, inc := range chip.Spec.Includes {
		isShared := strings.HasPrefix(inc, "soc/") || strings.HasPrefix(inc, "arch/") || strings.HasPrefix(inc, "drivers/")
		base := chip.Dir
		if isShared {
			base = halRoot
		}
		joined, err := Contain(base, inc)
		if err != nil {
			return nil, fmt.Errorf("includes of chip '%s': %w", chip.Name, err)
		}
		if chip.Local && isShared {
			if _, statErr := os.Stat(joined); errors.Is(statErr, fs.ErrNotExist) {
				if fb, ok := resolveRegistryIncludeFallback(in, inc, archDir, socDir); ok {
					joined = fb
				}
			}
		}
		out = append(out, joined)
	}
	return out, nil
}

func resolveRegistryIncludeFallback(in Input, inc, archDir, socDir string) (string, bool) {
	if strings.HasPrefix(inc, "soc/") && socDir != "" {
		if cand, err := Contain(filepath.Dir(socDir), inc); err == nil {
			if _, statErr := os.Stat(cand); statErr == nil {
				return cand, true
			}
		}
		if sub := strings.TrimPrefix(inc, "soc/"); sub != "" {
			if cand, err := Contain(socDir, sub); err == nil {
				if _, statErr := os.Stat(cand); statErr == nil {
					return cand, true
				}
			}
		}
	}
	if strings.HasPrefix(inc, "arch/") && archDir != "" {
		if cand, err := Contain(filepath.Join(archDir, "..", ".."), inc); err == nil {
			if _, statErr := os.Stat(cand); statErr == nil {
				return cand, true
			}
		}
	}
	if strings.HasPrefix(inc, "drivers/") && in.Registry != nil {
		if drvDir, err := in.Registry.DriverSourcePath(inc); err == nil {
			if _, statErr := os.Stat(drvDir); statErr == nil {
				return drvDir, true
			}
		}
		if archDir != "" {
			if cand, err := Contain(filepath.Join(archDir, "..", ".."), inc); err == nil {
				if _, statErr := os.Stat(cand); statErr == nil {
					return cand, true
				}
			}
		}
	}
	return "", false
}

func containAll(base string, rels []string) ([]string, error) {
	out := make([]string, 0, len(rels))
	for _, rel := range rels {
		joined, err := Contain(base, rel)
		if err != nil {
			return nil, err
		}
		out = append(out, joined)
	}
	return out, nil
}
