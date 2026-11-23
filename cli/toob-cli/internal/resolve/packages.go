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
	"github.com/toob-boot/toob/internal/paths"
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
	socManifestFile    = "soc_manifest.json"
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

func isCryptoDisabled(name string) bool {
	trimmed := strings.TrimSpace(name)
	return trimmed == "" || strings.EqualFold(trimmed, "none")
}

func normalizeRecoveryCryptoRef(name string) string {
	trimmed := strings.TrimSpace(name)
	switch {
	case strings.EqualFold(trimmed, "none"):
		return "none"
	case strings.EqualFold(trimmed, "rom"):
		return "rom"
	default:
		return trimmed
	}
}

func loadOptionalDriverManifest(dir string) (*manifestpkg.DriverManifest, error) {
	mPath, err := Contain(dir, driverManifestFile)
	if err != nil {
		return nil, err
	}
	if _, statErr := os.Lstat(mPath); errors.Is(statErr, fs.ErrNotExist) {
		return nil, nil
	}
	var dm manifestpkg.DriverManifest
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
func selectPackageSources(dir string, dm *manifestpkg.DriverManifest, mocked bool, fallbackRelFiles []string) ([]string, error) {
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

func resolveLocalDriverDir(in Input, trait, ref string) (string, bool, error) {
	halBase := localHALRoot(in)
	slashRef := filepath.ToSlash(ref)
	var relCandidates []string
	if strings.HasPrefix(slashRef, "drivers/") {
		relCandidates = append(relCandidates, slashRef)
	} else {
		relCandidates = append(relCandidates, path.Join("drivers", slashRef))
		if trait != "" {
			relCandidates = append(relCandidates, path.Join("drivers", trait, slashRef))
		}
	}
	if in.Index != nil {
		for _, k := range []string{ref, path.Base(slashRef)} {
			if info, ok := in.Index.Drivers[k]; ok && info.Path != "" && !slices.Contains(relCandidates, info.Path) {
				relCandidates = append(relCandidates, info.Path)
			}
		}
	}
	for _, relCand := range relCandidates {
		c, err := Contain(halBase, relCand)
		if err != nil {
			return "", false, fmt.Errorf("local driver override '%s': %w", ref, err)
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

func resolveDriverDirAndManifest(in Input, trait, ref, role string) (string, bool, *manifestpkg.DriverManifest, error) {
	dir, local, err := resolveLocalDriverDir(in, trait, ref)
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

func lookupDriverIndexInfo(idx *registry.Index, local bool, ref string) registry.DriverInfo {
	if idx == nil || local {
		return registry.DriverInfo{}
	}
	if info, ok := idx.Drivers[ref]; ok {
		return info
	}
	if !strings.HasPrefix(ref, "@") {
		if info, ok := idx.Drivers[path.Base(filepath.ToSlash(ref))]; ok {
			return info
		}
	}
	return registry.DriverInfo{}
}

// resolveDriverPackages merges chip hal_bindings, device.toml [drivers] overrides,
// and legacy sources.drivers, filtering bound and "none" traits before legacy resolution.
func resolveDriverPackages(in Input, chip *Chip, mode buildMode, contract *halContractSpec) ([]string, []ResolvedDriver, []string, error) {
	bindings := make(map[string]string, len(chip.halBindings)+len(in.Device.Drivers))
	for _, trait := range slices.Sorted(maps.Keys(chip.halBindings)) {
		if err := manifestpkg.ValidateName("driver trait", trait); err != nil {
			return nil, nil, nil, fmt.Errorf("chip '%s' hal_bindings: %w", chip.Name, err)
		}
		bindings[trait] = chip.halBindings[trait]
	}

	replacedDefaults := make(map[string]bool)
	disabledTraits := make(map[string]bool)
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
			disabledTraits[strings.ToLower(trait)] = true
			continue
		}
		if err := validatePackageOrRelName("driver", ref); err != nil {
			return nil, nil, nil, fmt.Errorf("device.toml [drivers.%s]: %w", trait, err)
		}
		bindings[trait] = ref
	}

	isTraitBoundOrDisabled := func(candidateTrait string) bool {
		if candidateTrait == "" {
			return false
		}
		for boundTrait := range bindings {
			if contract.traitMatches(boundTrait, candidateTrait) {
				return true
			}
		}
		for disabledTrait := range disabledTraits {
			if contract.traitMatches(disabledTrait, candidateTrait) {
				return true
			}
		}
		return false
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
		idxInfo := lookupDriverIndexInfo(in.Index, local, ref)

		var dmName, dmTrait, dmVer, dmLicense string
		var refCtx *manifestpkg.ReferenceBuildContext
		if dm != nil {
			dmName, dmTrait, dmVer, dmLicense = dm.Name, dm.Trait, dm.Version, dm.License
			refCtx = dm.ReferenceBuildContext
		}
		if dmTrait != "" && !contract.traitMatches(trait, dmTrait) {
			return nil, nil, nil, fmt.Errorf("driver %q declares trait %q in %s, cannot bind to trait %q", ref, dmTrait, driverManifestFile, trait)
		}
		if !local && idxInfo.Trait != "" && !contract.traitMatches(trait, idxInfo.Trait) {
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
			Trait:                 trait,
			Name:                  pkgName,
			Dir:                   dir,
			Version:               firstNonEmpty(idxInfo.Version, dmVer),
			Tier:                  tier,
			Local:                 local,
			Mocked:                mocked,
			SHA256:                firstNonEmpty(idxInfo.SHA256, idxInfo.TarballSHA),
			License:               dmLicense,
			ReferenceBuildContext: refCtx,
			Sources:               srcs,
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

		preIdx := lookupDriverIndexInfo(in.Index, false, grp.rel)
		if preIdx.Name == "" {
			preIdx = lookupDriverIndexInfo(in.Index, false, leaf)
		}
		if isTraitBoundOrDisabled(preIdx.Trait) {
			continue
		}

		dir, local, dm, err := resolveDriverDirAndManifest(in, preIdx.Trait, grp.rel, fmt.Sprintf("driver '%s'", grp.rel))
		if err != nil {
			return nil, nil, nil, err
		}
		idxInfo := lookupDriverIndexInfo(in.Index, local, grp.rel)
		if idxInfo.Name == "" && !local {
			idxInfo = lookupDriverIndexInfo(in.Index, false, leaf)
		}
		var dmName, dmTrait, dmVer, dmLicense string
		var refCtx *manifestpkg.ReferenceBuildContext
		if dm != nil {
			dmName, dmTrait, dmVer, dmLicense = dm.Name, dm.Trait, dm.Version, dm.License
			refCtx = dm.ReferenceBuildContext
		}
		if !local && dmName != "" && idxInfo.Name != "" && dmName != idxInfo.Name {
			return nil, nil, nil, fmt.Errorf("driver %q manifest name %q does not match registry index name %q", grp.rel, dmName, idxInfo.Name)
		}
		effectiveTrait := firstNonEmpty(idxInfo.Trait, dmTrait)
		if isTraitBoundOrDisabled(effectiveTrait) {
			continue
		}
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
			Trait:                 effectiveTrait,
			Name:                  pkgName,
			Dir:                   dir,
			Version:               firstNonEmpty(idxInfo.Version, dmVer),
			Tier:                  tier,
			Local:                 local,
			Mocked:                mocked,
			SHA256:                firstNonEmpty(idxInfo.SHA256, idxInfo.TarballSHA),
			License:               dmLicense,
			ReferenceBuildContext: refCtx,
			Sources:               srcs,
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
				if !fileExists(cand) {
					continue
				}
				ePath = cand
			}
		}
		appendUnique(ePath)
	}
	return out, nil
}

// resolveCrypto resolves Stage-1 backend, hash, and pqc crypto slots.
func resolveCrypto(in Input, chip *Chip, coreSDK string) ([]CryptoSlot, error) {
	var chipCrypto manifestpkg.ChipCrypto
	if chip.Spec != nil && chip.Spec.Crypto != nil {
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
		if isCryptoDisabled(s.name) {
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

func loadOptionalCryptoManifest(dir string) (*manifestpkg.CryptoManifest, error) {
	mPath, err := Contain(dir, cryptoManifestFile)
	if err != nil {
		return nil, err
	}
	if _, statErr := os.Lstat(mPath); errors.Is(statErr, fs.ErrNotExist) {
		return nil, nil
	}
	var cm manifestpkg.CryptoManifest
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
	for _, binding := range cm.ChipBindings() {
		if err := manifestpkg.ValidatePackageRef("crypto chip_binding", binding); err != nil {
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

func resolveLocalCryptoDir(in Input, slot, name string) (string, bool, error) {
	halBase := localHALRoot(in)
	slashName := filepath.ToSlash(name)
	var relCandidates []string
	relCandidates = append(relCandidates, path.Join("crypto", slashName))
	if slot != "" {
		baseSlot := strings.TrimPrefix(slot, "recovery_")
		relCandidates = append(relCandidates, path.Join("crypto", baseSlot, slashName))
	}
	if in.Index != nil {
		if info, ok := in.Index.Crypto[name]; ok && info.Path != "" && !slices.Contains(relCandidates, info.Path) {
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

func requiredCategoryForSlot(slot string) string {
	switch strings.ToLower(strings.TrimSpace(slot)) {
	case slotBackend, "recovery_backend":
		return slotBackend
	case slotHash, "recovery_hash":
		return slotHash
	case slotPQC:
		return slotPQC
	default:
		return strings.ToLower(strings.TrimSpace(slot))
	}
}

func resolveCryptoPackage(in Input, chip *Chip, coreSDK, slot, name string) (CryptoSlot, error) {
	if err := manifestpkg.ValidatePackageRef("crypto package", name); err != nil {
		return CryptoSlot{}, fmt.Errorf("crypto slot '%s': %w", slot, err)
	}

	dir, local, err := resolveLocalCryptoDir(in, slot, name)
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
	if local && cm == nil {
		return CryptoSlot{}, fmt.Errorf("local crypto override '%s' (slot: %s) is missing %s", name, slot, cryptoManifestFile)
	}
	if !local && cm != nil && cm.Name != "" && pkg.Name != "" && cm.Name != pkg.Name {
		return CryptoSlot{}, fmt.Errorf("crypto package '%s' manifest name %q does not match registry index name %q", name, cm.Name, pkg.Name)
	}

	var (
		minCoreSDK      string
		categories      []string
		chipBindings    []string
		cflags          []string
		upstreamSources []string
		includes        []string
		wrapperRel      string
		version         string
		license         string
		refCtx          *manifestpkg.ReferenceBuildContext
	)
	if cm != nil {
		minCoreSDK = cm.MinCoreSdk
		categories = cm.Category
		chipBindings = cm.ChipBindings()
		cflags = cm.Cflags
		upstreamSources = cm.UpstreamSources
		includes = cm.Includes
		wrapperRel = cm.Wrapper
		version = cm.Version
		license = cm.License
		refCtx = cm.ReferenceBuildContext
	} else {
		minCoreSDK = pkg.MinCoreSdk
		categories = pkg.Category
		chipBindings = pkg.ChipBinding
		cflags = pkg.Cflags
		upstreamSources = pkg.UpstreamSources
		includes = pkg.Includes
		if pkg.Wrapper != nil {
			wrapperRel = *pkg.Wrapper
		}
		version = pkg.Version
		license = pkg.License
	}
	if len(categories) == 0 && len(pkg.Category) > 0 {
		categories = pkg.Category
	}
	if version == "" {
		version = pkg.Version
	}
	if license == "" {
		license = pkg.License
	}

	wantCat := requiredCategoryForSlot(slot)
	if len(categories) > 0 && !slices.ContainsFunc(categories, func(c string) bool {
		return strings.EqualFold(strings.TrimSpace(c), wantCat)
	}) {
		return CryptoSlot{}, fmt.Errorf("crypto package '%s' declares category %v, cannot satisfy slot '%s'",
			name, categories, slot)
	}

	if minErr := checkMinCoreSDK(fmt.Sprintf("crypto package '%s'", name), coreSDK, minCoreSDK); minErr != nil {
		return CryptoSlot{}, minErr
	}
	if len(chipBindings) > 0 && !slices.Contains(chipBindings, chip.Name) {
		return CryptoSlot{}, fmt.Errorf("crypto package '%s' is chip-bound to %v, but target chip is '%s'",
			name, chipBindings, chip.Name)
	}
	for _, flag := range cflags {
		if flagErr := validateCryptoCflag(flag); flagErr != nil {
			return CryptoSlot{}, fmt.Errorf("crypto package '%s' cflags: %w", name, flagErr)
		}
	}

	// Never trust self-declared tier or author from inside an untrusted tarball.
	tier := registry.ClassifyTier(name, pkg.Author, pkg.Tier, local)
	out := CryptoSlot{
		Slot:                  slot,
		Name:                  name,
		Dir:                   dir,
		Version:               version,
		Tier:                  tier,
		Local:                 local,
		SHA256:                firstNonEmpty(pkg.SHA256, pkg.TarballSHA),
		License:               license,
		ReferenceBuildContext: refCtx,
		Cflags:                cflags,
	}
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

func resolveRecoveryWithMode(in Input, chip *Chip, mode buildMode, archDir, socDir string, contract *halContractSpec) (Recovery, error) {
	dt := in.Device
	var chipRecoveryCrypto manifestpkg.RecoveryCrypto
	if chip.recovery != nil && chip.recovery.Crypto != nil {
		chipRecoveryCrypto = *chip.recovery.Crypto
	}
	var chipCrypto manifestpkg.ChipCrypto
	if chip.Spec != nil && chip.Spec.Crypto != nil {
		chipCrypto = *chip.Spec.Crypto
	}

	rec := Recovery{
		Backend: normalizeRecoveryCryptoRef(firstNonEmpty(dt.Recovery.Crypto.Backend, chipRecoveryCrypto.Backend, dt.Crypto.Backend, chipCrypto.Backend)),
		Hash:    normalizeRecoveryCryptoRef(firstNonEmpty(dt.Recovery.Crypto.Hash, chipRecoveryCrypto.Hash, dt.Crypto.Hash, chipCrypto.Hash)),
	}
	for _, c := range []struct{ field, value string }{{"backend", rec.Backend}, {"hash", rec.Hash}} {
		if c.value == "" || c.value == "none" || c.value == "rom" {
			continue
		}
		if err := manifestpkg.ValidatePackageRef("recovery crypto "+c.field, c.value); err != nil {
			return Recovery{}, err
		}
	}

	devHasRecovery := dt.Recovery.Console != "" || dt.Recovery.Flash != "" ||
		dt.Recovery.WDT != "" || dt.Recovery.Clock != "" || dt.Recovery.RTC != "" ||
		dt.Recovery.Crypto.Backend != "" || dt.Recovery.Crypto.Hash != "" ||
		len(dt.Recovery.Sources) > 0 || len(dt.Recovery.Includes) > 0

	spec := chip.recovery
	if spec == nil && !devHasRecovery {
		return rec, nil
	}
	if spec == nil {
		spec = &manifestpkg.ChipRecovery{}
	}
	rec.Declared = true

	cleanRecoveryRef := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if strings.EqualFold(trimmed, "none") {
			return ""
		}
		return trimmed
	}

	console := cleanRecoveryRef(firstNonEmpty(dt.Recovery.Console, spec.Console))
	flash := cleanRecoveryRef(firstNonEmpty(dt.Recovery.Flash, spec.Flash))
	wdt := cleanRecoveryRef(firstNonEmpty(dt.Recovery.WDT, spec.WDT))
	clock := cleanRecoveryRef(firstNonEmpty(dt.Recovery.Clock, spec.Clock))
	confirm := cleanRecoveryRef(firstNonEmpty(dt.Recovery.RTC, spec.RTC))

	hasDriversOrSources := console != "" || flash != "" || wdt != "" || clock != "" || confirm != "" ||
		len(spec.Sources) > 0 || len(dt.Recovery.Sources) > 0
	if chip.recovery != nil || hasDriversOrSources {
		if console == "" {
			return Recovery{}, fmt.Errorf("chip '%s' manifest is missing required recovery 'console' driver mapping", chip.Name)
		}
		if flash == "" {
			return Recovery{}, fmt.Errorf("chip '%s' manifest is missing required recovery 'flash' driver mapping", chip.Name)
		}
	}

	var err error
	roles := []recoveryRole{
		{trait: "console", name: console},
		{trait: "flash", name: flash},
		{trait: "wdt", name: wdt},
		{trait: "clock", name: clock},
		{trait: "confirm", name: confirm},
	}
	rec.Drivers, rec.DriverPackages, rec.DriverSources, err = resolveRecoveryDrivers(in, mode, contract, roles...)
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

func resolveRecoveryDrivers(in Input, mode buildMode, contract *halContractSpec, roles ...recoveryRole) ([]string, []ResolvedDriver, []string, error) {
	var dirs []string
	var pkgs []ResolvedDriver
	var drvSources []string
	for _, role := range roles {
		if role.name == "" {
			continue
		}
		if err := validatePackageOrRelName("recovery driver", role.name); err != nil {
			return nil, nil, nil, err
		}
		dir, local, dm, err := resolveDriverDirAndManifest(in, role.trait, role.name, fmt.Sprintf("recovery driver '%s'", role.name))
		if err != nil {
			return nil, nil, nil, err
		}
		idxInfo := lookupDriverIndexInfo(in.Index, local, role.name)

		var dmName, dmTrait, dmVer, dmLicense string
		var refCtx *manifestpkg.ReferenceBuildContext
		if dm != nil {
			dmName, dmTrait, dmVer, dmLicense = dm.Name, dm.Trait, dm.Version, dm.License
			refCtx = dm.ReferenceBuildContext
		}
		if dmTrait != "" && !contract.traitMatches(role.trait, dmTrait) {
			return nil, nil, nil, fmt.Errorf("recovery driver %q declares trait %q in %s, cannot bind to recovery trait %q",
				role.name, dmTrait, driverManifestFile, role.trait)
		}
		if !local && idxInfo.Trait != "" && !contract.traitMatches(role.trait, idxInfo.Trait) {
			return nil, nil, nil, fmt.Errorf("recovery driver %q has registry trait %q, cannot bind to recovery trait %q",
				role.name, idxInfo.Trait, role.trait)
		}
		if !local && dmName != "" && idxInfo.Name != "" && dmName != idxInfo.Name {
			return nil, nil, nil, fmt.Errorf("recovery driver %q manifest name %q does not match registry index name %q",
				role.name, dmName, idxInfo.Name)
		}

		if !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
		mocked := mode.shouldMock(role.trait) || (dmTrait != "" && mode.shouldMock(dmTrait))
		srcs, err := selectPackageSources(dir, dm, mocked, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("recovery driver '%s' sources: %w", role.name, err)
		}
		for _, s := range srcs {
			if !slices.Contains(drvSources, s) {
				drvSources = append(drvSources, s)
			}
		}

		pkgName := firstNonEmpty(idxInfo.Name, dmName, path.Base(filepath.ToSlash(role.name)))
		if local {
			pkgName = firstNonEmpty(dmName, path.Base(filepath.ToSlash(role.name)))
		}
		tier := registry.ClassifyTier(pkgName, idxInfo.Author, idxInfo.Tier, local)
		pkgs = append(pkgs, ResolvedDriver{
			Trait:                 role.trait,
			Name:                  pkgName,
			Dir:                   dir,
			Version:               firstNonEmpty(idxInfo.Version, dmVer),
			Tier:                  tier,
			Local:                 local,
			Mocked:                mocked,
			SHA256:                firstNonEmpty(idxInfo.SHA256, idxInfo.TarballSHA),
			License:               dmLicense,
			ReferenceBuildContext: refCtx,
			Sources:               srcs,
		})
	}
	return dirs, pkgs, drvSources, nil
}

func recoverySources(in Input, chip *Chip, spec *manifestpkg.ChipRecovery) ([]string, error) {
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

func recoveryIncludes(in Input, chip *Chip, spec *manifestpkg.ChipRecovery, archDir, socDir string) ([]string, error) {
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

func resolveHALRoot(in Input, chip *Chip) string {
	if in.HalRoot != "" {
		return in.HalRoot
	}
	if chip != nil && chip.Local && in.Root != "" {
		return paths.HALDir(in.Root)
	}
	if dirProvider, ok := in.Registry.(interface{ Dir() string }); ok && dirProvider.Dir() != "" {
		base := dirProvider.Dir()
		pkgSub := filepath.Join(base, "packages")
		if st, err := os.Stat(pkgSub); err == nil && st.IsDir() {
			return pkgSub
		}
		return base
	}
	if in.Root != "" {
		hal := paths.HALDir(in.Root)
		if st, err := os.Stat(hal); err == nil && st.IsDir() {
			return hal
		}
	}
	return ""
}

// chipIncludesWithFallback resolves includes of chip_manifest.json explicitly
// from HalRoot, Arch, SoC, or Registry without relative '..' parent-walking guesses.
func chipIncludesWithFallback(in Input, chip *Chip, archDir, socDir string) ([]string, error) {
	if chip.Spec == nil {
		return nil, nil
	}
	halRoot := resolveHALRoot(in, chip)
	localHal := ""
	if in.Root != "" {
		localHal = paths.HALDir(in.Root)
	}

	out := make([]string, 0, len(chip.Spec.Includes))
	for _, inc := range chip.Spec.Includes {
		isShared := strings.HasPrefix(inc, "soc/") || strings.HasPrefix(inc, "arch/") || strings.HasPrefix(inc, "drivers/")
		if !isShared {
			joined, err := Contain(chip.Dir, inc)
			if err != nil {
				return nil, fmt.Errorf("includes of chip '%s': %w", chip.Name, err)
			}
			out = append(out, joined)
			continue
		}

		// Local project override under <root>/toobloader/hal takes precedence when present.
		if chip.Local && localHal != "" {
			localCand, err := Contain(localHal, inc)
			if err != nil {
				return nil, fmt.Errorf("includes of chip '%s': %w", chip.Name, err)
			}
			if _, statErr := os.Stat(localCand); statErr == nil {
				out = append(out, localCand)
				continue
			}
		}

		resolved, err := resolveSharedInclude(in, chip, inc, halRoot, archDir, socDir)
		if err != nil {
			return nil, fmt.Errorf("includes of chip '%s': %w", chip.Name, err)
		}
		out = append(out, resolved)
	}
	return out, nil
}

func resolveSharedInclude(in Input, chip *Chip, inc, halRoot, archDir, socDir string) (string, error) {
	switch {
	case strings.HasPrefix(inc, "soc/"):
		if socResolver, ok := in.Registry.(interface {
			ResolveSoCInclude(string) (string, string, string, error)
		}); ok {
			_, incDir, _, err := socResolver.ResolveSoCInclude(inc)
			if err != nil {
				return "", fmt.Errorf("resolving SoC include %q: %w", inc, err)
			}
			return incDir, nil
		}
		if socDir != "" {
			if sub := strings.TrimPrefix(inc, "soc/"); sub != "" {
				if cand, err := Contain(socDir, sub); err == nil {
					if _, statErr := os.Stat(cand); statErr == nil {
						return cand, nil
					}
				}
			}
		}
	case strings.HasPrefix(inc, "arch/") && archDir != "":
		prefix := "arch/" + chip.Arch + "/"
		if rel, ok := strings.CutPrefix(inc, prefix); ok && rel != "" {
			if cand, err := Contain(archDir, rel); err == nil {
				if _, statErr := os.Stat(cand); statErr == nil {
					return cand, nil
				}
			}
		}
	case strings.HasPrefix(inc, "drivers/") && in.Registry != nil:
		if drvDir, err := in.Registry.DriverSourcePath(inc); err == nil {
			if _, statErr := os.Stat(drvDir); statErr == nil {
				return drvDir, nil
			}
		}
	}

	if halRoot == "" {
		return "", fmt.Errorf("cannot resolve shared include %q: HAL root is not configured", inc)
	}
	return Contain(halRoot, inc)
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
