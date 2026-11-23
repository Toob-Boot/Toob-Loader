package resolve

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	build "github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
)

const (
	hardwareFile     = "hardware.json"
	chipManifestFile = "chip_manifest.json"
	archManifestFile = "arch_manifest.json"
)

// localHalDir is the project-relative root of locally overridden HAL packages.
var localHalDir = filepath.Join("toobloader", "hal")

// resolveChip locates the chip package once. A chip directory inside the
// project replaces the registry package completely; local and registry
// chip_manifest.json are authoritative and never overwritten by index metadata.
func resolveChip(in Input) (*Chip, error) {
	if in.Device == nil {
		return nil, errors.New("device.toml input is nil")
	}
	name := in.Device.Device.Chip
	if name == "" {
		return nil, errors.New("device.toml must define [device] with 'chip'")
	}
	if err := manifestpkg.ValidatePackageRef("chip", name); err != nil {
		return nil, fmt.Errorf("device.toml [device] chip: %w", err)
	}

	halBase := localHALRoot(in)
	dir, err := Contain(halBase, filepath.FromSlash(path.Join("chips", name)))
	if err != nil {
		return nil, fmt.Errorf("local chip override '%s': %w", name, err)
	}
	local, err := isDir(dir)
	if err != nil {
		return nil, err
	}
	if !local {
		if in.Registry == nil {
			return nil, errors.New("registry source is nil")
		}
		if dir, err = in.Registry.ChipSourcePath(name); err != nil {
			return nil, fmt.Errorf("failed to resolve chip '%s' from registry: %w", name, err)
		}
	}

	hwPath, err := Contain(dir, hardwareFile)
	if err != nil {
		return nil, fmt.Errorf("chip '%s': %w", name, err)
	}
	manifestPath, err := Contain(dir, chipManifestFile)
	if err != nil {
		return nil, fmt.Errorf("chip '%s': %w", name, err)
	}
	chip := &Chip{
		Name:         name,
		Dir:          dir,
		Local:        local,
		HardwarePath: hwPath,
		ManifestPath: manifestPath,
	}
	for _, file := range []string{chip.HardwarePath, chip.ManifestPath} {
		st, statErr := os.Lstat(file)
		if statErr != nil {
			return nil, fmt.Errorf("chip '%s' is incomplete (local override: %v): %w", name, local, statErr)
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("chip '%s' file %s must be a regular file", name, file)
		}
	}
	if loadErr := loadChipManifest(chip); loadErr != nil {
		return nil, loadErr
	}
	copros, err := loadChipCoprocessors(chip.HardwarePath)
	if err != nil {
		return nil, fmt.Errorf("chip '%s' %s: %w", name, hardwareFile, err)
	}
	chip.coprocessors = copros
	chip.halBindings, chip.driverFiles, chip.recovery = chipPackageEntries(in.Index, chip)

	var author, explicitTier string
	if !chip.Local && in.Index != nil {
		if info, ok := in.Index.Chips[chip.Name]; ok {
			author, explicitTier = info.Author, info.Tier
			chip.SHA256 = firstNonEmpty(info.SHA256, info.TarballSHA)
		}
	}
	chip.Tier = registry.ClassifyTier(chip.Name, author, explicitTier, chip.Local)
	return chip, nil
}

func localHALRoot(in Input) string {
	if in.HalRoot != "" {
		return in.HalRoot
	}
	return filepath.Join(in.Root, localHalDir)
}

func loadChipManifest(chip *Chip) error {
	var spec manifestpkg.ChipManifest
	if err := decodeStrictManifestJSON(chip.ManifestPath, &spec); err != nil {
		return err
	}
	if spec.Name != "" {
		if err := manifestpkg.ValidatePackageRef("chip", spec.Name); err != nil {
			return fmt.Errorf("%s: %w", chip.ManifestPath, err)
		}
		if !strings.EqualFold(spec.Name, chip.Name) {
			return fmt.Errorf("%s: chip name %q does not match requested chip %q", chip.ManifestPath, spec.Name, chip.Name)
		}
	}
	if spec.Arch == "" {
		return fmt.Errorf("%s of chip '%s' is missing required 'arch'", chipManifestFile, chip.Name)
	}
	if err := manifestpkg.ValidatePackageRef("arch", spec.Arch); err != nil {
		return fmt.Errorf("%s: %w", chip.ManifestPath, err)
	}
	if spec.CompilerPrefix != "" {
		trimmedPrefix := strings.TrimSuffix(spec.CompilerPrefix, "-")
		if err := validatePackageOrRelName("compiler prefix", trimmedPrefix); err != nil {
			return fmt.Errorf("%s: %w", chip.ManifestPath, err)
		}
	}
	if spec.Version == "" {
		return fmt.Errorf("%s of chip '%s' is missing required 'version'", chipManifestFile, chip.Name)
	}
	if err := manifestpkg.ValidateName("chip version", spec.Version); err != nil {
		return fmt.Errorf("%s: %w", chip.ManifestPath, err)
	}
	if spec.MinCompiler != "" {
		if strings.EqualFold(strings.TrimSpace(spec.MinCompiler), "latest") {
			return fmt.Errorf("%s: min_compiler = \"latest\" is forbidden (REG-009); specify a concrete compiler version", chip.ManifestPath)
		}
		if _, err := ExtractCompilerSemver(spec.MinCompiler); err != nil {
			return fmt.Errorf("%s: invalid min_compiler %q: %w", chip.ManifestPath, spec.MinCompiler, err)
		}
	}
	if err := build.ValidateCompilerFlags(chip.ManifestPath, spec.CompilerFlags); err != nil {
		return fmt.Errorf("%s compiler_flags: %w", chip.ManifestPath, err)
	}
	if spec.Sources != nil {
		for _, entry := range []struct{ field, rel string }{
			{"sources.startup", spec.Sources.Startup},
			{"sources.platform", spec.Sources.Platform},
			{"sources.config", spec.Sources.Config},
			{"sources.linker", spec.Sources.Linker},
			{"sources.hardware", spec.Sources.Hardware},
		} {
			if entry.rel != "" {
				if _, err := Contain(chip.Dir, entry.rel); err != nil {
					return fmt.Errorf("%s %s: %w", chip.ManifestPath, entry.field, err)
				}
			}
		}
		for _, extra := range spec.Sources.Extra {
			if _, err := Contain(chip.Dir, extra); err != nil {
				return fmt.Errorf("%s sources.extra: %w", chip.ManifestPath, err)
			}
		}
	}

	chip.Spec = &spec
	chip.Arch = spec.Arch
	chip.Prefix = spec.CompilerPrefix
	chip.Version = spec.Version
	chip.License = spec.License
	chip.ReferenceBuildContext = spec.ReferenceBuildContext
	return nil
}

func loadChipCoprocessors(hwPath string) ([]manifestpkg.Coprocessor, error) {
	var partial struct {
		MultiCore *manifestpkg.MultiCore `json:"multi_core"`
	}
	if err := decodeJSONFile(hwPath, &partial, false); err != nil {
		return nil, err
	}
	if partial.MultiCore == nil || len(partial.MultiCore.Coprocessors) == 0 {
		return nil, nil
	}
	return slices.Clone(partial.MultiCore.Coprocessors), nil
}

// chipPackageEntries reads hal_bindings, sources.drivers, and recovery authoritatively
// from chip_manifest.json; for registry chips, index metadata only supplies fields omitted
// by the manifest itself and never overwrites chip_manifest.json values.
func chipPackageEntries(idx *registry.Index, chip *Chip) (map[string]string, []string, *manifestpkg.ChipRecovery) {
	var bindings map[string]string
	var drivers []string
	var recovery *manifestpkg.ChipRecovery

	if chip.Spec != nil {
		bindings = chip.Spec.HalBindings
		if chip.Spec.Sources != nil {
			drivers = chip.Spec.Sources.Drivers
		}
		recovery = chip.Spec.Recovery
	}

	if !chip.Local && idx != nil {
		if info, ok := idx.Chips[chip.Name]; ok {
			if len(bindings) == 0 && len(info.HalBindings) > 0 {
				bindings = info.HalBindings
			}
			if len(drivers) == 0 && info.Sources != nil && len(info.Sources.Drivers) > 0 {
				drivers = info.Sources.Drivers
			}
			if recovery == nil && info.Recovery != nil {
				recovery = recoveryFromIndex(info.Recovery)
			}
		}
	}
	return bindings, drivers, recovery
}

func recoveryFromIndex(r *registry.ChipRecovery) *manifestpkg.ChipRecovery {
	if r == nil {
		return nil
	}
	out := &manifestpkg.ChipRecovery{
		Console:  r.Console,
		Flash:    r.Flash,
		WDT:      r.WDT,
		Clock:    r.Clock,
		RTC:      r.RTC,
		Sources:  r.Sources,
		Includes: r.Includes,
	}
	if r.Crypto != nil {
		out.Crypto = &manifestpkg.RecoveryCrypto{Backend: r.Crypto.Backend, Hash: r.Crypto.Hash}
	}
	return out
}

func loadOptionalArchManifest(dir, expectedArch string) (*manifestpkg.ArchManifest, []string, error) {
	mPath, err := Contain(dir, archManifestFile)
	if err != nil {
		return nil, nil, err
	}
	if _, statErr := os.Lstat(mPath); errors.Is(statErr, fs.ErrNotExist) {
		return nil, nil, nil
	}
	var am manifestpkg.ArchManifest
	if decErr := decodeStrictManifestJSON(mPath, &am); decErr != nil {
		return nil, nil, decErr
	}
	if am.Name != "" {
		if valErr := manifestpkg.ValidatePackageRef("arch", am.Name); valErr != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, valErr)
		}
		if expectedArch != "" && !strings.EqualFold(am.Name, expectedArch) {
			return nil, nil, fmt.Errorf("%s: arch name %q does not match chip arch %q", mPath, am.Name, expectedArch)
		}
	}
	if am.Version != "" {
		if verErr := manifestpkg.ValidateName("arch version", am.Version); verErr != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, verErr)
		}
	}
	if flagsErr := build.ValidateCompilerFlags(mPath, am.CompilerFlags); flagsErr != nil {
		return nil, nil, fmt.Errorf("%s compiler_flags: %w", mPath, flagsErr)
	}
	for _, h := range am.Headers {
		if hdrErr := validateHeaderRel(h); hdrErr != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, hdrErr)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(am.Symbols)) {
		if symErr := manifestpkg.ValidateName("arch symbol key", k); symErr != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, symErr)
		}
		if !isCSymbol(am.Symbols[k]) {
			return nil, nil, fmt.Errorf("%s: invalid C symbol %q for %q", mPath, am.Symbols[k], k)
		}
	}
	srcs, err := containAll(dir, am.Sources)
	if err != nil {
		return nil, nil, fmt.Errorf("%s sources: %w", mPath, err)
	}
	return &am, srcs, nil
}

func resolveArch(in Input, chip *Chip) (Arch, error) {
	halBase := localHALRoot(in)
	dir, err := Contain(halBase, filepath.FromSlash(path.Join("arch", filepath.ToSlash(chip.Arch))))
	if err != nil {
		return Arch{}, fmt.Errorf("local arch override '%s': %w", chip.Arch, err)
	}
	local, err := isDir(dir)
	if err != nil {
		return Arch{}, err
	}
	if !local {
		if in.Registry == nil {
			return Arch{}, errors.New("registry source is nil")
		}
		if dir, err = in.Registry.ArchSourcePath(chip.Arch); err != nil {
			return Arch{}, fmt.Errorf("failed to resolve architecture '%s': %w", chip.Arch, err)
		}
	}
	am, srcs, err := loadOptionalArchManifest(dir, chip.Arch)
	if err != nil {
		return Arch{}, err
	}
	var author, explicitTier, idxVer, idxSHA, license, manifestVer string
	var flags *manifestpkg.CompilerFlags
	if am != nil {
		manifestVer = am.Version
		license = am.License
		flags = am.CompilerFlags
	}
	if in.Index != nil && !local {
		if info, ok := in.Index.Archs[chip.Arch]; ok {
			author, explicitTier = info.Author, info.Tier
			idxVer = info.Version
			idxSHA = firstNonEmpty(info.SHA256, info.TarballSHA)
		}
	}
	return Arch{
		Name:          chip.Arch,
		Dir:           dir,
		Local:         local,
		Tier:          registry.ClassifyTier(chip.Arch, author, explicitTier, local),
		Version:       firstNonEmpty(manifestVer, idxVer),
		SHA256:        idxSHA,
		License:       license,
		Spec:          am,
		CompilerFlags: flags,
		Sources:       srcs,
	}, nil
}

// isDir reports whether path is an existing directory. A missing path is not
// an error; any other failure or a non-directory is.
func isDir(path string) (bool, error) {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	case !info.IsDir():
		return false, fmt.Errorf("%s exists but is not a directory", path)
	}
	return true, nil
}
