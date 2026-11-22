package resolve

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
)

const (
	hardwareFile     = "hardware.json"
	chipManifestFile = "chip_manifest.json"
	archManifestFile = "arch_manifest.json"
	defaultChipVer   = "1.0.0"
)

// localHalDir is the project-relative root of locally overridden HAL packages.
var localHalDir = filepath.Join("toobloader", "hal")

// resolveChip locates the chip package once. A chip directory inside the
// project replaces the registry package completely; mixing files from both
// would pair a hardware.json with a foreign chip_manifest.json.
func resolveChip(in Input) (*Chip, error) {
	if in.Device == nil {
		return nil, errors.New("device.toml input is nil")
	}
	name := in.Device.Device.Chip
	if name == "" {
		return nil, errors.New("device.toml must define [device] with 'chip'")
	}
	if err := manifestpkg.ValidateName("chip", name); err != nil {
		return nil, fmt.Errorf("device.toml [device] chip: %w", err)
	}

	halBase := filepath.Join(in.Root, localHalDir)
	dir, err := Contain(halBase, filepath.Join("chips", name))
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
		Name: name, Dir: dir, Local: local,
		HardwarePath: hwPath,
		ManifestPath: manifestPath,
	}
	for _, file := range []string{chip.HardwarePath, chip.ManifestPath} {
		if st, err := os.Lstat(file); err != nil {
			return nil, fmt.Errorf("chip '%s' is incomplete (local override: %v): %w", name, local, err)
		} else if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("chip '%s' file %s must be a regular file", name, file)
		}
	}
	if err := loadChipManifest(chip); err != nil {
		return nil, err
	}
	chip.halBindings, chip.driverFiles, chip.recovery = chipPackageEntries(in.Index, chip)
	var author, explicitTier string
	if in.Index != nil {
		if info, ok := in.Index.Chips[chip.Name]; ok && !chip.Local {
			author, explicitTier = info.Author, info.Tier
		}
	}
	chip.Tier = registry.ClassifyTier(chip.Name, author, explicitTier, chip.Local)
	return chip, nil
}

func loadChipManifest(chip *Chip) error {
	var spec ports.ChipManifest
	if err := decodeStrictManifestJSON(chip.ManifestPath, &spec); err != nil {
		return err
	}
	if spec.Name != "" {
		if err := manifestpkg.ValidateName("chip", spec.Name); err != nil {
			return fmt.Errorf("%s: %w", chip.ManifestPath, err)
		}
		if !strings.EqualFold(spec.Name, chip.Name) {
			return fmt.Errorf("%s: chip name %q does not match requested chip %q", chip.ManifestPath, spec.Name, chip.Name)
		}
	}
	if spec.Arch == "" || spec.CompilerPrefix == "" {
		return fmt.Errorf("%s of chip '%s' is missing 'arch' or 'compiler_prefix'; "+
			"ensure the registry or local manifest defines these fields", chipManifestFile, chip.Name)
	}
	if err := manifestpkg.ValidatePackageRef("arch", spec.Arch); err != nil {
		return fmt.Errorf("%s: %w", chip.ManifestPath, err)
	}
	if err := manifestpkg.ValidateName("compiler prefix", spec.CompilerPrefix); err != nil {
		return fmt.Errorf("%s: %w", chip.ManifestPath, err)
	}
	if spec.Version != "" {
		if err := manifestpkg.ValidateName("chip version", spec.Version); err != nil {
			return fmt.Errorf("%s: %w", chip.ManifestPath, err)
		}
	}
	if spec.MinCompiler != "" {
		if strings.EqualFold(strings.TrimSpace(spec.MinCompiler), "latest") {
			return fmt.Errorf("%s: min_compiler = \"latest\" is forbidden (REG-009); specify a concrete compiler version", chip.ManifestPath)
		}
		if _, err := ExtractCompilerSemver(spec.MinCompiler); err != nil {
			return fmt.Errorf("%s: invalid min_compiler %q: %w", chip.ManifestPath, spec.MinCompiler, err)
		}
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

	chip.Spec, chip.Arch, chip.Prefix, chip.Version = &spec, spec.Arch, spec.CompilerPrefix, spec.Version
	if chip.Version == "" {
		chip.Version = defaultChipVer
	}
	return nil
}

func chipPackageEntries(idx *registry.Index, chip *Chip) (map[string]string, []string, *ports.ChipRecovery) {
	var bindings map[string]string
	var drivers []string
	var recovery *ports.ChipRecovery
	if idx != nil {
		if info, ok := idx.Chips[chip.Name]; ok && !chip.Local {
			bindings = info.HalBindings
			if info.Sources != nil {
				drivers = info.Sources.Drivers
			}
			recovery = recoveryFromIndex(info.Recovery)
		}
	}
	if len(bindings) == 0 && chip.Spec != nil {
		bindings = chip.Spec.HalBindings
	}
	if len(drivers) == 0 && chip.Spec != nil && chip.Spec.Sources != nil {
		drivers = chip.Spec.Sources.Drivers
	}
	if recovery == nil && chip.Spec != nil {
		recovery = chip.Spec.Recovery
	}
	return bindings, drivers, recovery
}

func recoveryFromIndex(r *registry.ChipRecovery) *ports.ChipRecovery {
	if r == nil {
		return nil
	}
	out := &ports.ChipRecovery{
		Console: r.Console, Flash: r.Flash, WDT: r.WDT, Clock: r.Clock, RTC: r.RTC,
		Sources: r.Sources, Includes: r.Includes,
	}
	if r.Crypto != nil {
		out.Crypto = &ports.RecoveryCrypto{Backend: r.Crypto.Backend, Hash: r.Crypto.Hash}
	}
	return out
}

func loadOptionalArchManifest(dir, expectedArch string) (*ports.ArchManifest, []string, error) {
	mPath, err := Contain(dir, archManifestFile)
	if err != nil {
		return nil, nil, err
	}
	if _, err := os.Lstat(mPath); errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	var am ports.ArchManifest
	if err := decodeStrictManifestJSON(mPath, &am); err != nil {
		return nil, nil, err
	}
	if am.Name != "" {
		if err := manifestpkg.ValidatePackageRef("arch", am.Name); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, err)
		}
		if expectedArch != "" && !strings.EqualFold(am.Name, expectedArch) {
			return nil, nil, fmt.Errorf("%s: arch name %q does not match chip arch %q", mPath, am.Name, expectedArch)
		}
	}
	if am.Version != "" {
		if err := manifestpkg.ValidateName("arch version", am.Version); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	for _, h := range am.Headers {
		if err := validateHeaderRel(h); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, err)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(am.Symbols)) {
		if err := manifestpkg.ValidateName("arch symbol key", k); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", mPath, err)
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
	halBase := filepath.Join(in.Root, localHalDir)
	dir, err := Contain(halBase, filepath.Join("arch", filepath.FromSlash(chip.Arch)))
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
	_, srcs, err := loadOptionalArchManifest(dir, chip.Arch)
	if err != nil {
		return Arch{}, err
	}
	var author, explicitTier string
	if in.Index != nil && !local {
		if info, ok := in.Index.Archs[chip.Arch]; ok {
			author, explicitTier = info.Author, info.Tier
		}
	}
	return Arch{
		Name:    chip.Arch,
		Dir:     dir,
		Local:   local,
		Tier:    registry.ClassifyTier(chip.Arch, author, explicitTier, local),
		Sources: srcs,
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
