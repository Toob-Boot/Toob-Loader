package build

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// driverManifestFile is the file name every driver package must provide.
const driverManifestFile = "driver_manifest.json"

// archManifestFile is the file name every architecture package must provide.
const archManifestFile = "arch_manifest.json"

// Inputs describes every resolved input of a manifest build. The caller (CLI)
// owns environment resolution: registry lookup, cache paths and toolchains.
type Inputs struct {
	Device             *DeviceToml // Parsed device.toml (mandatory).
	ProjectDir         string      // Optional project directory containing device.toml (defaults to ".").
	HardwarePath       string      // Path to hardware.json (mandatory).
	ChipManifestPath   string      // Path to chip_manifest.json (optional).
	HalRoot            string      // Optional explicit root directory resolving soc/, arch/, and drivers/ paths (HIGH-86).
	CoreDir            string      // Core SDK directory containing hal_contract.json (auto-discovered from SourceDirs when empty).
	ArchDir            string      // Architecture package directory containing arch_manifest.json (optional until wiring).
	DriverDirs         []string    // Driver package directories, each with a driver_manifest.json.
	CryptoDirs         []string    // Crypto package directories, each with a crypto_manifest.json.
	RecoveryDriverDirs []string    // Optional Recovery OS driver package directories when distinct from Stage-1 DriverDirs.
	RecoveryCryptoDirs []string    // Optional Recovery OS crypto package directories when distinct from Stage-1 CryptoDirs.
	SourceDirs         []string    // C/ASM/LD source roots scanned by the macro consumption audit.
	OutDir             string      // Destination of all generated artifacts (mandatory).
}

// Context is the fully loaded, immutable input set of one build. Every file is
// read exactly once here; later pipeline stages never touch input files again.
type Context struct {
	Inputs

	Hardware        *HardwareJson
	HardwareRaw     []byte                     // Raw hardware.json bytes for provenance digest (MED-13).
	Chip            *ChipManifest              // nil if no chip manifest path was given.
	Arch            *ArchManifest              // nil if no arch directory was given.
	Drivers         map[string]*DriverManifest // Keyed by trait.
	Crypto          []*CryptoManifest
	RecoveryDrivers map[string]*DriverManifest // Optional Recovery OS drivers keyed by trait.
	RecoveryCrypto  []*CryptoManifest          // Optional Recovery OS crypto manifests.
	halContract     *halContract
	Log             Logger
}

// Load validates the inputs and reads all referenced files. It fails fast on
// missing, malformed or conflicting inputs instead of silently skipping them.
func Load(in Inputs, log Logger) (*Context, error) {
	if log == nil {
		return nil, errors.New("build.Load: logger must not be nil")
	}
	if in.Device == nil {
		return nil, errors.New("build.Load: Inputs.Device must not be nil")
	}
	if in.HardwarePath == "" {
		return nil, errors.New("build.Load: Inputs.HardwarePath must not be empty")
	}
	if in.OutDir == "" {
		return nil, errors.New("build.Load: Inputs.OutDir must not be empty")
	}

	if in.ProjectDir != "" {
		in.ProjectDir = filepath.Clean(in.ProjectDir)
	}
	if in.CoreDir != "" {
		in.CoreDir = filepath.Clean(in.CoreDir)
	}
	if in.ArchDir != "" {
		in.ArchDir = filepath.Clean(in.ArchDir)
	}
	if in.HalRoot != "" {
		in.HalRoot = filepath.Clean(in.HalRoot)
		info, err := os.Stat(in.HalRoot)
		if err != nil {
			return nil, fmt.Errorf("FATAL: HAL root directory %s: %w", in.HalRoot, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("FATAL: HAL root path %s is not a directory", in.HalRoot)
		}
	}
	in.DriverDirs = normalizeDirs(in.DriverDirs)
	in.CryptoDirs = normalizeDirs(in.CryptoDirs)
	in.RecoveryDriverDirs = normalizeDirs(in.RecoveryDriverDirs)
	in.RecoveryCryptoDirs = normalizeDirs(in.RecoveryCryptoDirs)
	in.SourceDirs = normalizeDirs(in.SourceDirs)
	if err := requireSourceDirs(in.SourceDirs); err != nil {
		return nil, err
	}

	hc, err := loadHalContract(in.CoreDir, in.SourceDirs)
	if err != nil {
		return nil, err
	}

	hw, hwRaw, err := parseHardwareJSONWithRaw(in.HardwarePath)
	if err != nil {
		return nil, fmt.Errorf("FATAL: hardware description: %w", err)
	}

	var chip *ChipManifest
	if in.ChipManifestPath != "" {
		if chip, err = decodeJSONFile[ChipManifest](in.ChipManifestPath, true); err != nil {
			return nil, fmt.Errorf("FATAL: chip manifest: %w", err)
		}
		if vErr := validateChipManifestFiles(filepath.Dir(in.ChipManifestPath), in.HalRoot, chip); vErr != nil {
			return nil, fmt.Errorf("FATAL: chip manifest: %w", vErr)
		}
	}

	var arch *ArchManifest
	if in.ArchDir != "" {
		if arch, err = loadArchManifest(in.ArchDir, chip); err != nil {
			return nil, err
		}
	}

	drivers, err := loadDriverManifests(in.DriverDirs)
	if err != nil {
		return nil, err
	}

	crypto, err := loadCryptoManifests(in.CryptoDirs)
	if err != nil {
		return nil, err
	}

	var recDrivers map[string]*DriverManifest
	if len(in.RecoveryDriverDirs) > 0 {
		if recDrivers, err = loadDriverManifests(in.RecoveryDriverDirs); err != nil {
			return nil, fmt.Errorf("recovery %w", err)
		}
	}

	var recCrypto []*CryptoManifest
	if len(in.RecoveryCryptoDirs) > 0 {
		if recCrypto, err = loadCryptoManifests(in.RecoveryCryptoDirs); err != nil {
			return nil, fmt.Errorf("recovery %w", err)
		}
	}

	return &Context{
		Inputs:          in,
		Hardware:        hw,
		HardwareRaw:     hwRaw,
		Chip:            chip,
		Arch:            arch,
		Drivers:         drivers,
		Crypto:          crypto,
		RecoveryDrivers: recDrivers,
		RecoveryCrypto:  recCrypto,
		halContract:     hc,
		Log:             log,
	}, nil
}

// normalizeDirs cleans every path and removes empty entries and duplicates
// (including case-folded aliases on Windows and SameFile aliases) while preserving order.
func normalizeDirs(dirs []string) []string {
	out := make([]string, 0, len(dirs))
	var infos []os.FileInfo
	for _, d := range dirs {
		if strings.TrimSpace(d) == "" {
			continue
		}
		c := filepath.Clean(d)
		fi, statErr := os.Stat(c)
		dup := false
		for i, prev := range out {
			if c == prev || (runtime.GOOS == "windows" && strings.EqualFold(c, prev)) {
				dup = true
				break
			}
			if statErr == nil && infos[i] != nil && os.SameFile(fi, infos[i]) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
			infos = append(infos, fi)
		}
	}
	return out
}

func requireSourceDirs(dirs []string) error {
	if len(dirs) == 0 {
		return errors.New("build.Load: Inputs.SourceDirs must contain at least one directory for the macro audit")
	}
	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil {
			return fmt.Errorf("FATAL: source directory %s: %w", d, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("FATAL: source path %s is not a directory", d)
		}
	}
	return nil
}

func chipHalRoot(chipDir, explicitHalRoot string) string {
	if explicitHalRoot != "" {
		return filepath.Clean(explicitHalRoot)
	}
	cleanChip := filepath.Clean(chipDir)
	parent := filepath.Dir(cleanChip)
	parentBase := filepath.Base(parent)
	if strings.EqualFold(parentBase, "chips") || strings.EqualFold(parentBase, "chip") {
		return filepath.Clean(filepath.Join(cleanChip, "..", ".."))
	}
	if strings.HasPrefix(parentBase, "@") {
		grandBase := filepath.Base(filepath.Dir(parent))
		if strings.EqualFold(grandBase, "chips") || strings.EqualFold(grandBase, "chip") {
			return filepath.Clean(filepath.Join(cleanChip, "..", "..", ".."))
		}
	}
	return cleanChip
}

func containChipOrHalPath(chipDir, halRoot, kind, rel string) error {
	if err := validateRelPath(kind, rel); err != nil {
		return err
	}
	base := chipDir
	if strings.HasPrefix(rel, "soc/") || strings.HasPrefix(rel, "arch/") || strings.HasPrefix(rel, "drivers/") {
		base = halRoot
	}
	_, err := containPath(base, rel)
	return err
}

// validateChipManifestFiles ensures paths and bindings declared in
// chip_manifest.json cannot escape the chip/packages root or inject unsafe names.
func validateChipManifestFiles(chipDir, explicitHalRoot string, chip *ChipManifest) error {
	halRoot := chipHalRoot(chipDir, explicitHalRoot)
	if chip.Name != "" {
		if err := ValidateName("chip", chip.Name); err != nil {
			return err
		}
	}
	if chip.Arch != "" {
		if err := ValidatePackageRef("arch", chip.Arch); err != nil {
			return err
		}
	}
	if chip.CompilerPrefix != "" {
		if err := ValidateName("compiler prefix", chip.CompilerPrefix); err != nil {
			return err
		}
	}
	if err := ValidateCompilerFlags("compiler_flags", chip.CompilerFlags); err != nil {
		return err
	}
	for trait, ref := range chip.HalBindings {
		if err := ValidateName("driver trait", trait); err != nil {
			return err
		}
		if err := validatePackageOrRelPath("driver", ref); err != nil {
			return err
		}
	}
	for _, inc := range chip.Includes {
		if err := containChipOrHalPath(chipDir, halRoot, "chip include", inc); err != nil {
			return fmt.Errorf("includes: %w", err)
		}
	}
	if chip.Sources != nil {
		for _, entry := range []struct{ field, rel string }{
			{"sources.startup", chip.Sources.Startup},
			{"sources.platform", chip.Sources.Platform},
			{"sources.config", chip.Sources.Config},
			{"sources.linker", chip.Sources.Linker},
			{"sources.hardware", chip.Sources.Hardware},
		} {
			if entry.rel != "" {
				if err := validateRelPath(entry.field, entry.rel); err != nil {
					return fmt.Errorf("%s: %w", entry.field, err)
				}
				if _, err := containPath(chipDir, entry.rel); err != nil {
					return fmt.Errorf("%s: %w", entry.field, err)
				}
			}
		}
		for _, extra := range chip.Sources.Extra {
			if err := validateRelPath("sources.extra", extra); err != nil {
				return fmt.Errorf("sources.extra: %w", err)
			}
			if _, err := containPath(chipDir, extra); err != nil {
				return fmt.Errorf("sources.extra: %w", err)
			}
		}
		for _, drv := range chip.Sources.Drivers {
			if err := containChipOrHalPath(chipDir, halRoot, "driver source", drv); err != nil {
				return fmt.Errorf("sources.drivers: %w", err)
			}
		}
	}
	if chip.Recovery != nil {
		for _, src := range chip.Recovery.Sources {
			if err := containChipOrHalPath(chipDir, halRoot, "recovery source", src); err != nil {
				return fmt.Errorf("recovery.sources: %w", err)
			}
		}
		for _, inc := range chip.Recovery.Includes {
			if err := containChipOrHalPath(chipDir, halRoot, "recovery include", inc); err != nil {
				return fmt.Errorf("recovery.includes: %w", err)
			}
		}
	}
	return nil
}

// loadDriverManifests reads one driver_manifest.json per directory and binds
// it to its trait. Each trait may be bound by exactly one driver.
func loadDriverManifests(dirs []string) (map[string]*DriverManifest, error) {
	drivers := make(map[string]*DriverManifest, len(dirs))
	origin := make(map[string]string, len(dirs))
	for _, dir := range dirs {
		path := filepath.Join(dir, driverManifestFile)
		dm, err := decodeJSONFile[DriverManifest](path, true)
		if err != nil {
			return nil, fmt.Errorf("FATAL: driver manifest: %w", err)
		}
		if dm.Trait == "" {
			return nil, fmt.Errorf("FATAL: driver manifest %s does not declare a 'trait'", path)
		}
		if err := ValidateName("driver trait", dm.Trait); err != nil {
			return nil, fmt.Errorf("FATAL: driver manifest %s: %w", path, err)
		}
		if dm.Name != "" {
			if err := ValidatePackageRef("driver", dm.Name); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s: %w", path, err)
			}
		}
		if dm.AbiVersion != "" {
			if err := ValidateName("driver abi_version", dm.AbiVersion); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s: %w", path, err)
			}
		}
		for _, h := range dm.Headers {
			if err := validateHeaderPath(h); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s invalid header path %q: %w", path, h, err)
			}
		}
		for _, k := range slices.Sorted(maps.Keys(dm.Symbols)) {
			if err := ValidateName("driver symbol key", k); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s: %w", path, err)
			}
			if !isCSymbol(dm.Symbols[k]) {
				return nil, fmt.Errorf("FATAL: driver manifest %s invalid C symbol %s=%q", path, k, dm.Symbols[k])
			}
		}
		for _, src := range dm.Sources {
			if err := validateRelPath("driver source", src); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s sources: %w", path, err)
			}
			if _, err := containPath(dir, src); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s sources: %w", path, err)
			}
		}
		for _, mockSrc := range dm.MockSources {
			if err := validateRelPath("driver mock_source", mockSrc); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s mock_sources: %w", path, err)
			}
			if _, err := containPath(dir, mockSrc); err != nil {
				return nil, fmt.Errorf("FATAL: driver manifest %s mock_sources: %w", path, err)
			}
		}
		if prev, dup := origin[dm.Trait]; dup {
			return nil, fmt.Errorf("FATAL: trait '%s' is bound twice (%s and %s)", dm.Trait, prev, path)
		}
		drivers[dm.Trait] = dm
		origin[dm.Trait] = path
	}
	return drivers, nil
}

// loadArchManifest reads and validates arch_manifest.json from an architecture package directory.
func loadArchManifest(dir string, chip *ChipManifest) (*ArchManifest, error) {
	path := filepath.Join(dir, archManifestFile)
	am, err := decodeJSONFile[ArchManifest](path, true)
	if err != nil {
		return nil, fmt.Errorf("FATAL: arch manifest: %w", err)
	}
	if am.Name == "" {
		return nil, fmt.Errorf("FATAL: arch manifest %s does not declare a 'name'", path)
	}
	if err := ValidatePackageRef("arch", am.Name); err != nil {
		return nil, fmt.Errorf("FATAL: arch manifest %s: %w", path, err)
	}
	if chip != nil && chip.Arch != "" && !strings.EqualFold(am.Name, chip.Arch) {
		return nil, fmt.Errorf("FATAL: arch manifest %s declares '%s', but chip_manifest.json requires '%s'",
			path, am.Name, chip.Arch)
	}
	if err := ValidateCompilerFlags("compiler_flags", am.CompilerFlags); err != nil {
		return nil, fmt.Errorf("FATAL: arch manifest %s: %w", path, err)
	}
	for _, h := range am.Headers {
		if err := validateHeaderPath(h); err != nil {
			return nil, fmt.Errorf("FATAL: arch manifest %s invalid header path %q: %w", path, h, err)
		}
	}
	for _, src := range am.Sources {
		if err := validateRelPath("arch source", src); err != nil {
			return nil, fmt.Errorf("FATAL: arch manifest %s sources: %w", path, err)
		}
		if _, err := containPath(dir, src); err != nil {
			return nil, fmt.Errorf("FATAL: arch manifest %s sources: %w", path, err)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(am.Symbols)) {
		if err := ValidateName("arch symbol key", k); err != nil {
			return nil, fmt.Errorf("FATAL: arch manifest %s: %w", path, err)
		}
		if !isCSymbol(am.Symbols[k]) {
			return nil, fmt.Errorf("FATAL: arch manifest %s invalid C symbol %s=%q", path, k, am.Symbols[k])
		}
	}
	for _, m := range am.RequiredMacros {
		if !isCIdentifier(m) {
			return nil, fmt.Errorf("FATAL: arch manifest %s invalid required macro %q", path, m)
		}
	}
	return am, nil
}
