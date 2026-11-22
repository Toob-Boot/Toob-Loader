package resolve

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
)

// Build profiles supported by the package resolver.
const (
	ProfileDev        = "dev"
	ProfileProduction = "production"
)

// Source provides the on-disk location of registry packages, fetching them
// on demand. *registry.Cache implements it.
type Source interface {
	ChipSourcePath(name string) (string, error)
	ArchSourcePath(arch string) (string, error)
	DriverSourcePath(driverDir string) (string, error)
	CryptoSourcePath(name string) (string, error)
	SoCSourcePath(socDir string) (string, error)
	ToolchainConfigPath(name string) (string, error)
}

// Input collects everything Resolve reads.
type Input struct {
	Root          string
	Device        *manifestpkg.DeviceToml
	Lock          *lockfile.Lockfile
	Index         *registry.Index
	Registry      Source
	Profile       string
	MockOverrides []string
	MockSet       bool
}

// ResolvedDriver records a resolved HAL driver package, its trust tier, and
// the exact C/ASM translation units selected for the active build profile.
type ResolvedDriver struct {
	Trait   string
	Name    string
	Dir     string
	Version string
	Tier    string
	Local   bool
	Mocked  bool
	Sources []string
}

// Plan is the validated result of Resolve.
type Plan struct {
	Profile        string
	MockHW         bool
	Chip           Chip
	CoreSDK        CoreSDK
	Compiler       string
	Arch           Arch
	Toolchain      Toolchain
	Drivers        []string
	DriverPackages []ResolvedDriver
	DriverSources  []string
	ChipSources    []string
	ChipIncludes   []string
	Crypto         []CryptoSlot
	Recovery       Recovery
	SoCDir         string
}

// Chip locates the resolved chip package.
type Chip struct {
	Name         string
	Dir          string
	Local        bool
	Tier         string
	HardwarePath string
	ManifestPath string
	Spec         *ports.ChipManifest
	Version      string
	Arch         string
	Prefix       string

	halBindings map[string]string
	driverFiles []string
	recovery    *ports.ChipRecovery
}

// CoreSDK is the resolved Core SDK version and where it came from.
type CoreSDK struct {
	Version string
	Origin  string
}

func (c CoreSDK) Label() string { return c.Version + " (" + c.Origin + ")" }

// Arch locates the architecture HAL.
type Arch struct {
	Name    string
	Dir     string
	Local   bool
	Tier    string
	Sources []string
}

// Toolchain describes the cross-compiler selection.
type Toolchain struct {
	Name            string
	Prefix          string
	File            string
	ExpectedVersion string
	UpstreamVersion string
	MinCompiler     string
}

// CryptoSlot is one of the backend, hash and pqc crypto slots.
type CryptoSlot struct {
	Slot     string
	Name     string
	Dir      string
	Tier     string
	Local    bool
	Sources  []string
	Includes []string
	Wrapper  string
	Cflags   []string
	Reused   bool
}

func (s CryptoSlot) Enabled() bool { return s.Name != "" }

// Recovery is the recovery-image configuration.
type Recovery struct {
	Backend       string
	Hash          string
	BackendSlot   *CryptoSlot
	HashSlot      *CryptoSlot
	Declared      bool
	Drivers       []string
	DriverSources []string
	Sources       []string
	Includes      []string
}

type buildMode struct {
	profile      string
	mockAll      bool
	mockedTraits map[string]bool
}

func (m buildMode) shouldMock(trait string) bool {
	if m.profile == ProfileProduction {
		return false
	}
	if m.mockAll {
		return true
	}
	return m.mockedTraits[strings.ToLower(trait)]
}

func (m buildMode) anyMockEnabled() bool {
	return m.profile != ProfileProduction && (m.mockAll || len(m.mockedTraits) > 0)
}

func resolveBuildMode(in Input) (buildMode, error) {
	if in.Device == nil {
		return buildMode{}, errors.New("device.toml input is nil")
	}
	rawProfile := strings.ToLower(strings.TrimSpace(firstNonEmpty(in.Profile, in.Device.Build.Profile, ProfileDev)))
	switch rawProfile {
	case ProfileDev, ProfileProduction:
	default:
		return buildMode{}, fmt.Errorf("invalid build profile %q: expected %q or %q", rawProfile, ProfileDev, ProfileProduction)
	}

	if rawProfile == ProfileProduction {
		if in.MockSet {
			for _, item := range in.MockOverrides {
				tok := strings.ToLower(strings.TrimSpace(item))
				if tok != "" && tok != "none" && tok != "false" {
					return buildMode{}, fmt.Errorf("hardware mocks (%q) are forbidden in %q profile", item, ProfileProduction)
				}
			}
		}
		return buildMode{profile: ProfileProduction, mockedTraits: map[string]bool{}}, nil
	}

	var rawMocks []string
	explicit := false
	if in.MockSet {
		rawMocks = in.MockOverrides
		explicit = true
	} else if len(in.Device.Build.Mock) > 0 {
		rawMocks = in.Device.Build.Mock
		explicit = true
	}

	if !explicit {
		return buildMode{
			profile:      ProfileDev,
			mockedTraits: map[string]bool{"keystore": true, "otp": true},
		}, nil
	}

	traits := make(map[string]bool)
	mockAll := false
	for _, entry := range rawMocks {
		for _, part := range strings.Split(entry, ",") {
			tok := strings.ToLower(strings.TrimSpace(part))
			switch tok {
			case "":
				continue
			case "none", "false":
				clear(traits)
				mockAll = false
			case "all", "*", "true":
				mockAll = true
			default:
				if err := manifestpkg.ValidateName("mock trait", tok); err != nil {
					return buildMode{}, err
				}
				traits[tok] = true
				if tok == "keystore" {
					traits["otp"] = true
				}
			}
		}
	}
	return buildMode{profile: ProfileDev, mockAll: mockAll, mockedTraits: traits}, nil
}

// PQCEnabled reports whether a post-quantum package is selected.
func (p *Plan) PQCEnabled() bool {
	for _, s := range p.Crypto {
		if s.Slot == slotPQC {
			return s.Enabled()
		}
	}
	return false
}

// CryptoDirs returns deduplicated non-empty package directories of enabled
// Stage 1 and distinct Recovery crypto slots in deterministic order.
func (p *Plan) CryptoDirs() []string {
	if p == nil {
		return nil
	}
	var dirs []string
	addDir := func(d string) {
		if d != "" && !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	for _, wantSlot := range []string{slotBackend, slotHash, slotPQC} {
		for _, s := range p.Crypto {
			if s.Slot == wantSlot && s.Enabled() {
				addDir(s.Dir)
			}
		}
	}
	for _, s := range p.Crypto {
		if s.Enabled() {
			addDir(s.Dir)
		}
	}
	if p.Recovery.BackendSlot != nil && p.Recovery.BackendSlot.Enabled() {
		addDir(p.Recovery.BackendSlot.Dir)
	}
	if p.Recovery.HashSlot != nil && p.Recovery.HashSlot.Enabled() {
		addDir(p.Recovery.HashSlot.Dir)
	}
	return dirs
}

// Resolve validates the build inputs and resolves every package they name.
func Resolve(in Input) (*Plan, error) {
	if in.Lock != nil {
		if err := in.Lock.Validate(); err != nil {
			return nil, err
		}
	}
	mode, err := resolveBuildMode(in)
	if err != nil {
		return nil, err
	}
	chip, err := resolveChip(in)
	if err != nil {
		return nil, err
	}
	sdk, err := resolveCoreSDK(in, chip)
	if err != nil {
		return nil, err
	}
	compiler, err := resolveCompiler(in)
	if err != nil {
		return nil, err
	}
	arch, err := resolveArch(in, chip)
	if err != nil {
		return nil, err
	}
	toolchain, err := resolveToolchain(in, chip)
	if err != nil {
		return nil, err
	}
	drivers, drvPkgs, drvSources, err := resolveDriverPackages(in, chip, mode)
	if err != nil {
		return nil, err
	}
	chipSources, err := resolveChipSources(chip, mode)
	if err != nil {
		return nil, err
	}
	socDir := resolveSoCDir(in, chip)
	chipIncs, err := chipIncludesWithFallback(in, chip, arch.Dir, socDir)
	if err != nil {
		return nil, err
	}
	crypto, err := resolveCrypto(in, chip, sdk.Version)
	if err != nil {
		return nil, err
	}
	if err := enforceLockedChip(in, chip, arch, crypto); err != nil {
		return nil, err
	}
	recovery, err := resolveRecoveryWithMode(in, chip, mode, arch.Dir, socDir)
	if err != nil {
		return nil, err
	}
	if err := resolveRecoveryCryptoSlots(in, chip, sdk.Version, crypto, &recovery); err != nil {
		return nil, err
	}

	mockHW := mode.anyMockEnabled()
	for _, dp := range drvPkgs {
		if dp.Mocked {
			mockHW = true
			break
		}
	}

	plan := &Plan{
		Profile:        mode.profile,
		MockHW:         mockHW,
		Chip:           *chip,
		CoreSDK:        sdk,
		Compiler:       compiler,
		Arch:           arch,
		Toolchain:      toolchain,
		Drivers:        drivers,
		DriverPackages: drvPkgs,
		DriverSources:  drvSources,
		ChipSources:    chipSources,
		ChipIncludes:   chipIncs,
		Crypto:         crypto,
		Recovery:       recovery,
		SoCDir:         socDir,
	}
	return plan, nil
}

func enforceLockedChip(in Input, chip *Chip, arch Arch, crypto []CryptoSlot) error {
	if in.Lock == nil {
		return nil
	}
	locked := in.Lock.GetChip(chip.Name)
	if locked == nil {
		return nil
	}
	if !chip.Local && locked.Version != "" && chip.Version != "" && locked.Version != chip.Version {
		return fmt.Errorf("chip '%s' version %q does not match locked version %q in toob.lock",
			chip.Name, chip.Version, locked.Version)
	}
	if locked.Arch != "" && !strings.EqualFold(locked.Arch, chip.Arch) {
		return fmt.Errorf("chip '%s' arch %q does not match locked arch %q in toob.lock",
			chip.Name, chip.Arch, locked.Arch)
	}
	if !arch.Local && locked.ArchVersion != "" && in.Index != nil {
		if aInfo, ok := in.Index.Archs[chip.Arch]; ok && aInfo.Version != "" && aInfo.Version != locked.ArchVersion {
			return fmt.Errorf("arch '%s' version %q does not match locked arch_version %q in toob.lock",
				chip.Arch, aInfo.Version, locked.ArchVersion)
		}
	}
	if len(crypto) == 3 {
		if in.Device.Crypto.Backend == "" && locked.CryptoBackend != "" && crypto[0].Name != locked.CryptoBackend {
			return fmt.Errorf("crypto backend %q does not match locked crypto_backend %q in toob.lock",
				crypto[0].Name, locked.CryptoBackend)
		}
		if in.Device.Crypto.Hash == "" && locked.CryptoHash != "" && crypto[1].Name != locked.CryptoHash {
			return fmt.Errorf("crypto hash %q does not match locked crypto_hash %q in toob.lock",
				crypto[1].Name, locked.CryptoHash)
		}
		if in.Device.Crypto.Pqc == "" && locked.CryptoPqc != "" && crypto[2].Name != locked.CryptoPqc {
			return fmt.Errorf("crypto pqc %q does not match locked crypto_pqc %q in toob.lock",
				crypto[2].Name, locked.CryptoPqc)
		}
	}
	return nil
}

func resolveRecoveryCryptoSlots(in Input, chip *Chip, coreSDK string, stage1 []CryptoSlot, rec *Recovery) error {
	var stage1Backend, stage1Hash string
	if len(stage1) >= 2 {
		stage1Backend = stage1[0].Name
		stage1Hash = stage1[1].Name
	}
	if rec.Backend != "" && !strings.EqualFold(rec.Backend, "rom") && !strings.EqualFold(rec.Backend, "none") && rec.Backend != stage1Backend {
		slot, err := resolveCryptoPackage(in, chip, coreSDK, "recovery_backend", rec.Backend)
		if err != nil {
			return fmt.Errorf("recovery.crypto.backend: %w", err)
		}
		rec.BackendSlot = &slot
	}
	if rec.Hash != "" && !strings.EqualFold(rec.Hash, "none") && rec.Hash != stage1Hash && rec.Hash != stage1Backend {
		slot, err := resolveCryptoPackage(in, chip, coreSDK, "recovery_hash", rec.Hash)
		if err != nil {
			return fmt.Errorf("recovery.crypto.hash: %w", err)
		}
		rec.HashSlot = &slot
	}
	return nil
}

func normalizeChipMatchKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}

func resolveSoCDir(in Input, chip *Chip) string {
	if in.Registry == nil || in.Index == nil || len(in.Index.SoCs) == 0 || chip == nil {
		return ""
	}
	targetChip := normalizeChipMatchKey(chip.Name)
	for _, key := range slices.Sorted(maps.Keys(in.Index.SoCs)) {
		soc := in.Index.SoCs[key]
		matched := slices.ContainsFunc(soc.Chips, func(c string) bool {
			return normalizeChipMatchKey(c) == targetChip
		})
		if !matched {
			continue
		}
		socRef := key
		if soc.Name != "" {
			socRef = soc.Name
		}
		if dir, err := in.Registry.SoCSourcePath(socRef); err == nil {
			return dir
		}
	}
	return ""
}

func resolveCompiler(in Input) (string, error) {
	compiler := in.Device.Build.Compiler
	if compiler == "" {
		return "latest", nil
	}
	if err := manifestpkg.ValidateName("compiler version", compiler); err != nil {
		return "", fmt.Errorf("device.toml [build] compiler: %w", err)
	}
	return compiler, nil
}
