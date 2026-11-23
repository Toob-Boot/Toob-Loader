package resolve

import (
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

	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
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
	HalRoot       string
	CoreDir       string
	Integration   string
	MockOverrides []string
	MockSet       bool
	Locked        bool
}

// ResolvedDriver records a resolved HAL driver package, its trust tier,
// license, reference build context, and selected translation units.
type ResolvedDriver struct {
	Trait                 string
	Name                  string
	Dir                   string
	Version               string
	Tier                  string
	Local                 bool
	Mocked                bool
	SHA256                string
	License               string
	ReferenceBuildContext *manifestpkg.ReferenceBuildContext
	Sources               []string
}

// Plan is the validated result of Resolve.
type Plan struct {
	Profile        string
	MockHW         bool
	HalRoot        string
	Integration    string
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
	ArchFlags      []string
	ChipCFlags     []string
	ChipAsmFlags   []string
	ChipLDFlags    []string
	ChipStartup    string
	ChipLinker     string
	Crypto         []CryptoSlot
	Recovery       Recovery
	SoCDir         string
	SoCName        string
	SoCVersion     string
	SoCSHA256      string
	SoCSource      string
	Coprocessors   []manifestpkg.Coprocessor
}

// Chip locates the resolved chip package.
type Chip struct {
	Name                  string
	Dir                   string
	Local                 bool
	Tier                  string
	HardwarePath          string
	ManifestPath          string
	Spec                  *manifestpkg.ChipManifest
	Version               string
	Arch                  string
	Prefix                string
	SHA256                string
	License               string
	ReferenceBuildContext *manifestpkg.ReferenceBuildContext

	halBindings  map[string]string
	driverFiles  []string
	recovery     *manifestpkg.ChipRecovery
	coprocessors []manifestpkg.Coprocessor
}

// CoreSDK is the resolved Core SDK version and where it came from.
type CoreSDK struct {
	Version string
	Origin  string
	SHA256  string
}

func (c CoreSDK) Label() string { return c.Version + " (" + c.Origin + ")" }

// Arch locates the architecture HAL.
type Arch struct {
	Name          string
	Dir           string
	Local         bool
	Tier          string
	Version       string
	SHA256        string
	License       string
	Spec          *manifestpkg.ArchManifest
	CompilerFlags *manifestpkg.CompilerFlags
	Sources       []string
}

// Toolchain describes the cross-compiler selection.
type Toolchain struct {
	Name            string
	Prefix          string
	File            string
	ExpectedVersion string
	UpstreamVersion string
	MinCompiler     string
	CompilerBinary  string
	SHA256          map[string]string
}

// CryptoSlot is one of the backend, hash and pqc crypto slots.
type CryptoSlot struct {
	Slot                  string
	Name                  string
	Dir                   string
	Version               string
	Tier                  string
	Local                 bool
	SHA256                string
	License               string
	ReferenceBuildContext *manifestpkg.ReferenceBuildContext
	Sources               []string
	Includes              []string
	Wrapper               string
	Cflags                []string
	Reused                bool
}

func (s CryptoSlot) Enabled() bool { return s.Name != "" }

// Recovery is the recovery-image configuration.
type Recovery struct {
	Backend        string
	Hash           string
	BackendSlot    *CryptoSlot
	HashSlot       *CryptoSlot
	Declared       bool
	Drivers        []string
	DriverPackages []ResolvedDriver
	DriverSources  []string
	Sources        []string
	Includes       []string
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

func resolveBuildMode(in Input, contract *halContractSpec) (buildMode, error) {
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
			mockedTraits: contract.securityCriticalMockTraits(),
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
				for _, expanded := range contract.expandMockToken(tok) {
					traits[expanded] = true
				}
			}
		}
	}
	return buildMode{profile: ProfileDev, mockAll: mockAll, mockedTraits: traits}, nil
}

// PQCEnabled reports whether a post-quantum package is selected.
func (p *Plan) PQCEnabled() bool {
	for i := range p.Crypto {
		if p.Crypto[i].Slot == slotPQC {
			return p.Crypto[i].Enabled()
		}
	}
	return false
}

// CryptoDirs returns deduplicated non-empty package directories of enabled
// Stage-1 crypto slots only (backend -> hash -> pqc).
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
		for i := range p.Crypto {
			if p.Crypto[i].Slot == wantSlot && p.Crypto[i].Enabled() {
				addDir(p.Crypto[i].Dir)
			}
		}
	}
	for i := range p.Crypto {
		if p.Crypto[i].Enabled() {
			addDir(p.Crypto[i].Dir)
		}
	}
	return dirs
}

// RecoveryCryptoDirs returns deduplicated non-empty package directories of enabled
// Recovery OS crypto slots only (backend -> hash).
func (p *Plan) RecoveryCryptoDirs() []string {
	if p == nil {
		return nil
	}
	var dirs []string
	if p.Recovery.BackendSlot != nil && p.Recovery.BackendSlot.Enabled() && p.Recovery.BackendSlot.Dir != "" {
		dirs = append(dirs, p.Recovery.BackendSlot.Dir)
	}
	if p.Recovery.HashSlot != nil && p.Recovery.HashSlot.Enabled() && p.Recovery.HashSlot.Dir != "" &&
		!slices.Contains(dirs, p.Recovery.HashSlot.Dir) {
		dirs = append(dirs, p.Recovery.HashSlot.Dir)
	}
	return dirs
}

// RecoveryDriverDirs returns deduplicated non-empty Recovery driver directories.
func (p *Plan) RecoveryDriverDirs() []string {
	if p == nil || len(p.Recovery.Drivers) == 0 {
		return nil
	}
	return slices.Clone(p.Recovery.Drivers)
}

// Resolve validates the build inputs and resolves every package they name.
func Resolve(in Input) (*Plan, error) {
	if in.Locked && in.Lock == nil {
		return nil, errors.New("--locked build requires a toob.lock file")
	}
	if in.Lock != nil {
		if err := in.Lock.Validate(); err != nil {
			return nil, err
		}
	}

	contract, err := loadHALContract(in.CoreDir)
	if err != nil {
		return nil, err
	}
	mode, err := resolveBuildMode(in, contract)
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
	drivers, drvPkgs, drvSources, err := resolveDriverPackages(in, chip, mode, contract)
	if err != nil {
		return nil, err
	}
	chipSources, err := resolveChipSources(chip, mode)
	if err != nil {
		return nil, err
	}
	socInfo, err := resolveSoC(in, chip)
	if err != nil {
		return nil, err
	}
	chipIncs, err := chipIncludesWithFallback(in, chip, arch.Dir, socInfo.dir)
	if err != nil {
		return nil, err
	}
	crypto, err := resolveCrypto(in, chip, sdk.Version)
	if err != nil {
		return nil, err
	}
	recovery, err := resolveRecoveryWithMode(in, chip, mode, arch.Dir, socInfo.dir, contract)
	if err != nil {
		return nil, err
	}
	if recCryErr := resolveRecoveryCryptoSlots(in, chip, sdk.Version, crypto, &recovery); recCryErr != nil {
		return nil, recCryErr
	}

	cFlags, asmFlags, ldFlags := mergeChipArchFlags(arch.CompilerFlags, chip.Spec.CompilerFlags)
	var chipStartup, chipLinker string
	if chip.Spec != nil && chip.Spec.Sources != nil {
		if chip.Spec.Sources.Startup != "" {
			chipStartup, err = Contain(chip.Dir, chip.Spec.Sources.Startup)
			if err != nil {
				return nil, fmt.Errorf("startup source of chip '%s': %w", chip.Name, err)
			}
		}
		if chip.Spec.Sources.Linker != "" {
			chipLinker, err = Contain(chip.Dir, chip.Spec.Sources.Linker)
			if err != nil {
				return nil, fmt.Errorf("linker script of chip '%s': %w", chip.Name, err)
			}
		}
	}

	integration := strings.TrimSpace(in.Integration)
	if integration == "" && in.Lock != nil {
		if tl, ok := in.Lock.Targets[chip.Name]; ok && tl.Integration != "" {
			intName, _ := splitLockedRef(tl.Integration)
			integration = intName
		}
	}

	mockHW := mode.anyMockEnabled()
	for i := range drvPkgs {
		if drvPkgs[i].Mocked {
			mockHW = true
			break
		}
	}

	plan := &Plan{
		Profile:        mode.profile,
		MockHW:         mockHW,
		HalRoot:        resolveHALRoot(in, chip),
		Integration:    integration,
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
		ArchFlags:      cFlags,
		ChipCFlags:     cFlags,
		ChipAsmFlags:   asmFlags,
		ChipLDFlags:    ldFlags,
		ChipStartup:    chipStartup,
		ChipLinker:     chipLinker,
		Crypto:         crypto,
		Recovery:       recovery,
		SoCDir:         socInfo.dir,
		SoCName:        socInfo.name,
		SoCVersion:     socInfo.version,
		SoCSHA256:      socInfo.sha256,
		SoCSource:      socInfo.source,
		Coprocessors:   chip.coprocessors,
	}

	if err := enforceLockedChip(in, chip, arch, crypto); err != nil {
		return nil, err
	}
	if in.Locked {
		if err := enforceLockedV2(in, plan); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

func mergeChipArchFlags(archFlags, chipFlags *manifestpkg.CompilerFlags) (cFlags, asmFlags, ldFlags []string) {
	appendUniq := func(dst, items []string) []string {
		for _, it := range items {
			if it != "" && !slices.Contains(dst, it) {
				dst = append(dst, it)
			}
		}
		return dst
	}
	if archFlags != nil {
		cFlags = appendUniq(cFlags, archFlags.CFlags)
		asmFlags = appendUniq(asmFlags, archFlags.AsmFlags)
		ldFlags = appendUniq(ldFlags, archFlags.LDFlags)
	}
	if chipFlags != nil {
		cFlags = appendUniq(cFlags, chipFlags.CFlags)
		asmFlags = appendUniq(asmFlags, chipFlags.AsmFlags)
		ldFlags = appendUniq(ldFlags, chipFlags.LDFlags)
	}
	return cFlags, asmFlags, ldFlags
}

func splitLockedRef(ref string) (name, ver string) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" || trimmed == "none" || strings.HasPrefix(trimmed, "local:") {
		return "", ""
	}
	lastAt := strings.LastIndex(trimmed, "@")
	if lastAt <= 0 {
		return trimmed, ""
	}
	return trimmed[:lastAt], trimmed[lastAt+1:]
}

func verifyLockedBinding(kind, lockedRef, wantName, wantVer string, isLocal bool) error {
	if strings.HasPrefix(lockedRef, "local:") {
		if !isLocal {
			return fmt.Errorf("%s %q is locked to %q, but resolved from registry", kind, wantName, lockedRef)
		}
		return nil
	}
	gotName, gotVer := splitLockedRef(lockedRef)
	if gotName == "" || !strings.EqualFold(gotName, wantName) {
		return fmt.Errorf("%s %q does not match locked reference %q", kind, wantName, lockedRef)
	}
	if gotVer != "" && wantVer != "" && gotVer != wantVer {
		return fmt.Errorf("%s %q version %q does not match locked version %q", kind, wantName, wantVer, gotVer)
	}
	return nil
}

func verifyLockedPackageEntry(lf *lockfile.Lockfile, category, name, version, sha256Hex string, isLocal bool) error {
	lp := lf.FindPackage(category, name, "")
	if lp == nil {
		return fmt.Errorf("--locked build: %s %q is missing from [[package]] in toob.lock", category, name)
	}
	if isLocal {
		if lp.Source != "local" && lp.Source != "spawned" {
			return fmt.Errorf("--locked build: %s %q resolved locally, but toob.lock pins source=%q", category, name, lp.Source)
		}
	} else {
		if lp.Source == "local" || lp.Source == "spawned" {
			return fmt.Errorf("--locked build: %s %q is pinned as source=%q in toob.lock, but resolved from registry", category, name, lp.Source)
		}
	}
	if version != "" && lp.Version != "" && !strings.EqualFold(lp.Version, version) {
		return fmt.Errorf("--locked build: %s %q version %q does not match locked %q", category, name, version, lp.Version)
	}
	if !isLocal && lp.SHA256 != "" && sha256Hex != "" && lp.SHA256 != sha256Hex {
		return fmt.Errorf("--locked build: %s %q sha256 %s does not match locked %s", category, name, sha256Hex, lp.SHA256)
	}
	return nil
}

func enforceLockedV2(in Input, p *Plan) error {
	target, ok := in.Lock.Targets[p.Chip.Name]
	if !ok {
		return fmt.Errorf("--locked build requires [targets.%s] in toob.lock", p.Chip.Name)
	}
	if err := verifyLockedBinding("chip", target.Chip, p.Chip.Name, p.Chip.Version, p.Chip.Local); err != nil {
		return err
	}
	if err := verifyLockedPackageEntry(in.Lock, "chip", p.Chip.Name, p.Chip.Version, p.Chip.SHA256, p.Chip.Local); err != nil {
		return err
	}

	if err := verifyLockedBinding("arch", target.Arch, p.Arch.Name, p.Arch.Version, p.Arch.Local); err != nil {
		return err
	}
	if err := verifyLockedPackageEntry(in.Lock, "arch", p.Arch.Name, p.Arch.Version, p.Arch.SHA256, p.Arch.Local); err != nil {
		return err
	}

	if target.Toolchain != "" {
		if err := verifyLockedBinding("toolchain", target.Toolchain, p.Toolchain.Name, p.Toolchain.ExpectedVersion, false); err != nil {
			return err
		}
	}

	if p.SoCName != "" || target.SoC != "" {
		if target.SoC == "" {
			return fmt.Errorf("--locked build: resolved SoC %q is missing from [targets.%s].soc in toob.lock", p.SoCName, p.Chip.Name)
		}
		if p.SoCName == "" {
			return fmt.Errorf("--locked build: locked SoC %q could not be resolved", target.SoC)
		}
		socLocal := p.SoCSource == "local"
		if err := verifyLockedBinding("soc", target.SoC, p.SoCName, p.SoCVersion, socLocal); err != nil {
			return err
		}
		if err := verifyLockedPackageEntry(in.Lock, "soc", p.SoCName, p.SoCVersion, p.SoCSHA256, socLocal); err != nil {
			return err
		}
	}

	resolvedDrivers := make(map[string]ResolvedDriver, len(p.DriverPackages))
	for i := range p.DriverPackages {
		dp := &p.DriverPackages[i]
		key := dp.Trait
		if key == "" {
			key = dp.Name
		}
		resolvedDrivers[key] = *dp
		lockedRef, exists := target.Drivers[key]
		if !exists {
			return fmt.Errorf("--locked build: resolved driver %q (trait %q) missing from toob.lock [targets.%s].drivers",
				dp.Name, key, p.Chip.Name)
		}
		if err := verifyLockedBinding("driver "+key, lockedRef, dp.Name, dp.Version, dp.Local); err != nil {
			return err
		}
		if err := verifyLockedPackageEntry(in.Lock, "driver", dp.Name, dp.Version, dp.SHA256, dp.Local); err != nil {
			return err
		}
	}
	for trait, lockedRef := range target.Drivers {
		if lockedRef == "none" {
			continue
		}
		if _, exists := resolvedDrivers[trait]; !exists {
			return fmt.Errorf("--locked build: locked driver trait %q (%q) is missing from resolved plan", trait, lockedRef)
		}
	}

	resolvedRecDrivers := make(map[string]ResolvedDriver, len(p.Recovery.DriverPackages))
	for i := range p.Recovery.DriverPackages {
		rp := &p.Recovery.DriverPackages[i]
		resolvedRecDrivers[rp.Trait] = *rp
		lockedRef, exists := target.RecoveryDrivers[rp.Trait]
		if !exists {
			return fmt.Errorf("--locked build: resolved recovery driver %q (trait %q) missing from toob.lock [targets.%s].recovery_drivers",
				rp.Name, rp.Trait, p.Chip.Name)
		}
		if err := verifyLockedBinding("recovery driver "+rp.Trait, lockedRef, rp.Name, rp.Version, rp.Local); err != nil {
			return err
		}
		if err := verifyLockedPackageEntry(in.Lock, "driver", rp.Name, rp.Version, rp.SHA256, rp.Local); err != nil {
			return err
		}
	}
	for trait, lockedRef := range target.RecoveryDrivers {
		if lockedRef == "none" {
			continue
		}
		if _, exists := resolvedRecDrivers[trait]; !exists {
			return fmt.Errorf("--locked build: locked recovery driver trait %q (%q) is missing from resolved plan", trait, lockedRef)
		}
	}

	resolvedCryptoBySlot := make(map[string]CryptoSlot, len(p.Crypto))
	for i := range p.Crypto {
		cs := &p.Crypto[i]
		resolvedCryptoBySlot[cs.Slot] = *cs
		if !cs.Enabled() {
			if lockedRef := target.Crypto[cs.Slot]; lockedRef != "" && lockedRef != "none" {
				return fmt.Errorf("--locked build: crypto slot %q is disabled, but toob.lock locks %q", cs.Slot, lockedRef)
			}
			continue
		}
		lockedRef, exists := target.Crypto[cs.Slot]
		if !exists || lockedRef == "none" {
			return fmt.Errorf("--locked build: enabled crypto slot %q (%q) missing from toob.lock [targets.%s].crypto",
				cs.Slot, cs.Name, p.Chip.Name)
		}
		if err := verifyLockedBinding("crypto "+cs.Slot, lockedRef, cs.Name, cs.Version, cs.Local); err != nil {
			return err
		}
		if err := verifyLockedPackageEntry(in.Lock, "crypto", cs.Name, cs.Version, cs.SHA256, cs.Local); err != nil {
			return err
		}
	}
	for slot, lockedRef := range target.Crypto {
		if lockedRef == "" || lockedRef == "none" {
			continue
		}
		if cs, ok := resolvedCryptoBySlot[slot]; !ok || !cs.Enabled() {
			return fmt.Errorf("--locked build: locked crypto slot %q (%q) is not active in resolved plan", slot, lockedRef)
		}
	}

	if err := verifyLockedRecoveryCrypto(in.Lock, p, target); err != nil {
		return err
	}
	return nil
}

func verifyLockedRecoveryCrypto(lf *lockfile.Lockfile, p *Plan, target lockfile.TargetLock) error {
	checkSlot := func(slotKey, resolvedVal string, slotPkg *CryptoSlot) error {
		lockedRef := target.RecoveryCrypto[slotKey]
		normResolved := normalizeRecoveryCryptoRef(resolvedVal)
		if normResolved == "" {
			normResolved = "none"
		}
		switch normResolved {
		case "none":
			if lockedRef != "" && lockedRef != "none" {
				return fmt.Errorf("--locked build: recovery crypto %s is disabled, but locked as %q", slotKey, lockedRef)
			}
			return nil
		case "rom":
			lockedBase, _ := splitLockedRef(lockedRef)
			if lockedRef != "rom" && lockedBase != "rom" {
				return fmt.Errorf("--locked build: recovery crypto %s is 'rom', but locked as %q", slotKey, lockedRef)
			}
			return nil
		default:
			if lockedRef == "" || lockedRef == "none" {
				return fmt.Errorf("--locked build: recovery crypto %s (%q) missing from toob.lock", slotKey, normResolved)
			}
			var ver, sha string
			var isLocal bool
			if slotPkg != nil && slotPkg.Enabled() {
				ver, sha, isLocal = slotPkg.Version, slotPkg.SHA256, slotPkg.Local
			} else {
				for i := range p.Crypto {
					if p.Crypto[i].Enabled() && p.Crypto[i].Name == normResolved {
						ver, sha, isLocal = p.Crypto[i].Version, p.Crypto[i].SHA256, p.Crypto[i].Local
						break
					}
				}
			}
			if err := verifyLockedBinding("recovery crypto "+slotKey, lockedRef, normResolved, ver, isLocal); err != nil {
				return err
			}
			return verifyLockedPackageEntry(lf, "crypto", normResolved, ver, sha, isLocal)
		}
	}

	if p.Recovery.Declared || len(target.RecoveryCrypto) > 0 {
		if err := checkSlot("backend", p.Recovery.Backend, p.Recovery.BackendSlot); err != nil {
			return err
		}
		if err := checkSlot("hash", p.Recovery.Hash, p.Recovery.HashSlot); err != nil {
			return err
		}
	}
	return nil
}

// ToLockfile materializes a validated Lockfile v2 pinning every resolved package,
// target slot binding, toolchain digest, registry revision, and SDK/compiler env.
func (p *Plan) ToLockfile(
	cache *registry.Cache,
	existing *lockfile.Lockfile,
	regURL, regRev, indexSHA, coreSDKSHA, compilerDigest string,
) (*lockfile.Lockfile, error) {
	if p == nil {
		return nil, errors.New("cannot build lockfile from nil resolve plan")
	}

	lf := lockfile.NewV2()
	if existing != nil {
		lf.Registry = existing.Registry
		lf.Environment = existing.Environment
		lf.Packages = slices.Clone(existing.Packages)
		maps.Copy(lf.Toolchains, existing.Toolchains)
		maps.Copy(lf.Targets, existing.Targets)
	}

	if regURL != "" {
		lf.Registry.URL = regURL
	} else if lf.Registry.URL == "" && cache != nil {
		lf.Registry.URL = cache.Remote()
	}
	if regRev != "" {
		lf.Registry.Revision = regRev
	}
	if indexSHA != "" {
		lf.Registry.IndexSHA256 = indexSHA
	}
	if cache != nil {
		if commit, err := cache.HeadCommit(); err == nil && commit != "" {
			lf.Registry.Commit = commit
		}
	}

	lf.Environment.CoreSDK = p.CoreSDK.Version
	lf.Environment.CoreSDKSHA256 = firstNonEmpty(coreSDKSHA, p.CoreSDK.SHA256, lf.Environment.CoreSDKSHA256)
	lf.Environment.Compiler = p.Compiler
	lf.Environment.CompilerDigest = firstNonEmpty(compilerDigest, lf.Environment.CompilerDigest)

	if p.Toolchain.Name != "" {
		ver := firstNonEmpty(p.Toolchain.ExpectedVersion, p.Toolchain.UpstreamVersion, "0.0.0")
		lf.Toolchains[p.Toolchain.Name] = lockfile.ToolchainEntry{
			Version: ver,
			SHA256:  maps.Clone(p.Toolchain.SHA256),
		}
	}

	target := lockfile.TargetLock{
		Drivers:         make(map[string]string),
		Crypto:          make(map[string]string),
		RecoveryDrivers: make(map[string]string),
		RecoveryCrypto:  make(map[string]string),
	}

	lockPkg := func(cat, name, ver, sha, dir, trait, localRel string, local bool) (string, error) {
		var baseVer, baseSHA string
		source := "registry"
		if local {
			source = "local"
			if existing != nil {
				if prev := existing.FindPackage(cat, name, ""); prev != nil {
					if prev.Source == "spawned" || prev.BaseVersion != "" || prev.BaseSHA256 != "" {
						source = "spawned"
						baseVer = prev.BaseVersion
						baseSHA = prev.BaseSHA256
					}
				}
			}
		}

		resolvedSHA := sha
		if resolvedSHA == "" && dir != "" {
			if st, err := os.Stat(dir); err == nil && st.IsDir() {
				computed, hashErr := hashPackageDir(dir)
				if hashErr != nil {
					return "", fmt.Errorf("computing sha256 for %s %q: %w", cat, name, hashErr)
				}
				resolvedSHA = computed
			}
		}
		if source == "registry" && resolvedSHA == "" {
			return "", fmt.Errorf("cannot lock registry %s %q@%q without sha256 digest or package directory", cat, name, ver)
		}

		lf.UpsertPackage(lockfile.LockedPackage{
			Category:    cat,
			Name:        name,
			Version:     ver,
			Source:      source,
			SHA256:      resolvedSHA,
			BaseVersion: baseVer,
			BaseSHA256:  baseSHA,
			Trait:       trait,
		})

		if local && ver == "" {
			if localRel == "" {
				localRel = path.Join("toobloader", "hal", cat, name)
			}
			return "local:" + filepath.ToSlash(localRel), nil
		}
		return name + "@" + ver, nil
	}

	var err error
	target.Chip, err = lockPkg("chip", p.Chip.Name, p.Chip.Version, p.Chip.SHA256, p.Chip.Dir, "",
		path.Join("toobloader", "hal", "chips", p.Chip.Name), p.Chip.Local)
	if err != nil {
		return nil, err
	}

	archVer := firstNonEmpty(p.Arch.Version, "1.0.0")
	target.Arch, err = lockPkg("arch", p.Arch.Name, archVer, p.Arch.SHA256, p.Arch.Dir, "",
		path.Join("toobloader", "hal", "arch", p.Arch.Name), p.Arch.Local)
	if err != nil {
		return nil, err
	}

	if p.Toolchain.Name != "" {
		tcVer := firstNonEmpty(p.Toolchain.ExpectedVersion, p.Toolchain.UpstreamVersion, "0.0.0")
		target.Toolchain = p.Toolchain.Name + "@" + tcVer
	}

	if p.SoCName != "" {
		socLocal := p.SoCSource == "local"
		socVer := firstNonEmpty(p.SoCVersion, "1.0.0")
		target.SoC, err = lockPkg("soc", p.SoCName, socVer, p.SoCSHA256, p.SoCDir, "",
			path.Join("toobloader", "hal", "soc", p.SoCName), socLocal)
		if err != nil {
			return nil, err
		}
	}

	if p.Integration != "" {
		target.Integration = p.Integration + "@1.0.0"
	}

	for i := range p.DriverPackages {
		dp := &p.DriverPackages[i]
		traitKey := dp.Trait
		if traitKey == "" {
			traitKey = dp.Name
		}
		drvVer := firstNonEmpty(dp.Version, "1.0.0")
		ref, lockErr := lockPkg("driver", dp.Name, drvVer, dp.SHA256, dp.Dir, dp.Trait,
			path.Join("toobloader", "hal", "drivers", dp.Name), dp.Local)
		if lockErr != nil {
			return nil, lockErr
		}
		target.Drivers[traitKey] = ref
	}

	stage1Refs := make(map[string]string, len(p.Crypto))
	for i := range p.Crypto {
		cs := &p.Crypto[i]
		if !cs.Enabled() {
			continue
		}
		cVer := firstNonEmpty(cs.Version, "1.0.0")
		ref, lockErr := lockPkg("crypto", cs.Name, cVer, cs.SHA256, cs.Dir, cs.Slot,
			path.Join("toobloader", "hal", "crypto", cs.Name), cs.Local)
		if lockErr != nil {
			return nil, lockErr
		}
		target.Crypto[cs.Slot] = ref
		stage1Refs[cs.Name] = ref
	}

	for i := range p.Recovery.DriverPackages {
		rp := &p.Recovery.DriverPackages[i]
		drvVer := firstNonEmpty(rp.Version, "1.0.0")
		ref, lockErr := lockPkg("driver", rp.Name, drvVer, rp.SHA256, rp.Dir, rp.Trait,
			path.Join("toobloader", "hal", "drivers", rp.Name), rp.Local)
		if lockErr != nil {
			return nil, lockErr
		}
		target.RecoveryDrivers[rp.Trait] = ref
	}

	if p.Recovery.Declared {
		recordRecCrypto := func(slotKey, raw string, slotPkg *CryptoSlot) error {
			norm := normalizeRecoveryCryptoRef(raw)
			switch norm {
			case "", "none":
				if norm == "none" {
					target.RecoveryCrypto[slotKey] = "none"
				}
			case "rom":
				target.RecoveryCrypto[slotKey] = "rom@builtin"
			default:
				if slotPkg != nil && slotPkg.Enabled() {
					cVer := firstNonEmpty(slotPkg.Version, "1.0.0")
					ref, lockErr := lockPkg("crypto", slotPkg.Name, cVer, slotPkg.SHA256, slotPkg.Dir, slotPkg.Slot,
						path.Join("toobloader", "hal", "crypto", slotPkg.Name), slotPkg.Local)
					if lockErr != nil {
						return lockErr
					}
					target.RecoveryCrypto[slotKey] = ref
				} else if existingRef, ok := stage1Refs[norm]; ok {
					target.RecoveryCrypto[slotKey] = existingRef
				}
			}
			return nil
		}
		if err := recordRecCrypto("backend", p.Recovery.Backend, p.Recovery.BackendSlot); err != nil {
			return nil, err
		}
		if err := recordRecCrypto("hash", p.Recovery.Hash, p.Recovery.HashSlot); err != nil {
			return nil, err
		}
	}

	lf.Targets[p.Chip.Name] = target
	if err := lf.Validate(); err != nil {
		return nil, fmt.Errorf("generated lockfile failed validation: %w", err)
	}
	return lf, nil
}

func hashPackageDir(rootDir string) (string, error) {
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
	slices.Sort(files)

	h := sha256.New()
	for _, rel := range files {
		_, _ = fmt.Fprintf(h, "%s\n", rel)
		f, openErr := os.Open(filepath.Join(rootDir, filepath.FromSlash(rel)))
		if openErr != nil {
			return "", openErr
		}
		if _, copyErr := io.Copy(h, f); copyErr != nil {
			_ = f.Close()
			return "", copyErr
		}
		if closeErr := f.Close(); closeErr != nil {
			return "", closeErr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	if rec.Backend != "" && rec.Backend != "rom" && rec.Backend != "none" && rec.Backend != stage1Backend {
		slot, err := resolveCryptoPackage(in, chip, coreSDK, "recovery_backend", rec.Backend)
		if err != nil {
			return fmt.Errorf("recovery.crypto.backend: %w", err)
		}
		rec.BackendSlot = &slot
	}
	if rec.Hash != "" && rec.Hash != "none" && rec.Hash != stage1Hash && rec.Hash != stage1Backend {
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

type resolvedSoC struct {
	name    string
	version string
	sha256  string
	source  string
	dir     string
}

// resolveSoC checks local toobloader/hal/soc overrides before registry SoCs and
// propagates Source/Cache lookup errors fail-fast instead of swallowing them (HIGH-89).
func resolveSoC(in Input, chip *Chip) (resolvedSoC, error) {
	if chip == nil {
		return resolvedSoC{}, nil
	}
	targetChip := normalizeChipMatchKey(chip.Name)

	// 1. Check local workspace SoC override (<root>/toobloader/hal/soc or soc/<name>).
	halBase := localHALRoot(in)
	if halBase != "" {
		localSoCRoot := filepath.Join(halBase, "soc")
		if ok, err := isDir(localSoCRoot); err != nil {
			return resolvedSoC{}, err
		} else if ok {
			if matched, found := matchLocalSoCDir(localSoCRoot, targetChip, in.Index); found {
				return matched, nil
			}
		}
	}

	if in.Registry == nil || in.Index == nil || len(in.Index.SoCs) == 0 {
		return resolvedSoC{}, nil
	}

	for _, key := range slices.Sorted(maps.Keys(in.Index.SoCs)) {
		soc := in.Index.SoCs[key]
		matched := slices.ContainsFunc(soc.Chips, func(c string) bool {
			return normalizeChipMatchKey(c) == targetChip
		})
		if !matched {
			continue
		}
		socRef := firstNonEmpty(soc.Name, key)
		dir, err := in.Registry.SoCSourcePath(socRef)
		if err != nil {
			return resolvedSoC{}, fmt.Errorf("failed to resolve SoC package '%s' for chip '%s': %w", socRef, chip.Name, err)
		}
		ver := soc.Version
		if mVer := readSoCManifestVersion(dir); mVer != "" && ver == "" {
			ver = mVer
		}
		return resolvedSoC{
			name:    socRef,
			version: ver,
			sha256:  firstNonEmpty(soc.SHA256, soc.TarballSHA),
			source:  "registry",
			dir:     dir,
		}, nil
	}
	return resolvedSoC{}, nil
}

type socManifestPartial struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Chips   []string `json:"chips"`
}

func readSoCManifestVersion(dir string) string {
	mPath, err := Contain(dir, socManifestFile)
	if err != nil {
		return ""
	}
	var m socManifestPartial
	if err := decodeJSONFile(mPath, &m, false); err != nil {
		return ""
	}
	return m.Version
}

func matchLocalSoCDir(localSoCRoot, targetChip string, idx *registry.Index) (resolvedSoC, bool) {
	// Check soc_manifest.json directly inside hal/soc/.
	if mPath, err := Contain(localSoCRoot, socManifestFile); err == nil {
		var m socManifestPartial
		if decErr := decodeJSONFile(mPath, &m, false); decErr == nil {
			if slices.ContainsFunc(m.Chips, func(c string) bool {
				return normalizeChipMatchKey(c) == targetChip
			}) {
				return resolvedSoC{
					name:    firstNonEmpty(m.Name, "soc"),
					version: m.Version,
					source:  "local",
					dir:     localSoCRoot,
				}, true
			}
		}
	}

	// Check named subdirectories under hal/soc/<socName>/ via index or soc_manifest.json.
	entries, err := os.ReadDir(localSoCRoot)
	if err != nil {
		return resolvedSoC{}, false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subDir := filepath.Join(localSoCRoot, e.Name())
		if mPath, err := Contain(subDir, socManifestFile); err == nil {
			var m socManifestPartial
			if decErr := decodeJSONFile(mPath, &m, false); decErr == nil {
				if slices.ContainsFunc(m.Chips, func(c string) bool {
					return normalizeChipMatchKey(c) == targetChip
				}) {
					return resolvedSoC{
						name:    firstNonEmpty(m.Name, e.Name()),
						version: m.Version,
						source:  "local",
						dir:     subDir,
					}, true
				}
			}
		}
		if idx != nil {
			if info, ok := idx.SoCs[e.Name()]; ok {
				if slices.ContainsFunc(info.Chips, func(c string) bool {
					return normalizeChipMatchKey(c) == targetChip
				}) {
					return resolvedSoC{
						name:    firstNonEmpty(info.Name, e.Name()),
						version: info.Version,
						source:  "local",
						dir:     subDir,
					}, true
				}
			}
		}
	}
	return resolvedSoC{}, false
}

func resolveCompiler(in Input) (string, error) {
	devCompiler := strings.TrimSpace(in.Device.Build.Compiler)
	var lockedCompiler string
	if in.Lock != nil {
		lockedCompiler = strings.TrimSpace(in.Lock.Environment.Compiler)
	}

	if in.Locked {
		if in.Lock == nil || lockedCompiler == "" {
			return "", errors.New("--locked build requires [environment].compiler in toob.lock")
		}
		if devCompiler != "" && devCompiler != lockedCompiler {
			return "", fmt.Errorf("--locked build rejects unlocked device.toml [build] compiler override %q (locked: %q)",
				devCompiler, lockedCompiler)
		}
		if err := manifestpkg.ValidateName("locked compiler version", lockedCompiler); err != nil {
			return "", fmt.Errorf("toob.lock [environment] compiler: %w", err)
		}
		return lockedCompiler, nil
	}

	compiler := firstNonEmpty(devCompiler, lockedCompiler, "latest")
	if err := manifestpkg.ValidateName("compiler version", compiler); err != nil {
		return "", fmt.Errorf("device.toml [build] compiler: %w", err)
	}
	return compiler, nil
}
