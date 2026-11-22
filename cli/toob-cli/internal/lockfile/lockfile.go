// Package lockfile manages the toob.lock file for reproducible builds (Lockfile v2
// with backward-compatible loading and migration of legacy v1 lockfiles).
//
// BOUNDARY TYPES: Struct types in this file are mirrored in internal/ports/ports.go.
package lockfile

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/toob-boot/toob/internal/httputil"
)

const (
	// FormatVersionV2 is the canonical Lockfile v2 schema version.
	FormatVersionV2 = 2

	maxLockfileBytes = 1 << 20 // 1 MiB
	emptyFileSHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	singleTokenPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	strictPackagePattern    = regexp.MustCompile(`^(@[a-z0-9][a-z0-9_-]*/)?[a-z0-9][a-z0-9._+-]*$`)
	legacyScopePattern      = regexp.MustCompile(`^@[A-Za-z0-9][A-Za-z0-9._-]*$`)
	platformKeyPattern      = regexp.MustCompile(`^[a-z0-9]+_[a-z0-9]+$`)
	traitSlotKeyPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	compilerDigestHexSuffix = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

var validCategories = map[string]bool{
	"chip":        true,
	"arch":        true,
	"driver":      true,
	"crypto":      true,
	"soc":         true,
	"integration": true,
	"toolchain":   true,
	"port":        true,
}

// RegistryLock pins the upstream registry origin, snapshot revision, and index digest.
type RegistryLock struct {
	URL         string `toml:"url,omitempty"`
	Revision    string `toml:"revision,omitempty"`
	IndexSHA256 string `toml:"index_sha256,omitempty"`

	// Legacy v1 compatibility fields.
	Version string `toml:"version,omitempty"`
	Commit  string `toml:"commit,omitempty"`
}

// EnvironmentLock pins the Core SDK and compiler container image digests.
type EnvironmentLock struct {
	CoreSDK        string `toml:"core_sdk,omitempty"`
	CoreSDKSHA256  string `toml:"core_sdk_sha256,omitempty"`
	Compiler       string `toml:"compiler,omitempty"`
	CompilerDigest string `toml:"compiler_digest,omitempty"`
}

// LockedPackage represents one resolved package node in Lockfile v2.
type LockedPackage struct {
	Category    string `toml:"category"`
	Name        string `toml:"name"`
	Version     string `toml:"version"`
	Source      string `toml:"source"` // "registry" | "spawned" | "local"
	SHA256      string `toml:"sha256,omitempty"`
	BaseVersion string `toml:"base_version,omitempty"`
	BaseSHA256  string `toml:"base_sha256,omitempty"`
	Trait       string `toml:"trait,omitempty"`
}

// ChipEntry is the legacy Lockfile v1 [[chip]] block retained for compatibility.
type ChipEntry struct {
	Name             string `toml:"name"`
	Version          string `toml:"version"`
	Arch             string `toml:"arch"`
	ArchVersion      string `toml:"arch_version"`
	Toolchain        string `toml:"toolchain"`
	ToolchainVersion string `toml:"toolchain_version"`
	CryptoBackend    string `toml:"crypto_backend"`
	CryptoHash       string `toml:"crypto_hash"`
	CryptoPqc        string `toml:"crypto_pqc"`
	Spawned          bool   `toml:"spawned"`
}

// ToolchainEntry pins a toolchain version and per-platform archive SHA-256 digests.
type ToolchainEntry struct {
	Version string            `toml:"version"`
	SHA256  map[string]string `toml:"sha256,omitempty"`
}

// TargetLock records the complete resolved dependency graph for one target chip.
type TargetLock struct {
	Chip            string            `toml:"chip"`
	Arch            string            `toml:"arch,omitempty"`
	Toolchain       string            `toml:"toolchain,omitempty"`
	SoC             string            `toml:"soc,omitempty"`
	Integration     string            `toml:"integration,omitempty"`
	Drivers         map[string]string `toml:"drivers,omitempty"`
	Crypto          map[string]string `toml:"crypto,omitempty"`
	RecoveryDrivers map[string]string `toml:"recovery_drivers,omitempty"`
	RecoveryCrypto  map[string]string `toml:"recovery_crypto,omitempty"`
}

// Lockfile is the in-memory representation of toob.lock.
type Lockfile struct {
	FormatVersion int                       `toml:"format_version,omitempty"`
	Registry      RegistryLock              `toml:"registry"`
	Environment   EnvironmentLock           `toml:"environment"`
	Packages      []LockedPackage           `toml:"package,omitempty"`
	Chips         []ChipEntry               `toml:"chip,omitempty"`
	Toolchains    map[string]ToolchainEntry `toml:"toolchains,omitempty"`
	Targets       map[string]TargetLock     `toml:"targets,omitempty"`
}

// NewV2 constructs an initialized Lockfile v2 instance.
func NewV2() *Lockfile {
	return &Lockfile{
		FormatVersion: FormatVersionV2,
		Packages:      make([]LockedPackage, 0),
		Chips:         make([]ChipEntry, 0),
		Toolchains:    make(map[string]ToolchainEntry),
		Targets:       make(map[string]TargetLock),
	}
}

func (lf *Lockfile) isV2Mode() bool {
	return lf.FormatVersion == FormatVersionV2 ||
		len(lf.Packages) > 0 && len(lf.Chips) == 0 ||
		len(lf.Targets) > 0 && len(lf.Chips) == 0 ||
		lf.Registry.URL != "" ||
		lf.Registry.IndexSHA256 != "" ||
		lf.Environment.CoreSDKSHA256 != "" ||
		lf.Environment.CompilerDigest != ""
}

// ValidatePackageToken validates a lowercase unscoped or @scope/pkg package identifier.
func ValidatePackageToken(field, val string) error {
	if val == "" {
		return fmt.Errorf("lockfile %s must not be empty", field)
	}
	if strings.Contains(val, "..") || !strictPackagePattern.MatchString(val) {
		return fmt.Errorf("lockfile %s contains invalid package identifier %q", field, val)
	}
	return nil
}

func validateSingleToken(field, val string) error {
	if val == "" {
		return fmt.Errorf("lockfile %s must not be empty", field)
	}
	if strings.Contains(val, "..") || !singleTokenPattern.MatchString(val) {
		return fmt.Errorf("lockfile %s contains unsafe value %q", field, val)
	}
	return nil
}

func validateLegacyPackageToken(field, val string) error {
	if strings.HasPrefix(val, "@") {
		scope, pkg, ok := strings.Cut(val, "/")
		if !ok || strings.Contains(pkg, "/") || strings.Contains(scope, "..") || !legacyScopePattern.MatchString(scope) {
			return fmt.Errorf("lockfile %s contains invalid scoped reference %q", field, val)
		}
		return validateSingleToken(field, pkg)
	}
	return validateSingleToken(field, val)
}

func validateCoreSDKToken(field, val string) error {
	if rest, ok := strings.CutPrefix(val, "core/"); ok {
		return validateSingleToken(field, rest)
	}
	return validateSingleToken(field, val)
}

func validateHexSHA256(field, val string) error {
	clean := strings.ToLower(strings.TrimSpace(val))
	decoded, err := hex.DecodeString(clean)
	if err != nil || len(decoded) != sha256.Size || val != clean {
		return fmt.Errorf("lockfile %s contains invalid sha256 digest %q (expected 64 lowercase hex chars)", field, val)
	}
	if clean == emptyFileSHA256 {
		return fmt.Errorf("lockfile %s refuses placeholder empty-file sha256 digest", field)
	}
	return nil
}

func validateLocalRef(field, rawPath string) error {
	if strings.TrimSpace(rawPath) == "" {
		return fmt.Errorf("lockfile %s local: path must not be empty", field)
	}
	for _, r := range rawPath {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("lockfile %s contains control characters", field)
		}
	}
	if strings.Contains(rawPath, ":") || filepath.IsAbs(rawPath) || strings.HasPrefix(rawPath, "/") || strings.HasPrefix(rawPath, `\`) {
		return fmt.Errorf("lockfile %s local path %q must be relative", field, rawPath)
	}
	slash := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rawPath)))
	if slash == "." || slash == ".." || strings.HasPrefix(slash, "../") || strings.Contains(rawPath, "..") {
		return fmt.Errorf("lockfile %s local path %q escapes workspace", field, rawPath)
	}
	return nil
}

func validateTargetBindingRef(field, ref string, strictV2 bool) error {
	if ref == "none" {
		return nil
	}
	if localRel, ok := strings.CutPrefix(ref, "local:"); ok {
		return validateLocalRef(field, localRel)
	}
	lastAt := strings.LastIndex(ref, "@")
	if lastAt <= 0 {
		if !strictV2 {
			return validateLegacyPackageToken(field, ref)
		}
		return fmt.Errorf("lockfile %s must use <name>@<version>, \"none\", or \"local:<path>\", got %q", field, ref)
	}
	name, ver := ref[:lastAt], ref[lastAt+1:]
	if err := ValidatePackageToken(field, name); err != nil {
		if strictV2 {
			return err
		}
		if legErr := validateLegacyPackageToken(field, name); legErr != nil {
			return legErr
		}
	}
	return validateSingleToken(field+" version", ver)
}

func validateTargetMap(prefix string, m map[string]string, strictV2 bool) error {
	seenKeys := make(map[string]string, len(m))
	for slot, ref := range m {
		if !traitSlotKeyPattern.MatchString(slot) {
			return fmt.Errorf("lockfile %s has invalid slot/trait key %q", prefix, slot)
		}
		folded := strings.ToLower(slot)
		if prev, exists := seenKeys[folded]; exists {
			return fmt.Errorf("lockfile %s has duplicate slot key %q and %q", prefix, prev, slot)
		}
		seenKeys[folded] = slot
		if err := validateTargetBindingRef(prefix+"."+slot, ref, strictV2); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks every lockfile field against path traversal, CMake separators,
// leading dashes, duplicate keys, unknown format versions, and missing digests.
func (lf *Lockfile) Validate() error {
	if lf == nil {
		return errors.New("lockfile is nil")
	}
	if lf.FormatVersion < 0 || lf.FormatVersion > FormatVersionV2 {
		return fmt.Errorf("unsupported lockfile format_version %d (supported: <= %d)", lf.FormatVersion, FormatVersionV2)
	}

	strictV2 := lf.FormatVersion == FormatVersionV2

	if lf.Registry.URL != "" {
		if _, err := httputil.ValidateHTTPSOrLoopbackURL(lf.Registry.URL); err != nil {
			return fmt.Errorf("lockfile registry.url: %w", err)
		}
	}
	if lf.Registry.Revision != "" {
		if err := validateSingleToken("registry.revision", lf.Registry.Revision); err != nil {
			return err
		}
	}
	if lf.Registry.IndexSHA256 != "" {
		if err := validateHexSHA256("registry.index_sha256", lf.Registry.IndexSHA256); err != nil {
			return err
		}
	}
	if lf.Registry.Version != "" {
		if err := validateSingleToken("registry.version", lf.Registry.Version); err != nil {
			return err
		}
	}
	if lf.Registry.Commit != "" {
		if err := validateSingleToken("registry.commit", lf.Registry.Commit); err != nil {
			return err
		}
	}

	if lf.Environment.Compiler != "" {
		if err := validateSingleToken("environment.compiler", lf.Environment.Compiler); err != nil {
			return err
		}
	}
	if lf.Environment.CompilerDigest != "" {
		if !compilerDigestHexSuffix.MatchString(lf.Environment.CompilerDigest) {
			return fmt.Errorf("lockfile environment.compiler_digest must match sha256:<64-lowercase-hex>, got %q", lf.Environment.CompilerDigest)
		}
	}
	if lf.Environment.CoreSDK != "" {
		if err := validateCoreSDKToken("environment.core_sdk", lf.Environment.CoreSDK); err != nil {
			return err
		}
	}
	if lf.Environment.CoreSDKSHA256 != "" {
		if err := validateHexSHA256("environment.core_sdk_sha256", lf.Environment.CoreSDKSHA256); err != nil {
			return err
		}
	}

	if err := lf.validatePackages(strictV2); err != nil {
		return err
	}
	if err := lf.validateChips(); err != nil {
		return err
	}
	if err := lf.validateToolchains(strictV2); err != nil {
		return err
	}
	return lf.validateTargets(strictV2)
}

func (lf *Lockfile) validatePackages(strictV2 bool) error {
	seenPkgs := make(map[string]int, len(lf.Packages))
	for i := range lf.Packages {
		p := &lf.Packages[i]
		prefix := fmt.Sprintf("package[%d]", i)
		if !validCategories[p.Category] {
			return fmt.Errorf("lockfile %s.category %q is not a recognized package category", prefix, p.Category)
		}
		if strictV2 {
			if err := ValidatePackageToken(prefix+".name", p.Name); err != nil {
				return err
			}
		} else if err := validateLegacyPackageToken(prefix+".name", p.Name); err != nil {
			return err
		}

		switch p.Source {
		case "registry", "spawned", "local":
		default:
			return fmt.Errorf("lockfile %s.source must be \"registry\", \"spawned\", or \"local\", got %q", prefix, p.Source)
		}

		if p.Source != "local" || p.Version != "" {
			if err := validateSingleToken(prefix+".version", p.Version); err != nil {
				return err
			}
		}

		if p.Source == "registry" && strictV2 && p.SHA256 == "" {
			return fmt.Errorf("lockfile %s (%s@%s) with source=\"registry\" requires a sha256 digest", prefix, p.Name, p.Version)
		}
		if p.SHA256 != "" {
			if err := validateHexSHA256(prefix+".sha256", p.SHA256); err != nil {
				return err
			}
		}
		if p.BaseVersion != "" {
			if err := validateSingleToken(prefix+".base_version", p.BaseVersion); err != nil {
				return err
			}
		}
		if p.BaseSHA256 != "" {
			if err := validateHexSHA256(prefix+".base_sha256", p.BaseSHA256); err != nil {
				return err
			}
		}
		if p.Trait != "" && !traitSlotKeyPattern.MatchString(p.Trait) {
			return fmt.Errorf("lockfile %s.trait contains invalid value %q", prefix, p.Trait)
		}

		dupKey := strings.ToLower(p.Category) + "\x00" + strings.ToLower(p.Name) + "\x00" + strings.ToLower(p.Version)
		if firstIdx, exists := seenPkgs[dupKey]; exists {
			return fmt.Errorf("lockfile contains duplicate package entry (%s, %s, %s) at indices %d and %d",
				p.Category, p.Name, p.Version, firstIdx, i)
		}
		seenPkgs[dupKey] = i
	}
	return nil
}

func (lf *Lockfile) validateChips() error {
	seenChips := make(map[string]int, len(lf.Chips))
	for i := range lf.Chips {
		e := &lf.Chips[i]
		if err := validateLegacyPackageToken(fmt.Sprintf("chip[%d].name", i), e.Name); err != nil {
			return err
		}
		folded := strings.ToLower(e.Name)
		if firstIdx, exists := seenChips[folded]; exists {
			return fmt.Errorf("lockfile contains duplicate chip entry %q at indices %d and %d", e.Name, firstIdx, i)
		}
		seenChips[folded] = i

		if e.Version != "" {
			if err := validateSingleToken(fmt.Sprintf("chip[%d].version", i), e.Version); err != nil {
				return err
			}
		}
		if e.Arch != "" {
			if err := validateLegacyPackageToken(fmt.Sprintf("chip[%d].arch", i), e.Arch); err != nil {
				return err
			}
		}
		if e.ArchVersion != "" {
			if err := validateSingleToken(fmt.Sprintf("chip[%d].arch_version", i), e.ArchVersion); err != nil {
				return err
			}
		}
		if e.Toolchain != "" {
			if err := validateLegacyPackageToken(fmt.Sprintf("chip[%d].toolchain", i), e.Toolchain); err != nil {
				return err
			}
		}
		if e.ToolchainVersion != "" {
			if err := validateSingleToken(fmt.Sprintf("chip[%d].toolchain_version", i), e.ToolchainVersion); err != nil {
				return err
			}
		}
		if e.CryptoBackend != "" && e.CryptoBackend != "none" {
			if err := validateLegacyPackageToken(fmt.Sprintf("chip[%d].crypto_backend", i), e.CryptoBackend); err != nil {
				return err
			}
		}
		if e.CryptoHash != "" && e.CryptoHash != "none" {
			if err := validateLegacyPackageToken(fmt.Sprintf("chip[%d].crypto_hash", i), e.CryptoHash); err != nil {
				return err
			}
		}
		if e.CryptoPqc != "" && e.CryptoPqc != "none" {
			if err := validateLegacyPackageToken(fmt.Sprintf("chip[%d].crypto_pqc", i), e.CryptoPqc); err != nil {
				return err
			}
		}
	}
	return nil
}

func (lf *Lockfile) validateToolchains(strictV2 bool) error {
	seenTC := make(map[string]string, len(lf.Toolchains))
	for name, tc := range lf.Toolchains {
		if strictV2 {
			if err := ValidatePackageToken("toolchains key", name); err != nil {
				return err
			}
		} else if err := validateLegacyPackageToken("toolchains key", name); err != nil {
			return err
		}

		folded := strings.ToLower(name)
		if prev, exists := seenTC[folded]; exists {
			return fmt.Errorf("lockfile contains case-colliding toolchain keys %q and %q", prev, name)
		}
		seenTC[folded] = name

		if tc.Version != "" {
			if err := validateSingleToken("toolchains."+name+".version", tc.Version); err != nil {
				return err
			}
		}
		for plat, sum := range tc.SHA256 {
			if !platformKeyPattern.MatchString(plat) {
				return fmt.Errorf("lockfile toolchains.%s.sha256 has invalid platform key %q", name, plat)
			}
			if err := validateHexSHA256(fmt.Sprintf("toolchains.%s.sha256.%s", name, plat), sum); err != nil {
				return err
			}
		}
	}
	return nil
}

func (lf *Lockfile) validateTargets(strictV2 bool) error {
	seenTargets := make(map[string]string, len(lf.Targets))
	for key, t := range lf.Targets {
		if strictV2 {
			if err := ValidatePackageToken("targets key", key); err != nil {
				return err
			}
		} else if err := validateLegacyPackageToken("targets key", key); err != nil {
			return err
		}

		folded := strings.ToLower(key)
		if prev, exists := seenTargets[folded]; exists {
			return fmt.Errorf("lockfile contains case-colliding target keys %q and %q", prev, key)
		}
		seenTargets[folded] = key

		prefix := "targets." + key
		if err := validateTargetBindingRef(prefix+".chip", t.Chip, strictV2); err != nil {
			return err
		}
		for _, pair := range []struct {
			field string
			val   string
		}{
			{".arch", t.Arch},
			{".toolchain", t.Toolchain},
			{".soc", t.SoC},
			{".integration", t.Integration},
		} {
			if pair.val != "" {
				if err := validateTargetBindingRef(prefix+pair.field, pair.val, strictV2); err != nil {
					return err
				}
			}
		}
		if err := validateTargetMap(prefix+".drivers", t.Drivers, strictV2); err != nil {
			return err
		}
		if err := validateTargetMap(prefix+".crypto", t.Crypto, strictV2); err != nil {
			return err
		}
		if err := validateTargetMap(prefix+".recovery_drivers", t.RecoveryDrivers, strictV2); err != nil {
			return err
		}
		if err := validateTargetMap(prefix+".recovery_crypto", t.RecoveryCrypto, strictV2); err != nil {
			return err
		}
	}
	return nil
}

func (lf *Lockfile) migrateLegacyV1InMemory() {
	if lf.FormatVersion == FormatVersionV2 {
		return
	}
	if lf.Registry.Revision == "" && lf.Registry.Commit != "" {
		lf.Registry.Revision = lf.Registry.Commit
	}
	if len(lf.Chips) == 0 || (len(lf.Packages) > 0 && len(lf.Targets) > 0) {
		return
	}
	if lf.Targets == nil {
		lf.Targets = make(map[string]TargetLock, len(lf.Chips))
	}

	for i := range lf.Chips {
		c := &lf.Chips[i]
		src := "registry"
		if c.Spawned {
			src = "spawned"
		}
		if c.Version != "" {
			lf.UpsertPackage(LockedPackage{
				Category: "chip",
				Name:     c.Name,
				Version:  c.Version,
				Source:   src,
			})
		}
		if c.Arch != "" && c.ArchVersion != "" {
			lf.UpsertPackage(LockedPackage{
				Category: "arch",
				Name:     c.Arch,
				Version:  c.ArchVersion,
				Source:   src,
			})
		}
		if c.Toolchain != "" && c.ToolchainVersion != "" {
			if _, ok := lf.Toolchains[c.Toolchain]; !ok {
				lf.Toolchains[c.Toolchain] = ToolchainEntry{Version: c.ToolchainVersion}
			}
		}

		chipRef := c.Name
		if c.Version != "" {
			chipRef = c.Name + "@" + c.Version
		}
		archRef := c.Arch
		if c.Arch != "" && c.ArchVersion != "" {
			archRef = c.Arch + "@" + c.ArchVersion
		}
		tcRef := c.Toolchain
		if c.Toolchain != "" && c.ToolchainVersion != "" {
			tcRef = c.Toolchain + "@" + c.ToolchainVersion
		}

		cryptoMap := make(map[string]string)
		if c.CryptoBackend != "" {
			cryptoMap["backend"] = c.CryptoBackend
		}
		if c.CryptoHash != "" {
			cryptoMap["hash"] = c.CryptoHash
		}
		if c.CryptoPqc != "" {
			cryptoMap["pqc"] = c.CryptoPqc
		}

		tl := TargetLock{
			Chip:      chipRef,
			Arch:      archRef,
			Toolchain: tcRef,
		}
		if len(cryptoMap) > 0 {
			tl.Crypto = cryptoMap
		}
		lf.Targets[c.Name] = tl
	}
}

// Load parses and validates an existing toob.lock. Returns an empty Lockfile if not found.
func Load(path string) (*Lockfile, error) {
	lf := &Lockfile{
		Packages:   make([]LockedPackage, 0),
		Chips:      make([]ChipEntry, 0),
		Toolchains: make(map[string]ToolchainEntry),
		Targets:    make(map[string]TargetLock),
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return lf, nil
		}
		return nil, fmt.Errorf("failed to stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("lockfile %s is not a regular file", path)
	}
	if info.Size() > maxLockfileBytes {
		return nil, fmt.Errorf("lockfile %s exceeds maximum size (%d bytes)", path, maxLockfileBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	data, readErr := httputil.ReadBounded(f, maxLockfileBytes)
	closeErr := f.Close()
	if readErr != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("failed to close %s: %w", path, closeErr)
	}

	md, err := toml.Decode(string(data), lf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("failed to parse %s: unknown key %q", path, undecoded[0].String())
	}
	if dupErr := checkRawTOMLDuplicates(string(data)); dupErr != nil {
		return nil, fmt.Errorf("invalid %s: %w", path, dupErr)
	}
	if lf.Packages == nil {
		lf.Packages = make([]LockedPackage, 0)
	}
	if lf.Chips == nil {
		lf.Chips = make([]ChipEntry, 0)
	}
	if lf.Toolchains == nil {
		lf.Toolchains = make(map[string]ToolchainEntry)
	}
	if lf.Targets == nil {
		lf.Targets = make(map[string]TargetLock)
	}
	if err = lf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", path, err)
	}
	lf.migrateLegacyV1InMemory()
	return lf, nil
}

// checkRawTOMLDuplicates catches case-insensitive duplicate [toolchains.*] or [targets.*]
// tables that a Go map decode would otherwise collapse when differing only in case.
func checkRawTOMLDuplicates(raw string) error {
	var rawMap map[string]any
	if _, err := toml.Decode(raw, &rawMap); err != nil {
		return err
	}
	for _, section := range []string{"toolchains", "targets"} {
		sub, ok := rawMap[section].(map[string]any)
		if !ok {
			continue
		}
		seen := make(map[string]string, len(sub))
		for k := range sub {
			folded := strings.ToLower(k)
			if prev, exists := seen[folded]; exists && prev != k {
				return fmt.Errorf("duplicate %s key %q and %q", section, prev, k)
			}
			seen[folded] = k
		}
	}
	return nil
}

// Save validates and atomically writes the lockfile as canonical TOML without
// mutating any caller-owned slices or maps in place.
func (lf *Lockfile) Save(path string) error {
	v2 := lf.isV2Mode()
	savedVer := lf.FormatVersion
	if v2 && lf.FormatVersion == 0 {
		lf.FormatVersion = FormatVersionV2
	}
	if err := lf.Validate(); err != nil {
		lf.FormatVersion = savedVer
		return err
	}

	var b strings.Builder
	b.WriteString("# Auto-generated by toob CLI. Do not edit manually.\n\n")

	if v2 {
		writeV2TOML(&b, lf)
	} else {
		writeLegacyV1TOML(&b, lf)
	}

	return atomicWriteLockfile(path, b.String())
}

func writeV2TOML(b *strings.Builder, lf *Lockfile) {
	fmt.Fprintf(b, "format_version = %d\n\n", FormatVersionV2)

	b.WriteString("[registry]\n")
	if lf.Registry.URL != "" {
		fmt.Fprintf(b, "url = %q\n", lf.Registry.URL)
	}
	rev := cmp.Or(lf.Registry.Revision, lf.Registry.Commit)
	if rev != "" {
		fmt.Fprintf(b, "revision = %q\n", rev)
	}
	if lf.Registry.IndexSHA256 != "" {
		fmt.Fprintf(b, "index_sha256 = %q\n", lf.Registry.IndexSHA256)
	}
	if lf.Registry.Version != "" {
		fmt.Fprintf(b, "version = %q\n", lf.Registry.Version)
	}
	b.WriteString("\n")

	if lf.Environment.CoreSDK != "" || lf.Environment.CoreSDKSHA256 != "" ||
		lf.Environment.Compiler != "" || lf.Environment.CompilerDigest != "" {
		b.WriteString("[environment]\n")
		if lf.Environment.CoreSDK != "" {
			fmt.Fprintf(b, "core_sdk = %q\n", lf.Environment.CoreSDK)
		}
		if lf.Environment.CoreSDKSHA256 != "" {
			fmt.Fprintf(b, "core_sdk_sha256 = %q\n", lf.Environment.CoreSDKSHA256)
		}
		if lf.Environment.Compiler != "" {
			fmt.Fprintf(b, "compiler = %q\n", lf.Environment.Compiler)
		}
		if lf.Environment.CompilerDigest != "" {
			fmt.Fprintf(b, "compiler_digest = %q\n", lf.Environment.CompilerDigest)
		}
		b.WriteString("\n")
	}

	pkgs := slices.Clone(lf.Packages)
	slices.SortStableFunc(pkgs, func(a, bPkg LockedPackage) int {
		if c := cmp.Compare(a.Category, bPkg.Category); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Name, bPkg.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Version, bPkg.Version)
	})

	for i := range pkgs {
		p := &pkgs[i]
		b.WriteString("[[package]]\n")
		fmt.Fprintf(b, "category = %q\n", p.Category)
		fmt.Fprintf(b, "name = %q\n", p.Name)
		fmt.Fprintf(b, "version = %q\n", p.Version)
		fmt.Fprintf(b, "source = %q\n", p.Source)
		if p.SHA256 != "" {
			fmt.Fprintf(b, "sha256 = %q\n", p.SHA256)
		}
		if p.BaseVersion != "" {
			fmt.Fprintf(b, "base_version = %q\n", p.BaseVersion)
		}
		if p.BaseSHA256 != "" {
			fmt.Fprintf(b, "base_sha256 = %q\n", p.BaseSHA256)
		}
		if p.Trait != "" {
			fmt.Fprintf(b, "trait = %q\n", p.Trait)
		}
		b.WriteString("\n")
	}

	writeToolchainsTOML(b, lf.Toolchains)
	writeTargetsTOML(b, lf.Targets)
}

func writeLegacyV1TOML(b *strings.Builder, lf *Lockfile) {
	b.WriteString("[registry]\n")
	if lf.Registry.Version != "" {
		fmt.Fprintf(b, "version = %q\n", lf.Registry.Version)
	}
	fmt.Fprintf(b, "commit = %q\n\n", lf.Registry.Commit)

	if lf.Environment.Compiler != "" || lf.Environment.CoreSDK != "" {
		b.WriteString("[environment]\n")
		if lf.Environment.Compiler != "" {
			fmt.Fprintf(b, "compiler = %q\n", lf.Environment.Compiler)
		}
		if lf.Environment.CoreSDK != "" {
			fmt.Fprintf(b, "core_sdk = %q\n", lf.Environment.CoreSDK)
		}
		b.WriteString("\n")
	}

	chips := slices.Clone(lf.Chips)
	slices.SortStableFunc(chips, func(a, bChip ChipEntry) int {
		return cmp.Compare(a.Name, bChip.Name)
	})

	for i := range chips {
		e := &chips[i]
		b.WriteString("[[chip]]\n")
		fmt.Fprintf(b, "name = %q\n", e.Name)
		fmt.Fprintf(b, "version = %q\n", e.Version)
		fmt.Fprintf(b, "arch = %q\n", e.Arch)
		if e.ArchVersion != "" {
			fmt.Fprintf(b, "arch_version = %q\n", e.ArchVersion)
		}
		if e.Toolchain != "" {
			fmt.Fprintf(b, "toolchain = %q\n", e.Toolchain)
		}
		if e.ToolchainVersion != "" {
			fmt.Fprintf(b, "toolchain_version = %q\n", e.ToolchainVersion)
		}
		if e.CryptoBackend != "" {
			fmt.Fprintf(b, "crypto_backend = %q\n", e.CryptoBackend)
		}
		if e.CryptoHash != "" {
			fmt.Fprintf(b, "crypto_hash = %q\n", e.CryptoHash)
		}
		if e.CryptoPqc != "" {
			fmt.Fprintf(b, "crypto_pqc = %q\n", e.CryptoPqc)
		}
		if e.Spawned {
			b.WriteString("spawned = true\n\n")
		} else {
			b.WriteString("spawned = false\n\n")
		}
	}

	writeToolchainsTOML(b, lf.Toolchains)
}

func writeToolchainsTOML(b *strings.Builder, toolchains map[string]ToolchainEntry) {
	tcNames := slices.Sorted(maps.Keys(toolchains))
	for _, name := range tcNames {
		e := toolchains[name]
		fmt.Fprintf(b, "[toolchains.%q]\n", name)
		fmt.Fprintf(b, "version = %q\n", e.Version)
		if len(e.SHA256) > 0 {
			fmt.Fprintf(b, "[toolchains.%q.sha256]\n", name)
			for _, plat := range slices.Sorted(maps.Keys(e.SHA256)) {
				fmt.Fprintf(b, "%s = %q\n", plat, e.SHA256[plat])
			}
		}
		b.WriteString("\n")
	}
}

func writeInlineStringMap(b *strings.Builder, field string, m map[string]string) {
	if len(m) == 0 {
		return
	}
	fmt.Fprintf(b, "%s = { ", field)
	keys := slices.Sorted(maps.Keys(m))
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s = %q", k, m[k])
	}
	b.WriteString(" }\n")
}

func writeTargetsTOML(b *strings.Builder, targets map[string]TargetLock) {
	for _, name := range slices.Sorted(maps.Keys(targets)) {
		t := targets[name]
		fmt.Fprintf(b, "[targets.%q]\n", name)
		fmt.Fprintf(b, "chip = %q\n", t.Chip)
		if t.Arch != "" {
			fmt.Fprintf(b, "arch = %q\n", t.Arch)
		}
		if t.Toolchain != "" {
			fmt.Fprintf(b, "toolchain = %q\n", t.Toolchain)
		}
		if t.SoC != "" {
			fmt.Fprintf(b, "soc = %q\n", t.SoC)
		}
		if t.Integration != "" {
			fmt.Fprintf(b, "integration = %q\n", t.Integration)
		}
		writeInlineStringMap(b, "drivers", t.Drivers)
		writeInlineStringMap(b, "crypto", t.Crypto)
		writeInlineStringMap(b, "recovery_drivers", t.RecoveryDrivers)
		writeInlineStringMap(b, "recovery_crypto", t.RecoveryCrypto)
		b.WriteString("\n")
	}
}

func atomicWriteLockfile(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".toob-lock-*.tmp")
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
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o644); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// UpsertPackage inserts or updates a LockedPackage matching (Category, Name, Version)
// case-insensitively.
func (lf *Lockfile) UpsertPackage(pkg LockedPackage) {
	for i := range lf.Packages {
		existing := &lf.Packages[i]
		if strings.EqualFold(existing.Category, pkg.Category) &&
			strings.EqualFold(existing.Name, pkg.Name) &&
			strings.EqualFold(existing.Version, pkg.Version) {
			*existing = pkg
			return
		}
	}
	lf.Packages = append(lf.Packages, pkg)
}

// FindPackage locates a LockedPackage by category, name, and (optional) version.
func (lf *Lockfile) FindPackage(category, name, version string) *LockedPackage {
	for i := range lf.Packages {
		p := &lf.Packages[i]
		if !strings.EqualFold(p.Category, category) || !strings.EqualFold(p.Name, name) {
			continue
		}
		if version == "" || strings.EqualFold(p.Version, version) {
			return p
		}
	}
	return nil
}

func splitRefNameVersion(ref string) (string, string) {
	if ref == "" || ref == "none" || strings.HasPrefix(ref, "local:") {
		return "", ""
	}
	lastAt := strings.LastIndex(ref, "@")
	if lastAt <= 0 {
		return ref, ""
	}
	return ref[:lastAt], ref[lastAt+1:]
}

func targetReferencesPackage(t TargetLock, category, name, version string) bool {
	matchRef := func(ref string) bool {
		refName, refVer := splitRefNameVersion(ref)
		if refName == "" || !strings.EqualFold(refName, name) {
			return false
		}
		return version == "" || refVer == "" || strings.EqualFold(refVer, version)
	}

	switch strings.ToLower(category) {
	case "chip":
		return matchRef(t.Chip)
	case "arch":
		return matchRef(t.Arch)
	case "toolchain":
		return matchRef(t.Toolchain)
	case "soc":
		return matchRef(t.SoC)
	case "integration":
		return matchRef(t.Integration)
	case "driver":
		for _, r := range t.Drivers {
			if matchRef(r) {
				return true
			}
		}
		for _, r := range t.RecoveryDrivers {
			if matchRef(r) {
				return true
			}
		}
	case "crypto":
		for _, r := range t.Crypto {
			if matchRef(r) {
				return true
			}
		}
		for _, r := range t.RecoveryCrypto {
			if matchRef(r) {
				return true
			}
		}
	}
	return false
}

// RemoveTarget deletes target (matched case-insensitively) from Targets and Chips,
// and prunes unreferenced packages and toolchains once remaining targets exist or
// all targets are removed.
func (lf *Lockfile) RemoveTarget(target string) bool {
	removed := false
	for k := range lf.Targets {
		if strings.EqualFold(k, target) {
			delete(lf.Targets, k)
			removed = true
		}
	}
	filteredChips := make([]ChipEntry, 0, len(lf.Chips))
	for i := range lf.Chips {
		if strings.EqualFold(lf.Chips[i].Name, target) {
			removed = true
			continue
		}
		filteredChips = append(filteredChips, lf.Chips[i])
	}
	lf.Chips = filteredChips

	if !removed {
		return false
	}

	keptPkgs := make([]LockedPackage, 0, len(lf.Packages))
	for i := range lf.Packages {
		p := &lf.Packages[i]
		referenced := false
		for _, t := range lf.Targets {
			if targetReferencesPackage(t, p.Category, p.Name, p.Version) {
				referenced = true
				break
			}
		}
		if referenced {
			keptPkgs = append(keptPkgs, *p)
		}
	}
	lf.Packages = keptPkgs

	for tcName := range lf.Toolchains {
		referenced := false
		for _, t := range lf.Targets {
			if targetReferencesPackage(t, "toolchain", tcName, "") {
				referenced = true
				break
			}
		}
		for i := range lf.Chips {
			if strings.EqualFold(lf.Chips[i].Toolchain, tcName) {
				referenced = true
				break
			}
		}
		if !referenced {
			delete(lf.Toolchains, tcName)
		}
	}
	return true
}

// IsSpawnedPackageShared reports whether any target other than excludeTarget
// references the package identified by (category, name).
func (lf *Lockfile) IsSpawnedPackageShared(category, name, excludeTarget string) bool {
	for k, t := range lf.Targets {
		if strings.EqualFold(k, excludeTarget) {
			continue
		}
		if targetReferencesPackage(t, category, name, "") {
			return true
		}
	}
	if len(lf.Targets) == 0 && strings.EqualFold(category, "arch") {
		return lf.IsArchShared(name, excludeTarget)
	}
	return false
}

// HasChip checks if a chip is installed in either Chips or Targets.
func (lf *Lockfile) HasChip(name string) bool {
	return lf.GetChip(name) != nil
}

// GetChip returns a chip entry (matching case-insensitively) from Chips or
// synthesized from Lockfile v2 Targets, or nil if absent.
func (lf *Lockfile) GetChip(name string) *ChipEntry {
	for i := range lf.Chips {
		if strings.EqualFold(lf.Chips[i].Name, name) {
			return &lf.Chips[i]
		}
	}
	for k, t := range lf.Targets {
		if !strings.EqualFold(k, name) {
			continue
		}
		chipName, chipVer := splitRefNameVersion(t.Chip)
		archName, archVer := splitRefNameVersion(t.Arch)
		tcName, tcVer := splitRefNameVersion(t.Toolchain)
		backend, _ := splitRefNameVersion(t.Crypto["backend"])
		hashPkg, _ := splitRefNameVersion(t.Crypto["hash"])
		pqcPkg, _ := splitRefNameVersion(t.Crypto["pqc"])
		if t.Crypto["backend"] == "none" {
			backend = "none"
		}
		if t.Crypto["hash"] == "none" {
			hashPkg = "none"
		}
		if t.Crypto["pqc"] == "none" {
			pqcPkg = "none"
		}
		spawned := false
		if pkg := lf.FindPackage("chip", cmp.Or(chipName, k), chipVer); pkg != nil && pkg.Source == "spawned" {
			spawned = true
		}
		return &ChipEntry{
			Name:             cmp.Or(chipName, k),
			Version:          chipVer,
			Arch:             archName,
			ArchVersion:      archVer,
			Toolchain:        tcName,
			ToolchainVersion: tcVer,
			CryptoBackend:    backend,
			CryptoHash:       hashPkg,
			CryptoPqc:        pqcPkg,
			Spawned:          spawned,
		}
	}
	return nil
}

// IsArchShared returns true if any chip/target other than exclude uses the given arch.
func (lf *Lockfile) IsArchShared(arch, exclude string) bool {
	for k, t := range lf.Targets {
		if !strings.EqualFold(k, exclude) && targetReferencesPackage(t, "arch", arch, "") {
			return true
		}
	}
	for i := range lf.Chips {
		if !strings.EqualFold(lf.Chips[i].Name, exclude) && strings.EqualFold(lf.Chips[i].Arch, arch) {
			return true
		}
	}
	return false
}
