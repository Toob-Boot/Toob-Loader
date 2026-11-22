package conformance

import (
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/literallint"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
)

var allManifestFilenames = []string{
	"driver_manifest.json",
	"chip_manifest.json",
	"arch_manifest.json",
	"crypto_manifest.json",
	"soc_manifest.json",
	"integration_manifest.json",
	"toolchain_manifest.json",
	"port_manifest.json",
}

var manifestFilenameSet = map[string]bool{
	"driver_manifest.json":      true,
	"chip_manifest.json":        true,
	"arch_manifest.json":        true,
	"crypto_manifest.json":      true,
	"soc_manifest.json":         true,
	"integration_manifest.json": true,
	"toolchain_manifest.json":   true,
	"port_manifest.json":        true,
}

var cKeywordSet = map[string]bool{
	"auto": true, "bool": true, "break": true, "case": true, "char": true, "const": true,
	"continue": true, "default": true, "do": true, "double": true, "else": true, "enum": true,
	"extern": true, "false": true, "float": true, "for": true, "goto": true, "if": true,
	"inline": true, "int": true, "long": true, "NULL": true, "register": true, "restrict": true,
	"return": true, "short": true, "signed": true, "sizeof": true, "static": true, "struct": true,
	"switch": true, "true": true, "typedef": true, "union": true, "unsigned": true, "void": true,
	"volatile": true, "while": true, "_Alignas": true, "_Alignof": true, "_Atomic": true,
	"_Bool": true, "_Complex": true, "_Generic": true, "_Imaginary": true, "_Noreturn": true,
	"_Static_assert": true, "static_assert": true, "_Thread_local": true, "thread_local": true,
	"alignas": true, "alignof": true, "constexpr": true, "nullptr": true, "typeof": true, "typeof_unqual": true,
}

var (
	archSymbolIdentRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	germanCharRegex      = regexp.MustCompile(`[äöüÄÖÜß]`)
	jsonSkipKeyRegex     = regexp.MustCompile(`^\s*"(author|license|copyright|ref)"\s*:`)
)

func isValidCSymbol(sym string) bool {
	return archSymbolIdentRegex.MatchString(sym) && !cKeywordSet[sym]
}

func isCIdentifier(sym string) bool {
	return isValidCSymbol(sym)
}

func validateContainedRelPath(rel string) (slashPath, osPath string, err error) {
	if rel == "" || strings.Contains(rel, `\`) || strings.ContainsRune(rel, 0) || strings.Contains(rel, ":") {
		return "", "", fmt.Errorf("invalid relative path %q", rel)
	}
	slash := filepath.ToSlash(rel)
	if strings.HasPrefix(slash, "/") {
		return "", "", fmt.Errorf("absolute path %q is forbidden", rel)
	}
	for part := range strings.SplitSeq(slash, "/") {
		if part == "" || part == "." || part == ".." {
			return "", "", fmt.Errorf("unsafe path component %q in %q", part, rel)
		}
	}
	return slash, filepath.FromSlash(slash), nil
}

func readRootRegularFile(root *os.Root, rel string, maxBytes int64) ([]byte, error) {
	_, osRel, err := validateContainedRelPath(rel)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(osRel)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink %q is forbidden", rel)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", rel)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%q (%d bytes) exceeds %d-byte limit", rel, info.Size(), maxBytes)
	}
	f, err := root.Open(osRel)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%q exceeds %d-byte limit", rel, maxBytes)
	}
	return data, nil
}

func resolveRootHeader(root *os.Root, h string) (string, bool) {
	if !strings.HasSuffix(h, ".h") {
		return "", false
	}
	if slash, _, err := validateContainedRelPath(h); err == nil {
		if _, rErr := readRootRegularFile(root, slash, maxSourceFileBytes); rErr == nil {
			return slash, true
		}
		inc := "include/" + slash
		if _, rErr := readRootRegularFile(root, inc, maxSourceFileBytes); rErr == nil {
			return inc, true
		}
	}
	return "", false
}

func checkRootDirExists(root *os.Root, rel string) bool {
	if rel == "." {
		return true
	}
	_, osRel, err := validateContainedRelPath(rel)
	if err != nil {
		return false
	}
	info, err := root.Lstat(osRel)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 {
		return false
	}
	return info.IsDir()
}

type discoveredManifest struct {
	name string
	path string
	data []byte
}

func scanPackageManifests(pkgRoot *os.Root) ([]discoveredManifest, error) {
	var found []discoveredManifest
	seenRel := make(map[string]bool)

	for _, mf := range allManifestFilenames {
		info, err := pkgRoot.Lstat(mf)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", mf, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("manifest %s must not be a symlink", mf)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("manifest %s is not a regular file", mf)
		}
		data, err := readRootRegularFile(pkgRoot, mf, maxPackageManifestBytes)
		if err != nil {
			return nil, err
		}
		found = append(found, discoveredManifest{name: mf, path: mf, data: data})
		seenRel[mf] = true
	}

	// Scan nested paths so packages bundling >1 manifest anywhere are rejected (matching tarball_validate.go:165-171).
	walkErr := fs.WalkDir(pkgRoot.FS(), ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "build" || base == "builds" || base == ".toob" {
				return fs.SkipDir
			}
			return nil
		}
		base := filepath.Base(relPath)
		slashRel := filepath.ToSlash(relPath)
		if manifestFilenameSet[base] && !seenRel[slashRel] {
			data, rErr := readRootRegularFile(pkgRoot, slashRel, maxPackageManifestBytes)
			if rErr != nil {
				return rErr
			}
			found = append(found, discoveredManifest{name: base, path: slashRel, data: data})
			seenRel[slashRel] = true
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("scan package directory: %w", walkErr)
	}
	return found, nil
}

// AuditPackage audits any of the 8 registry package categories for HAL contract
// conformance, *os.Root containment, Mock/Real equivalence, REG-035, and REG-040.
func AuditPackage(packagePath string) (*ConformanceReport, error) {
	return AuditPackageWithOptions(packagePath, AuditOptions{})
}

// AuditPackageWithOptions audits packagePath with explicit AuditOptions.
func AuditPackageWithOptions(packagePath string, opts AuditOptions) (*ConformanceReport, error) {
	pkgRoot, err := os.OpenRoot(packagePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open package directory %s: %w", packagePath, err)
	}
	defer func() { _ = pkgRoot.Close() }()

	manifests, err := scanPackageManifests(pkgRoot)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, fmt.Errorf("rejected: no manifest found at %s (expected one of: %s)",
			packagePath, strings.Join(allManifestFilenames, ", "))
	}
	if len(manifests) > 1 {
		names := make([]string, len(manifests))
		for i, m := range manifests {
			names[i] = m.path
		}
		return nil, fmt.Errorf("rejected: multiple manifests found: %s", strings.Join(names, ", "))
	}

	m := manifests[0]
	if m.path != m.name {
		return nil, fmt.Errorf("rejected: manifest %q must reside at package root", m.path)
	}

	hc, err := loadHalContract(packagePath, opts)
	if err != nil {
		return nil, err
	}

	switch m.name {
	case "driver_manifest.json":
		return auditDriverPackage(pkgRoot, packagePath, m.data, hc)
	case "chip_manifest.json":
		return auditChipPackage(pkgRoot, packagePath, m.data, hc)
	case "arch_manifest.json":
		return auditArchPackage(pkgRoot, packagePath, m.data, hc)
	case "crypto_manifest.json":
		return auditCryptoPackage(pkgRoot, packagePath, m.name, m.data, hc)
	case "soc_manifest.json":
		return auditSoCPackage(pkgRoot, packagePath, m.data)
	case "integration_manifest.json":
		return auditIntegrationPackage(pkgRoot, packagePath, m.data)
	case "toolchain_manifest.json":
		return auditToolchainPackage(pkgRoot, packagePath, m.data)
	case "port_manifest.json":
		return auditPortPackage(pkgRoot, packagePath, m.data)
	default:
		return nil, fmt.Errorf("unsupported manifest %s", m.name)
	}
}

func auditDriverPackage(pkgRoot *os.Root, packagePath string, data []byte, hc *halContract) (*ConformanceReport, error) {
	dm, err := decodeStrictJSON[driverManifestSchema]("driver_manifest.json", data)
	if err != nil {
		return nil, err
	}

	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: dm.Name,
		PackagePath: packagePath,
		Trait:       dm.Trait,
		AbiVersion:  dm.AbiVersion,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if dm.Name == "" {
		addCheck(report, "Manifest Metadata: Name", false, "driver_manifest.json is missing required 'name' field")
	} else if err := manifest.ValidatePackageRef("driver package", dm.Name); err != nil {
		addCheck(report, "Manifest Metadata: Name", false, err.Error())
	} else {
		addCheck(report, "Manifest Metadata: Name", true, fmt.Sprintf("Package name '%s'", dm.Name))
	}

	if dm.Version != "" {
		if err := manifest.ValidateName("driver version", dm.Version); err != nil {
			addCheck(report, "Manifest Metadata: Version", false, err.Error())
		}
	}

	var ownerTrait *halTraitContract
	if dm.Trait == "" {
		addCheck(report, "Manifest Metadata: Trait", false, "driver_manifest.json is missing required 'trait' field")
	} else if err := manifest.ValidateName("driver trait", dm.Trait); err != nil {
		addCheck(report, "Manifest Metadata: Trait", false, err.Error())
	} else if ownerTrait = hc.findDriverTrait(dm.Trait); ownerTrait == nil {
		addCheck(report, "Manifest Metadata: Trait", false,
			fmt.Sprintf("Unrecognized HAL trait '%s' (not defined in hal_contract.json)", dm.Trait))
	} else {
		addCheck(report, "Manifest Metadata: Trait", true, fmt.Sprintf("Satisfies HAL trait '%s'", dm.Trait))
	}

	if dm.AbiVersion == "" {
		addCheck(report, "Manifest Metadata: ABI Version", false, "driver_manifest.json is missing required 'abi_version' field")
	} else if err := manifest.ValidateName("driver abi_version", dm.AbiVersion); err != nil {
		addCheck(report, "Manifest Metadata: ABI Version", false, err.Error())
	} else if ownerTrait != nil && ownerTrait.AbiVersion != "" && !strings.EqualFold(dm.AbiVersion, ownerTrait.AbiVersion) {
		addCheck(report, "Manifest Metadata: ABI Version", false,
			fmt.Sprintf("Driver declares abi_version '%s', but hal_contract.json trait '%s' requires '%s'",
				dm.AbiVersion, ownerTrait.Name, ownerTrait.AbiVersion))
	} else {
		addCheck(report, "Manifest Metadata: ABI Version", true, fmt.Sprintf("ABI version '%s'", dm.AbiVersion))
	}

	if ownerTrait != nil {
		reqKeys, allowedKeys, needAny := ownerTrait.driverSymbolContract()
		if len(dm.Symbols) == 0 {
			addCheck(report, "Trait Symbol Contract", false,
				fmt.Sprintf("Driver satisfying trait '%s' defines no 'symbols' map in driver_manifest.json", dm.Trait))
		} else {
			var missing, invalid []string
			for _, symKey := range reqKeys {
				symVal := strings.TrimSpace(dm.Symbols[symKey])
				if symVal == "" {
					missing = append(missing, symKey)
				}
			}
			boundAllowed := 0
			for _, symKey := range slices.Sorted(maps.Keys(dm.Symbols)) {
				symVal := strings.TrimSpace(dm.Symbols[symKey])
				if err := manifest.ValidateName("driver symbol key", symKey); err != nil || !isValidCSymbol(symVal) {
					invalid = append(invalid, fmt.Sprintf("%s=%q", symKey, dm.Symbols[symKey]))
					continue
				}
				if slices.Contains(allowedKeys, symKey) {
					boundAllowed++
				}
			}
			if needAny && boundAllowed == 0 {
				missing = append(missing, "at least one method of ["+strings.Join(allowedKeys, ", ")+"]")
			}
			if len(missing) > 0 || len(invalid) > 0 {
				var parts []string
				if len(missing) > 0 {
					parts = append(parts, fmt.Sprintf("missing required symbols for trait '%s': %s", dm.Trait, strings.Join(missing, ", ")))
				}
				if len(invalid) > 0 {
					parts = append(parts, "invalid C identifier(s): "+strings.Join(invalid, ", "))
				}
				addCheck(report, "Trait Symbol Contract", false, strings.Join(parts, "; "))
			} else {
				addCheck(report, "Trait Symbol Contract", true,
					fmt.Sprintf("All %d required symbol(s) for trait '%s' are mapped to valid C identifiers", len(reqKeys), dm.Trait))
			}
		}
	}

	if len(dm.Headers) == 0 {
		addCheck(report, "Driver Manifest: Headers", false, "driver_manifest.json must declare at least one header in 'headers'")
	} else {
		var missingHeaders []string
		for _, h := range dm.Headers {
			if _, ok := resolveRootHeader(pkgRoot, h); !ok {
				missingHeaders = append(missingHeaders, h)
			}
		}
		if len(missingHeaders) > 0 {
			addCheck(report, "Driver Manifest: Headers", false,
				"Missing or invalid declared driver header(s): "+strings.Join(missingHeaders, ", "))
		} else {
			addCheck(report, "Driver Manifest: Headers", true, fmt.Sprintf("Verified %d header(s)", len(dm.Headers)))
		}
	}

	if len(dm.Sources) > 0 {
		var badSources []string
		for _, src := range dm.Sources {
			if _, err := readRootRegularFile(pkgRoot, src, maxSourceFileBytes); err != nil {
				badSources = append(badSources, src)
			}
		}
		if len(badSources) > 0 {
			addCheck(report, "Driver Manifest: Sources", false,
				"Missing or invalid declared source(s): "+strings.Join(badSources, ", "))
		} else {
			addCheck(report, "Driver Manifest: Sources", true, fmt.Sprintf("Verified %d source file(s)", len(dm.Sources)))
		}
	}

	recordMockEquivalence(report, verifyMockEquivalence(pkgRoot, dm.Sources, dm.MockSources))

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, nil)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func auditArchPackage(pkgRoot *os.Root, packagePath string, data []byte, hc *halContract) (*ConformanceReport, error) {
	am, err := decodeStrictJSON[archManifestSchema]("arch_manifest.json", data)
	if err != nil {
		return nil, err
	}

	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: am.Name,
		PackagePath: packagePath,
		Trait:       "arch_package",
		AbiVersion:  am.Version,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if am.Name == "" {
		addCheck(report, "Arch Manifest: Name", false, "arch_manifest.json missing required 'name' field")
	} else if err := manifest.ValidatePackageRef("arch package", am.Name); err != nil {
		addCheck(report, "Arch Manifest: Name", false, err.Error())
	} else {
		addCheck(report, "Arch Manifest: Name", true, fmt.Sprintf("Architecture '%s'", am.Name))
	}

	if am.Version == "" {
		addCheck(report, "Arch Manifest: Version", false, "arch_manifest.json missing required 'version' field")
	} else if err := manifest.ValidateName("arch version", am.Version); err != nil {
		addCheck(report, "Arch Manifest: Version", false, err.Error())
	} else {
		addCheck(report, "Arch Manifest: Version", true, fmt.Sprintf("Version '%s'", am.Version))
	}

	if len(am.Headers) == 0 {
		addCheck(report, "Arch Manifest: Headers", false, "arch_manifest.json must declare at least one header in 'headers'")
	} else {
		var missingHeaders []string
		for _, h := range am.Headers {
			if _, ok := resolveRootHeader(pkgRoot, h); !ok {
				missingHeaders = append(missingHeaders, h)
			}
		}
		if len(missingHeaders) > 0 {
			addCheck(report, "Arch Manifest: Headers", false,
				"Missing or invalid declared arch header(s): "+strings.Join(missingHeaders, ", "))
		} else {
			addCheck(report, "Arch Manifest: Headers", true, fmt.Sprintf("Verified %d header(s)", len(am.Headers)))
		}
	}

	if len(am.Sources) == 0 {
		addCheck(report, "Arch Manifest: Sources", false, "arch_manifest.json must declare at least one source file in 'sources'")
	} else {
		var missingSources []string
		for _, src := range am.Sources {
			if _, err := readRootRegularFile(pkgRoot, src, maxSourceFileBytes); err != nil {
				missingSources = append(missingSources, src)
			}
		}
		if len(missingSources) > 0 {
			addCheck(report, "Arch Manifest: Sources", false,
				"Missing or invalid declared arch source(s): "+strings.Join(missingSources, ", "))
		} else {
			addCheck(report, "Arch Manifest: Sources", true, fmt.Sprintf("Verified %d source file(s)", len(am.Sources)))
		}
	}

	reqArchSyms := hc.requiredArchSymbols()
	checkedKeys := make(map[string]bool, len(reqArchSyms))
	var missingSyms, invalidSyms []string
	for _, req := range reqArchSyms {
		checkedKeys[req] = true
		sym := am.Symbols[req]
		if sym == "" {
			missingSyms = append(missingSyms, req)
		} else if !isValidCSymbol(sym) {
			invalidSyms = append(invalidSyms, fmt.Sprintf("%s=%q", req, sym))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(am.Symbols)) {
		if checkedKeys[k] {
			continue
		}
		sym := am.Symbols[k]
		if err := manifest.ValidateName("arch symbol key", k); err != nil || !isValidCSymbol(sym) {
			invalidSyms = append(invalidSyms, fmt.Sprintf("%s=%q", k, sym))
		}
	}
	if len(missingSyms) > 0 || len(invalidSyms) > 0 {
		var parts []string
		if len(missingSyms) > 0 {
			parts = append(parts, "missing required symbol(s): "+strings.Join(missingSyms, ", "))
		}
		if len(invalidSyms) > 0 {
			parts = append(parts, "invalid C identifier(s): "+strings.Join(invalidSyms, ", "))
		}
		addCheck(report, "Arch Symbol Contract", false, strings.Join(parts, "; "))
	} else {
		addCheck(report, "Arch Symbol Contract", true, "All required architecture contract symbols are mapped")
	}

	if len(am.RequiredMacros) > 0 {
		var badMacros []string
		for _, m := range am.RequiredMacros {
			if !isCIdentifier(m) {
				badMacros = append(badMacros, fmt.Sprintf("%q", m))
			}
		}
		if len(badMacros) > 0 {
			addCheck(report, "Arch Manifest: Required Macros", false,
				"Invalid C macro identifier(s) in required_macros: "+strings.Join(badMacros, ", "))
		} else {
			addCheck(report, "Arch Manifest: Required Macros", true,
				fmt.Sprintf("Verified %d required macro identifier(s)", len(am.RequiredMacros)))
		}
	}

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, nil)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func resolveChipHardwareJSON(pkgRoot *os.Root, packagePath string, cm *chipManifestSchema) error {
	hwRel := "hardware.json"
	if cm.Sources != nil && strings.TrimSpace(cm.Sources.Hardware) != "" {
		hwRel = strings.TrimSpace(cm.Sources.Hardware)
	}
	hwData, err := readRootRegularFile(pkgRoot, hwRel, maxSourceFileBytes)
	if err != nil {
		return fmt.Errorf("cannot read chip %s: %w", hwRel, err)
	}
	hw, err := decodeStrictJSON[manifest.HardwareJson](hwRel, hwData)
	if err != nil {
		return err
	}
	if hw.BootromImage == nil || strings.TrimSpace(hw.BootromImage.Extends) == "" {
		return nil
	}

	extRel := strings.TrimSpace(hw.BootromImage.Extends)
	extSlash, _, err := validateContainedRelPath(extRel)
	if err != nil {
		return fmt.Errorf("bootrom_image.extends: %w", err)
	}
	if !strings.HasSuffix(extSlash, ".json") {
		return fmt.Errorf("bootrom_image.extends %q must end with '.json'", extRel)
	}

	// 1. Check inside the chip package root itself.
	if extBytes, rErr := readRootRegularFile(pkgRoot, extSlash, maxPackageManifestBytes); rErr == nil {
		_, err = decodeStrictJSON[manifest.BootromImageSpec](extSlash, extBytes)
		return err
	} else if !errors.Is(rErr, os.ErrNotExist) {
		return fmt.Errorf("bootrom_image.extends %q: %w", extSlash, rErr)
	}

	// 2. For shared soc/... profiles, check parent registry packages root or local registry cache via *os.Root.
	if strings.HasPrefix(extSlash, "soc/") {
		var candidateRoots []string
		parentPkgs := filepath.Clean(filepath.Join(packagePath, "..", ".."))
		if st, sErr := os.Stat(filepath.Join(parentPkgs, "soc")); sErr == nil && st.IsDir() {
			candidateRoots = append(candidateRoots, parentPkgs)
		}
		if regDir, rErr := paths.RegistryDir(); rErr == nil {
			if st, sErr := os.Stat(filepath.Join(regDir, "soc")); sErr == nil && st.IsDir() {
				candidateRoots = append(candidateRoots, regDir)
			}
		}
		if len(candidateRoots) == 0 {
			return nil
		}
		for _, candDir := range candidateRoots {
			extRoot, oErr := os.OpenRoot(candDir)
			if oErr != nil {
				continue
			}
			extBytes, rErr := readRootRegularFile(extRoot, extSlash, maxPackageManifestBytes)
			_ = extRoot.Close()
			if rErr == nil {
				_, err = decodeStrictJSON[manifest.BootromImageSpec](extSlash, extBytes)
				return err
			}
		}
	}

	return fmt.Errorf("missing bootrom_image.extends file %q", extSlash)
}

func auditChipPackage(pkgRoot *os.Root, packagePath string, data []byte, _ *halContract) (*ConformanceReport, error) {
	cm, err := decodeStrictJSON[chipManifestSchema]("chip_manifest.json", data)
	if err != nil {
		return nil, err
	}

	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: cm.Name,
		PackagePath: packagePath,
		Trait:       "chip_package",
		AbiVersion:  cm.Version,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if cm.Name == "" {
		addCheck(report, "Chip Manifest: Name", false, "chip_manifest.json missing required 'name' field")
	} else if err := manifest.ValidatePackageRef("chip package", cm.Name); err != nil {
		addCheck(report, "Chip Manifest: Name", false, err.Error())
	} else {
		addCheck(report, "Chip Manifest: Name", true, fmt.Sprintf("Chip '%s'", cm.Name))
	}

	if cm.Arch == "" {
		addCheck(report, "Chip Manifest: Arch", false, "chip_manifest.json missing required 'arch' field")
	} else {
		addCheck(report, "Chip Manifest: Arch", true, fmt.Sprintf("Architecture '%s'", cm.Arch))
	}

	if cm.SlotCapabilities == nil {
		addCheck(report, "Chip Manifest: Slot Capabilities", false, "chip_manifest.json missing required 'slot_capabilities'")
	} else {
		addCheck(report, "Chip Manifest: Slot Capabilities", true,
			fmt.Sprintf("Exec model '%s', slot count %d", cm.SlotCapabilities.ExecModel, cm.SlotCapabilities.SlotCount))
	}

	if len(cm.HalBindings) == 0 {
		addCheck(report, "Chip Manifest: HAL Bindings", false, "chip_manifest.json missing required 'hal_bindings' map")
	} else {
		addCheck(report, "Chip Manifest: HAL Bindings", true, fmt.Sprintf("Defines %d HAL driver trait bindings", len(cm.HalBindings)))
	}

	if cm.Sources != nil {
		var badLocalSources []string
		for _, localSrc := range []string{cm.Sources.Startup, cm.Sources.Platform, cm.Sources.Config, cm.Sources.Linker} {
			if strings.TrimSpace(localSrc) == "" {
				continue
			}
			if _, err := readRootRegularFile(pkgRoot, strings.TrimSpace(localSrc), maxSourceFileBytes); err != nil {
				badLocalSources = append(badLocalSources, localSrc)
			}
		}
		for _, extra := range cm.Sources.Extra {
			if _, err := readRootRegularFile(pkgRoot, strings.TrimSpace(extra), maxSourceFileBytes); err != nil {
				badLocalSources = append(badLocalSources, extra)
			}
		}
		if len(badLocalSources) > 0 {
			addCheck(report, "Chip Manifest: Sources", false,
				"Missing or invalid chip source file(s): "+strings.Join(badLocalSources, ", "))
		} else {
			addCheck(report, "Chip Manifest: Sources", true, "Verified local chip source files")
		}
	}

	if err := resolveChipHardwareJSON(pkgRoot, packagePath, cm); err != nil {
		addCheck(report, "Chip Manifest: Hardware JSON", false, err.Error())
	} else {
		addCheck(report, "Chip Manifest: Hardware JSON", true, "Validated hardware.json and bootrom_image contract")
	}

	recordMockEquivalence(report, verifyMockEquivalence(pkgRoot, nil, nil))

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, nil)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func auditCryptoPackage(pkgRoot *os.Root, packagePath, manifestRel string, data []byte, hc *halContract) (*ConformanceReport, error) {
	cm, err := decodeStrictJSON[cryptoManifestSchema]("crypto_manifest.json", data)
	if err != nil {
		return nil, err
	}

	expectedCryptoABI, requiredCryptoByCat := hc.cryptoCategoryRequirements()

	traitLabel := "crypto_package"
	if len(cm.Category) > 0 {
		traitLabel = "crypto:" + strings.Join(cm.Category, ",")
	}
	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: cm.Name,
		PackagePath: packagePath,
		Trait:       traitLabel,
		AbiVersion:  cm.AbiVersion,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if cm.Name == "" {
		addCheck(report, "Crypto Manifest: Name", false, "crypto_manifest.json missing required 'name' field")
	} else if err := manifest.ValidatePackageRef("crypto package", cm.Name); err != nil {
		addCheck(report, "Crypto Manifest: Name", false, err.Error())
	} else {
		addCheck(report, "Crypto Manifest: Name", true, fmt.Sprintf("Crypto package '%s'", cm.Name))
	}

	if cm.Version == "" {
		addCheck(report, "Crypto Manifest: Version", false, "crypto_manifest.json missing required 'version' field")
	} else if err := manifest.ValidateName("crypto version", cm.Version); err != nil {
		addCheck(report, "Crypto Manifest: Version", false, err.Error())
	} else {
		addCheck(report, "Crypto Manifest: Version", true, fmt.Sprintf("Version '%s'", cm.Version))
	}

	if cm.AbiVersion == "" {
		addCheck(report, "Crypto Manifest: ABI Version", false, "crypto_manifest.json missing required 'abi_version' field")
	} else if err := manifest.ValidateName("crypto abi_version", cm.AbiVersion); err != nil {
		addCheck(report, "Crypto Manifest: ABI Version", false, err.Error())
	} else if expectedCryptoABI != "" && !strings.EqualFold(cm.AbiVersion, expectedCryptoABI) {
		addCheck(report, "Crypto Manifest: ABI Version", false,
			fmt.Sprintf("crypto_manifest.json abi_version '%s' does not match hal_contract.json crypto ABI '%s'",
				cm.AbiVersion, expectedCryptoABI))
	} else {
		addCheck(report, "Crypto Manifest: ABI Version", true, fmt.Sprintf("ABI version '%s'", cm.AbiVersion))
	}

	if len(cm.Category) == 0 {
		addCheck(report, "Crypto Manifest: Category", false, "crypto_manifest.json must declare at least one category")
	} else {
		var badCats []string
		for _, cat := range cm.Category {
			if _, ok := requiredCryptoByCat[cat]; !ok {
				badCats = append(badCats, cat)
			}
		}
		if len(badCats) > 0 {
			addCheck(report, "Crypto Manifest: Category", false,
				"Unsupported crypto category value(s): "+strings.Join(badCats, ", "))
		} else {
			addCheck(report, "Crypto Manifest: Category", true, "Categories: "+strings.Join(cm.Category, ", "))
		}
	}

	var wrapperRel string
	if cm.Wrapper == "" {
		addCheck(report, "Crypto Manifest: Wrapper", false, "crypto_manifest.json missing required 'wrapper' C file")
	} else if !strings.HasSuffix(cm.Wrapper, ".c") {
		addCheck(report, "Crypto Manifest: Wrapper", false, fmt.Sprintf("Crypto wrapper %q must be a .c file", cm.Wrapper))
	} else if slash, _, pErr := validateContainedRelPath(cm.Wrapper); pErr != nil {
		addCheck(report, "Crypto Manifest: Wrapper", false, fmt.Sprintf("Invalid wrapper path %q: %v", cm.Wrapper, pErr))
	} else if _, rErr := readRootRegularFile(pkgRoot, slash, maxSourceFileBytes); rErr != nil {
		addCheck(report, "Crypto Manifest: Wrapper", false, fmt.Sprintf("Missing or invalid declared wrapper file %q", cm.Wrapper))
	} else {
		wrapperRel = slash
		addCheck(report, "Crypto Manifest: Wrapper", true, fmt.Sprintf("Verified wrapper '%s'", cm.Wrapper))
	}

	var upstreamRels []string
	var missingUpstream []string
	for _, src := range cm.UpstreamSources {
		slash, _, pErr := validateContainedRelPath(src)
		if pErr != nil {
			missingUpstream = append(missingUpstream, src)
			continue
		}
		if _, rErr := readRootRegularFile(pkgRoot, slash, maxSourceFileBytes); rErr != nil {
			missingUpstream = append(missingUpstream, src)
		} else {
			upstreamRels = append(upstreamRels, slash)
		}
	}
	if len(missingUpstream) > 0 {
		addCheck(report, "Crypto Manifest: Upstream Sources", false,
			"Missing or invalid upstream_sources: "+strings.Join(missingUpstream, ", "))
	} else {
		addCheck(report, "Crypto Manifest: Upstream Sources", true,
			fmt.Sprintf("Verified %d upstream source file(s)", len(upstreamRels)))
	}

	var headerRels []string
	if len(cm.Headers) == 0 {
		addCheck(report, "Crypto Manifest: Headers", false, "crypto_manifest.json must declare at least one header in 'headers'")
	} else {
		var missingHeaders []string
		for _, h := range cm.Headers {
			if relH, ok := resolveRootHeader(pkgRoot, h); !ok {
				missingHeaders = append(missingHeaders, h)
			} else {
				headerRels = append(headerRels, relH)
			}
		}
		if len(missingHeaders) > 0 {
			addCheck(report, "Crypto Manifest: Headers", false,
				"Missing or invalid declared crypto header(s): "+strings.Join(missingHeaders, ", "))
		} else {
			addCheck(report, "Crypto Manifest: Headers", true, fmt.Sprintf("Verified %d header(s)", len(headerRels)))
		}
	}

	cSourceRels := make([]string, 0, 1+len(upstreamRels))
	if wrapperRel != "" {
		cSourceRels = append(cSourceRels, wrapperRel)
	}
	cSourceRels = append(cSourceRels, upstreamRels...)
	strippedCode := readStrippedCSourcesRoot(pkgRoot, cSourceRels)

	var symIssues []string
	if len(cm.Symbols) == 0 {
		symIssues = append(symIssues, "crypto_manifest.json defines no 'symbols' map")
	} else {
		for _, cat := range cm.Category {
			for _, reqKey := range requiredCryptoByCat[cat] {
				if strings.TrimSpace(cm.Symbols[reqKey]) == "" {
					symIssues = append(symIssues, fmt.Sprintf("missing required symbol key %q for category %q", reqKey, cat))
				}
			}
		}
		for _, k := range slices.Sorted(maps.Keys(cm.Symbols)) {
			sym := cm.Symbols[k]
			if err := manifest.ValidateName("crypto symbol key", k); err != nil {
				symIssues = append(symIssues, fmt.Sprintf("invalid symbol key %q", k))
				continue
			}
			if !isValidCSymbol(sym) {
				symIssues = append(symIssues, fmt.Sprintf("invalid C identifier %s=%q", k, sym))
				continue
			}
			symRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(sym) + `\b`)
			if !symRe.MatchString(strippedCode) {
				symIssues = append(symIssues, fmt.Sprintf("symbol %q (for %q) not found in package C sources", sym, k))
			}
		}
	}
	if len(symIssues) > 0 {
		addCheck(report, "Crypto Symbol Contract", false, strings.Join(symIssues, "; "))
	} else {
		addCheck(report, "Crypto Symbol Contract", true, fmt.Sprintf("Verified %d C symbol(s) in package sources", len(cm.Symbols)))
	}

	firstPartyLangRels := []string{manifestRel}
	var wrapperLintPaths []string
	if wrapperRel != "" {
		firstPartyLangRels = append(firstPartyLangRels, wrapperRel)
		wrapperLintPaths = append(wrapperLintPaths, filepath.Join(packagePath, filepath.FromSlash(wrapperRel)))
	}
	firstPartyLangRels = append(firstPartyLangRels, headerRels...)
	for _, hr := range headerRels {
		wrapperLintPaths = append(wrapperLintPaths, filepath.Join(packagePath, filepath.FromSlash(hr)))
	}

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, firstPartyLangRels)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintFiles(packagePath, wrapperLintPaths)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func auditSoCPackage(pkgRoot *os.Root, packagePath string, data []byte) (*ConformanceReport, error) {
	sm, err := decodeStrictJSON[socManifestSchema]("soc_manifest.json", data)
	if err != nil {
		return nil, err
	}

	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: sm.Name,
		PackagePath: packagePath,
		Trait:       "soc_package",
		AbiVersion:  sm.Version,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if sm.Name == "" {
		addCheck(report, "SoC Manifest: Name", false, "soc_manifest.json missing required 'name' field")
	} else if err := manifest.ValidatePackageRef("soc package", sm.Name); err != nil {
		addCheck(report, "SoC Manifest: Name", false, err.Error())
	} else {
		addCheck(report, "SoC Manifest: Name", true, fmt.Sprintf("SoC package '%s'", sm.Name))
	}

	if sm.Version == "" {
		addCheck(report, "SoC Manifest: Version", false, "soc_manifest.json missing required 'version' field")
	} else if err := manifest.ValidateName("soc version", sm.Version); err != nil {
		addCheck(report, "SoC Manifest: Version", false, err.Error())
	} else {
		addCheck(report, "SoC Manifest: Version", true, fmt.Sprintf("Version '%s'", sm.Version))
	}

	var fileIssues []string
	for _, h := range sm.Headers {
		if _, ok := resolveRootHeader(pkgRoot, h); !ok {
			fileIssues = append(fileIssues, fmt.Sprintf("missing/invalid header %q", h))
		}
	}
	for _, src := range sm.Sources {
		if _, rErr := readRootRegularFile(pkgRoot, src, maxSourceFileBytes); rErr != nil {
			fileIssues = append(fileIssues, fmt.Sprintf("missing/invalid source %q", src))
		}
	}
	for _, inc := range sm.Includes {
		if !checkRootDirExists(pkgRoot, inc) {
			fileIssues = append(fileIssues, fmt.Sprintf("missing/invalid include dir %q", inc))
		}
	}
	bootromRel := strings.TrimSpace(sm.BootromImage)
	if bootromRel == "" {
		if _, statErr := pkgRoot.Lstat("bootrom_image.json"); statErr == nil {
			bootromRel = "bootrom_image.json"
		}
	}
	if bootromRel != "" {
		if brBytes, rErr := readRootRegularFile(pkgRoot, bootromRel, maxPackageManifestBytes); rErr != nil {
			fileIssues = append(fileIssues, fmt.Sprintf("missing/invalid bootrom_image %q", bootromRel))
		} else if _, dErr := decodeStrictJSON[manifest.BootromImageSpec](bootromRel, brBytes); dErr != nil {
			fileIssues = append(fileIssues, dErr.Error())
		}
	}
	if len(fileIssues) > 0 {
		addCheck(report, "SoC Manifest: Files", false, strings.Join(fileIssues, "; "))
	} else {
		addCheck(report, "SoC Manifest: Files", true, "Verified SoC package files and containment")
	}

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, nil)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func auditIntegrationPackage(pkgRoot *os.Root, packagePath string, data []byte) (*ConformanceReport, error) {
	im, err := decodeStrictJSON[integrationManifestSchema]("integration_manifest.json", data)
	if err != nil {
		return nil, err
	}

	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: im.Name,
		PackagePath: packagePath,
		Trait:       "integration_package",
		AbiVersion:  im.Version,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if im.Name == "" {
		addCheck(report, "Integration Manifest: Name", false, "integration_manifest.json missing required 'name' field")
	} else if err := manifest.ValidatePackageRef("integration package", im.Name); err != nil {
		addCheck(report, "Integration Manifest: Name", false, err.Error())
	} else {
		addCheck(report, "Integration Manifest: Name", true, fmt.Sprintf("Integration '%s'", im.Name))
	}

	if im.Version == "" {
		addCheck(report, "Integration Manifest: Version", false, "integration_manifest.json missing required 'version' field")
	} else if err := manifest.ValidateName("integration version", im.Version); err != nil {
		addCheck(report, "Integration Manifest: Version", false, err.Error())
	} else {
		addCheck(report, "Integration Manifest: Version", true, fmt.Sprintf("Version '%s'", im.Version))
	}

	switch {
	case len(im.Files) > 0:
		var badFiles []string
		for _, f := range im.Files {
			if _, rErr := readRootRegularFile(pkgRoot, f, maxSourceFileBytes); rErr != nil {
				badFiles = append(badFiles, f)
			}
		}
		if len(badFiles) > 0 {
			addCheck(report, "Integration Manifest: Files", false,
				"Missing or invalid declared file(s): "+strings.Join(badFiles, ", "))
		} else {
			addCheck(report, "Integration Manifest: Files", true, fmt.Sprintf("Verified %d integration file(s)", len(im.Files)))
		}
	case !checkRootDirExists(pkgRoot, "files"):
		addCheck(report, "Integration Manifest: Files", false, "Integration package must contain a 'files/' directory or declare 'files'")
	default:
		fileCount := 0
		var symlinkErr error
		_ = fs.WalkDir(pkgRoot.FS(), "files", func(rel string, d fs.DirEntry, wErr error) error {
			if wErr != nil || rel == "files" {
				return wErr
			}
			info, lErr := pkgRoot.Lstat(filepath.FromSlash(rel))
			if lErr != nil {
				symlinkErr = lErr
				return lErr
			}
			if info.Mode()&fs.ModeSymlink != 0 {
				symlinkErr = fmt.Errorf("symlink %q is forbidden in integration files", rel)
				return symlinkErr
			}
			if !d.IsDir() {
				fileCount++
			}
			return nil
		})
		switch {
		case symlinkErr != nil:
			addCheck(report, "Integration Manifest: Files", false, symlinkErr.Error())
		case fileCount == 0:
			addCheck(report, "Integration Manifest: Files", false, "Integration 'files/' directory is empty")
		default:
			addCheck(report, "Integration Manifest: Files", true, fmt.Sprintf("Verified %d file(s) in files/", fileCount))
		}
	}

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, nil)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func auditToolchainPackage(pkgRoot *os.Root, packagePath string, data []byte) (*ConformanceReport, error) {
	tm, err := decodeStrictJSON[toolchainManifestSchema]("toolchain_manifest.json", data)
	if err != nil {
		return nil, err
	}

	pkgName := cmp.Or(strings.TrimSpace(tm.Name), filepath.Base(packagePath))
	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: pkgName,
		PackagePath: packagePath,
		Trait:       "toolchain_package",
		AbiVersion:  tm.Version,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if tm.Name != "" {
		if err := manifest.ValidatePackageRef("toolchain package", tm.Name); err != nil {
			addCheck(report, "Toolchain Manifest: Name", false, err.Error())
		} else {
			addCheck(report, "Toolchain Manifest: Name", true, fmt.Sprintf("Toolchain '%s'", tm.Name))
		}
	} else {
		addCheck(report, "Toolchain Manifest: Name", true, fmt.Sprintf("Toolchain '%s'", pkgName))
	}

	if tm.Version == "" {
		addCheck(report, "Toolchain Manifest: Version", false, "toolchain_manifest.json missing required 'version' field")
	} else if err := manifest.ValidateName("toolchain version", tm.Version); err != nil {
		addCheck(report, "Toolchain Manifest: Version", false, err.Error())
	} else {
		addCheck(report, "Toolchain Manifest: Version", true, fmt.Sprintf("Version '%s'", tm.Version))
	}

	if len(tm.URLs) == 0 {
		addCheck(report, "Toolchain Manifest: Archive Digests", false, "toolchain_manifest.json must declare at least one platform URL in 'urls'")
	} else {
		var digestIssues []string
		for _, plat := range slices.Sorted(maps.Keys(tm.URLs)) {
			u := strings.TrimSpace(tm.URLs[plat])
			if !strings.HasPrefix(u, "https://") {
				digestIssues = append(digestIssues, fmt.Sprintf("platform %q URL must use https://", plat))
			}
			sum := strings.TrimSpace(tm.SHA256[plat])
			decoded, hexErr := hex.DecodeString(sum)
			if hexErr != nil || len(decoded) != 32 {
				digestIssues = append(digestIssues, fmt.Sprintf("platform %q missing valid 64-hex SHA-256 digest", plat))
			}
		}
		if len(digestIssues) > 0 {
			addCheck(report, "Toolchain Manifest: Archive Digests", false, strings.Join(digestIssues, "; "))
		} else {
			addCheck(report, "Toolchain Manifest: Archive Digests", true,
				fmt.Sprintf("Verified HTTPS URLs and SHA-256 digests for %d platform(s)", len(tm.URLs)))
		}
	}

	tcFile := cmp.Or(strings.TrimSpace(tm.ToolchainFile), "toolchain.cmake")
	if _, rErr := readRootRegularFile(pkgRoot, tcFile, maxSourceFileBytes); rErr != nil {
		addCheck(report, "Toolchain Manifest: CMake File", false, fmt.Sprintf("Missing or invalid %q", tcFile))
	} else {
		addCheck(report, "Toolchain Manifest: CMake File", true, fmt.Sprintf("Verified '%s'", tcFile))
	}

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, nil)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	return report, nil
}

func auditPortPackage(pkgRoot *os.Root, packagePath string, data []byte) (*ConformanceReport, error) {
	pm, err := decodeStrictJSON[portManifestSchema]("port_manifest.json", data)
	if err != nil {
		return nil, err
	}

	report := &ConformanceReport{
		Timestamp:   time.Now().UTC(),
		PackageName: pm.Name,
		PackagePath: packagePath,
		Trait:       "port_package",
		AbiVersion:  pm.Version,
		Passed:      true,
		Checks:      make([]ConformanceCheck, 0),
	}

	if pm.Name == "" {
		addCheck(report, "Port Manifest: Name", false, "port_manifest.json missing required 'name' field")
	} else if err := manifest.ValidatePackageRef("port package", pm.Name); err != nil {
		addCheck(report, "Port Manifest: Name", false, err.Error())
	} else {
		addCheck(report, "Port Manifest: Name", true, fmt.Sprintf("Port package '%s'", pm.Name))
	}

	if pm.Version == "" {
		addCheck(report, "Port Manifest: Version", false, "port_manifest.json missing required 'version' field")
	} else if err := manifest.ValidateName("port version", pm.Version); err != nil {
		addCheck(report, "Port Manifest: Version", false, err.Error())
	} else {
		addCheck(report, "Port Manifest: Version", true, fmt.Sprintf("Version '%s'", pm.Version))
	}

	var fileIssues []string
	for _, h := range pm.Headers {
		if _, ok := resolveRootHeader(pkgRoot, h); !ok {
			fileIssues = append(fileIssues, fmt.Sprintf("missing/invalid header %q", h))
		}
	}
	for _, src := range pm.Sources {
		if _, rErr := readRootRegularFile(pkgRoot, src, maxSourceFileBytes); rErr != nil {
			fileIssues = append(fileIssues, fmt.Sprintf("missing/invalid source %q", src))
		}
	}
	for _, inc := range pm.Includes {
		if !checkRootDirExists(pkgRoot, inc) {
			fileIssues = append(fileIssues, fmt.Sprintf("missing/invalid include dir %q", inc))
		}
	}
	if len(fileIssues) > 0 {
		addCheck(report, "Port Manifest: Files", false, strings.Join(fileIssues, "; "))
	} else {
		addCheck(report, "Port Manifest: Files", true, "Verified declared port files and containment")
	}

	if len(pm.Symbols) > 0 {
		var badSyms []string
		for _, k := range slices.Sorted(maps.Keys(pm.Symbols)) {
			sym := pm.Symbols[k]
			if err := manifest.ValidateName("port symbol key", k); err != nil || !isValidCSymbol(sym) {
				badSyms = append(badSyms, fmt.Sprintf("%s=%q", k, sym))
			}
		}
		if len(badSyms) > 0 {
			addCheck(report, "Port Symbol Contract", false, "Invalid C symbol mapping(s): "+strings.Join(badSyms, ", "))
		} else {
			addCheck(report, "Port Symbol Contract", true, fmt.Sprintf("Verified %d symbol mapping(s)", len(pm.Symbols)))
		}
	}

	recordMockEquivalence(report, verifyMockEquivalence(pkgRoot, pm.Sources, pm.MockSources))

	langPassed, langDetails := verifyLanguagePolicyRoot(pkgRoot, nil)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func recordMockEquivalence(report *ConformanceReport, mockEq *MockEquivalenceCheck) {
	report.MockEquivalence = mockEq
	if mockEq == nil {
		addCheck(report, "Mock / Real Equivalence", true, "No mock_sources declared — single production target")
		return
	}
	if !mockEq.Passed {
		addCheck(report, "Mock / Real Equivalence", false,
			"Mock and Real implementations exhibit divergences: "+strings.Join(mockEq.Divergences, "; "))
		return
	}
	addCheck(report, "Mock / Real Equivalence", true, "Mock and Real implementations are binary & contract equivalent")
}

func addCheck(r *ConformanceReport, name string, passed bool, details string) {
	r.Checks = append(r.Checks, ConformanceCheck{
		Name:    name,
		Passed:  passed,
		Details: details,
	})
	if !passed {
		r.Passed = false
	}
}

// verifyMockEquivalence compares exported C function signatures between Real and Mock
// translation units via *os.Root. Returns nil when no mock files exist so CRA reports
// never emit a false Mock/Real equivalence attestation (HIGH-70 / NEW-CLI-S1-01).
func verifyMockEquivalence(pkgRoot *os.Root, declaredSources, declaredMockSources []string) *MockEquivalenceCheck {
	var realRels []string
	var mockRels []string
	var fileDivergences []string

	seenMock := make(map[string]bool)
	seenReal := make(map[string]bool)

	for _, ms := range declaredMockSources {
		slash, _, err := validateContainedRelPath(ms)
		if err != nil {
			fileDivergences = append(fileDivergences, fmt.Sprintf("invalid mock_sources path %q", ms))
			continue
		}
		if _, rErr := readRootRegularFile(pkgRoot, slash, maxSourceFileBytes); rErr != nil {
			fileDivergences = append(fileDivergences, fmt.Sprintf("missing declared mock_sources file %q", ms))
			continue
		}
		if !seenMock[slash] {
			seenMock[slash] = true
			mockRels = append(mockRels, slash)
		}
	}

	for _, rs := range declaredSources {
		slash, _, err := validateContainedRelPath(rs)
		if err != nil || !strings.HasSuffix(slash, ".c") {
			continue
		}
		if _, rErr := readRootRegularFile(pkgRoot, slash, maxSourceFileBytes); rErr == nil && !seenReal[slash] {
			seenReal[slash] = true
			realRels = append(realRels, slash)
		}
	}

	_ = fs.WalkDir(pkgRoot.FS(), ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "build" || base == "builds" || base == ".toob" {
				return fs.SkipDir
			}
			return nil
		}
		slash := filepath.ToSlash(relPath)
		name := filepath.Base(slash)
		if !strings.HasSuffix(name, ".c") {
			return nil
		}
		if strings.HasSuffix(name, "_mock.c") || strings.Contains(name, "mock_") {
			if !seenMock[slash] {
				seenMock[slash] = true
				mockRels = append(mockRels, slash)
			}
		} else if len(declaredSources) == 0 && (strings.HasSuffix(name, "_real.c") || !strings.Contains(name, "test")) {
			if !seenReal[slash] {
				seenReal[slash] = true
				realRels = append(realRels, slash)
			}
		}
		return nil
	})

	if len(mockRels) == 0 && len(fileDivergences) == 0 {
		return nil
	}

	check := &MockEquivalenceCheck{
		Passed:      len(fileDivergences) == 0,
		Divergences: fileDivergences,
	}

	if len(realRels) == 0 {
		check.Passed = false
		check.Divergences = append(check.Divergences, "Mock implementation exists without corresponding Real C source file(s)")
		return check
	}

	readAllContents := func(rels []string) []string {
		out := make([]string, 0, len(rels))
		for _, r := range rels {
			b, err := readRootRegularFile(pkgRoot, r, maxSourceFileBytes)
			if err != nil {
				check.Passed = false
				check.Divergences = append(check.Divergences, fmt.Sprintf("cannot read %q: %v", r, err))
				continue
			}
			out = append(out, string(b))
		}
		return out
	}

	realFuncs := extractExportedCFunctionSigs(readAllContents(realRels))
	mockFuncs := extractExportedCFunctionSigs(readAllContents(mockRels))

	for _, fnName := range slices.Sorted(maps.Keys(realFuncs)) {
		realSig := realFuncs[fnName]
		mockSig, exists := mockFuncs[fnName]
		if !exists {
			check.Passed = false
			check.Divergences = append(check.Divergences,
				fmt.Sprintf("Function '%s' (%s) defined in Real TU is missing from Mock TU", fnName, realSig))
			continue
		}
		if mockSig != realSig {
			check.Passed = false
			check.Divergences = append(check.Divergences,
				fmt.Sprintf("Function '%s' signature divergence: Mock '%s' vs Real '%s'", fnName, mockSig, realSig))
		}
	}

	for _, fnName := range slices.Sorted(maps.Keys(mockFuncs)) {
		if _, exists := realFuncs[fnName]; exists {
			continue
		}
		// Allow dedicated mock test-reset helpers (e.g. *_mock_reset) while flagging mismatched symbol names.
		lower := strings.ToLower(fnName)
		if strings.Contains(lower, "mock") {
			continue
		}
		check.Passed = false
		check.Divergences = append(check.Divergences,
			fmt.Sprintf("Function '%s' (%s) defined in Mock TU has no matching Real TU definition", fnName, mockFuncs[fnName]))
	}

	return check
}

func stripCCommentsAndStrings(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	inBlock, inLine, inStr, inChar := false, false, false, false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inLine {
			if c == '\n' {
				inLine = false
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if inBlock {
			switch {
			case c == '*' && i+1 < len(src) && src[i+1] == '/':
				inBlock = false
				b.WriteString("  ")
				i++
			case c == '\n':
				b.WriteByte('\n')
			default:
				b.WriteByte(' ')
			}
			continue
		}
		if inStr {
			if c == '\\' && i+1 < len(src) {
				b.WriteString("  ")
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
			b.WriteByte(' ')
			continue
		}
		if inChar {
			if c == '\\' && i+1 < len(src) {
				b.WriteString("  ")
				i++
				continue
			}
			if c == '\'' {
				inChar = false
			}
			b.WriteByte(' ')
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			inLine = true
			b.WriteString("  ")
			i++
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			inBlock = true
			b.WriteString("  ")
			i++
			continue
		}
		if c == '"' {
			inStr = true
			b.WriteByte(' ')
			continue
		}
		if c == '\'' {
			inChar = true
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func readStrippedCSourcesRoot(pkgRoot *os.Root, rels []string) string {
	var b strings.Builder
	for _, rel := range rels {
		raw, err := readRootRegularFile(pkgRoot, rel, maxSourceFileBytes)
		if err != nil {
			continue
		}
		b.WriteString(stripCCommentsAndStrings(string(raw)))
		b.WriteByte('\n')
	}
	return b.String()
}

func isAttributionCommentLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "copyright") ||
		strings.Contains(lower, "(c)") ||
		strings.Contains(lower, "©") ||
		strings.Contains(lower, "@author") ||
		strings.Contains(lower, "spdx-license-identifier") ||
		strings.Contains(lower, "license:")
}

func extractCCommentLines(src string) map[int]string {
	commentsByLine := make(map[int]string)
	normalized := strings.ReplaceAll(src, "\r\n", "\n")
	line := 1
	inBlock, inLine, inStr, inChar := false, false, false, false

	var lineBuf strings.Builder
	flushLine := func(ln int) {
		if lineBuf.Len() > 0 {
			commentsByLine[ln] += " " + lineBuf.String()
			lineBuf.Reset()
		}
	}

	for i := 0; i < len(normalized); i++ {
		c := normalized[i]
		if inLine {
			if c == '\n' {
				flushLine(line)
				inLine = false
				line++
			} else {
				lineBuf.WriteByte(c)
			}
			continue
		}
		if inBlock {
			switch {
			case c == '*' && i+1 < len(normalized) && normalized[i+1] == '/':
				flushLine(line)
				inBlock = false
				i++
			case c == '\n':
				flushLine(line)
				line++
			default:
				lineBuf.WriteByte(c)
			}
			continue
		}
		if inStr {
			if c == '\\' && i+1 < len(normalized) {
				if normalized[i+1] == '\n' {
					line++
				}
				i++
				continue
			}
			switch c {
			case '"':
				inStr = false
			case '\n':
				line++
			}
			continue
		}
		if inChar {
			if c == '\\' && i+1 < len(normalized) {
				if normalized[i+1] == '\n' {
					line++
				}
				i++
				continue
			}
			switch c {
			case '\'':
				inChar = false
			case '\n':
				line++
			}
			continue
		}
		if c == '/' && i+1 < len(normalized) && normalized[i+1] == '/' {
			inLine = true
			i++
			continue
		}
		if c == '/' && i+1 < len(normalized) && normalized[i+1] == '*' {
			inBlock = true
			i++
			continue
		}
		if c == '"' {
			inStr = true
			continue
		}
		if c == '\'' {
			inChar = true
			continue
		}
		if c == '\n' {
			line++
		}
	}
	flushLine(line)
	return commentsByLine
}

// verifyLanguagePolicyRoot checks C/H comments and manifest prose via *os.Root
// for REG-035 compliance while skipping author/license/copyright proper-noun lines (MED-58).
func verifyLanguagePolicyRoot(pkgRoot *os.Root, explicitRels []string) (bool, string) {
	var targetRels []string
	if len(explicitRels) > 0 {
		targetRels = explicitRels
	} else {
		_ = fs.WalkDir(pkgRoot.FS(), ".", func(relPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if relPath == "." {
				return nil
			}
			if d.IsDir() {
				base := d.Name()
				if base == ".git" || base == "build" || base == "builds" || base == ".toob" {
					return fs.SkipDir
				}
				return nil
			}
			slash := filepath.ToSlash(relPath)
			// Skip generated conformance reports in package root if re-auditing.
			if slash == "conformance_report.json" || slash == "conformance_report.md" {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(slash))
			if ext == ".c" || ext == ".h" || ext == ".json" {
				targetRels = append(targetRels, slash)
			}
			return nil
		})
	}

	var violations []string
	for _, rel := range targetRels {
		data, err := readRootRegularFile(pkgRoot, rel, maxSourceFileBytes)
		if err != nil {
			continue
		}
		ext := strings.ToLower(filepath.Ext(rel))
		if ext == ".c" || ext == ".h" {
			comments := extractCCommentLines(string(data))
			for _, ln := range slices.Sorted(maps.Keys(comments)) {
				text := comments[ln]
				if isAttributionCommentLine(text) {
					continue
				}
				if germanCharRegex.MatchString(text) {
					violations = append(violations, fmt.Sprintf("%s:L%d", rel, ln))
				}
			}
			continue
		}

		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		for idx, line := range lines {
			if jsonSkipKeyRegex.MatchString(line) {
				continue
			}
			if germanCharRegex.MatchString(line) {
				violations = append(violations, fmt.Sprintf("%s:L%d", rel, idx+1))
			}
		}
	}

	if len(violations) > 0 {
		return false, "Non-English German characters (ä/ö/ü/ß) found at: " + strings.Join(violations, ", ")
	}
	return true, "All code comments and manifest texts strictly adhere to the English Language Policy"
}

func verifyLiteralLintFiles(packagePath string, files []string) (bool, string) {
	if len(files) == 0 {
		return true, "No wrapper C/H files present to scan"
	}
	report, err := literallint.RunLint(literallint.DefaultConfig(files...))
	if err != nil {
		return false, fmt.Sprintf("Literal lint check error: %v", err)
	}
	if !report.Passed {
		var details []string
		for _, v := range report.Violations {
			rel, _ := filepath.Rel(packagePath, v.File)
			if rel == "" {
				rel = v.File
			}
			details = append(details, fmt.Sprintf("%s:L%d '%s'", filepath.ToSlash(rel), v.Line, v.Literal))
		}
		return false, fmt.Sprintf("Found %d unauthorized numeric literal(s): %s", len(report.Violations), strings.Join(details, ", "))
	}
	return true, "Wrapper C/H code contains no unauthorized numeric literals (REG-040 clean; upstream_sources skipped)"
}

func verifyLiteralLintCheck(packagePath string) (bool, string) {
	report, err := literallint.RunLint(literallint.DefaultConfig(packagePath))
	if err != nil {
		return false, fmt.Sprintf("Literal lint check error: %v", err)
	}
	if !report.Passed {
		var details []string
		for _, v := range report.Violations {
			rel, _ := filepath.Rel(packagePath, v.File)
			if rel == "" {
				rel = v.File
			}
			details = append(details, fmt.Sprintf("%s:L%d '%s'", filepath.ToSlash(rel), v.Line, v.Literal))
		}
		return false, fmt.Sprintf("Found %d unauthorized numeric literal(s): %s", len(report.Violations), strings.Join(details, ", "))
	}
	return true, "All C/H files contain no unauthorized numeric literals (REG-040 clean)"
}
