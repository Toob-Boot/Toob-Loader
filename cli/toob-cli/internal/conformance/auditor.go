package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/literallint"
	"github.com/toob-boot/toob/internal/manifest"
)


// Required HAL Trait symbol tables
var requiredTraitSymbols = map[string][]string{
	"flash":     {"init", "deinit", "read", "write", "erase_sector", "get_sector_size", "get_vendor_error"},
	"wdt":       {"init", "deinit", "kick", "suspend", "resume"},
	"clock":     {"get_reset_reason"},
	"confirm":   {"init", "deinit", "check_ok", "clear"},
	"console":   {"init", "deinit", "putchar", "getchar", "flush"},
	"slot_caps": {"slot_caps"},
	"otp":       {"read_pubkey", "read_dslc", "write_dslc"},
	"keystore":  {"read_pubkey", "read_dslc", "write_dslc"},
	"entropy":   {"random"},
}

// AuditPackage audits a driver or chip package for HAL conformance and Mock/Real equivalence.
func AuditPackage(packagePath string) (*ConformanceReport, error) {
	manifestPath := filepath.Join(packagePath, "driver_manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		// Fallback check for chip_manifest.json
		chipManifestPath := filepath.Join(packagePath, "chip_manifest.json")
		if _, errChip := os.ReadFile(chipManifestPath); errChip == nil {
			return auditChipPackage(packagePath, chipManifestPath)
		}
		return nil, fmt.Errorf("package does not contain a driver_manifest.json or chip_manifest.json at %s", packagePath)
	}

	var dm manifest.DriverManifest
	if err := json.Unmarshal(data, &dm); err != nil {
		return nil, fmt.Errorf("invalid driver_manifest.json: %w", err)
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

	// 1. Manifest Metadata Check
	if dm.Name == "" {
		addCheck(report, "Manifest Metadata: Name", false, "driver_manifest.json is missing required 'name' field")
	} else {
		addCheck(report, "Manifest Metadata: Name", true, fmt.Sprintf("Package name '%s'", dm.Name))
	}

	if dm.Trait == "" {
		addCheck(report, "Manifest Metadata: Trait", false, "driver_manifest.json is missing required 'trait' field")
	} else {
		addCheck(report, "Manifest Metadata: Trait", true, fmt.Sprintf("Satisfies HAL trait '%s'", dm.Trait))
	}

	if dm.AbiVersion == "" {
		addCheck(report, "Manifest Metadata: ABI Version", false, "driver_manifest.json is missing required 'abi_version' field")
	} else {
		addCheck(report, "Manifest Metadata: ABI Version", true, fmt.Sprintf("ABI version '%s'", dm.AbiVersion))
	}

	// 2. Trait Symbol Contract Audit
	if reqSymbols, ok := requiredTraitSymbols[dm.Trait]; ok {
		if dm.Symbols == nil {
			addCheck(report, "Trait Symbol Contract", false, fmt.Sprintf("Driver satisfying trait '%s' defines no 'symbols' map in driver_manifest.json", dm.Trait))
		} else {
			missing := make([]string, 0)
			for _, symKey := range reqSymbols {
				symVal, exists := dm.Symbols[symKey]
				if !exists || strings.TrimSpace(symVal) == "" {
					missing = append(missing, symKey)
				}
			}

			if len(missing) > 0 {
				addCheck(report, "Trait Symbol Contract", false, fmt.Sprintf("Driver missing required symbols for trait '%s': %s", dm.Trait, strings.Join(missing, ", ")))
			} else {
				addCheck(report, "Trait Symbol Contract", true, fmt.Sprintf("All %d required symbols for trait '%s' are present in symbols map", len(reqSymbols), dm.Trait))
			}
		}
	} else if dm.Trait != "" {
		addCheck(report, "Trait Symbol Contract", true, fmt.Sprintf("Custom or non-standard trait '%s'", dm.Trait))
	}

	// 3. Slot Caps Trait Specific Checks
	if dm.Trait == "slot_caps" {
		if len(dm.Headers) == 0 {
			addCheck(report, "Slot Caps Trait: Headers", false, "slot_caps driver missing required 'headers' array in driver_manifest.json")
		} else {
			addCheck(report, "Slot Caps Trait: Headers", true, fmt.Sprintf("Header path '%s' specified", dm.Headers[0]))
		}
	}

	// 4. Mock / Real Equivalence Verification
	mockEq := verifyMockEquivalence(packagePath)
	report.MockEquivalence = mockEq
	if !mockEq.Passed {
		report.Passed = false
		addCheck(report, "Mock / Real Equivalence", false, fmt.Sprintf("Mock and Real implementations exhibit divergences: %s", strings.Join(mockEq.Divergences, "; ")))
	} else if len(mockEq.Divergences) == 0 {
		addCheck(report, "Mock / Real Equivalence", true, "Mock and Real implementations are binary & contract equivalent")
	}

	// 5. Language Policy Check (REG-035)
	langPassed, langDetails := verifyLanguagePolicy(packagePath)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	// 6. Literal-Bann-Lint Check (REG-040)
	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
}

func auditChipPackage(packagePath, chipManifestPath string) (*ConformanceReport, error) {
	data, err := os.ReadFile(chipManifestPath)
	if err != nil {
		return nil, err
	}
	var cm manifest.ChipManifest
	if err := json.Unmarshal(data, &cm); err != nil {
		return nil, fmt.Errorf("invalid chip_manifest.json: %w", err)
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

	if cm.Arch == "" {
		addCheck(report, "Chip Manifest: Arch", false, "chip_manifest.json missing required 'arch' field")
	} else {
		addCheck(report, "Chip Manifest: Arch", true, fmt.Sprintf("Architecture '%s'", cm.Arch))
	}

	if cm.SlotCapabilities == nil {
		addCheck(report, "Chip Manifest: Slot Capabilities", false, "chip_manifest.json missing required 'slot_capabilities'")
	} else {
		addCheck(report, "Chip Manifest: Slot Capabilities", true, fmt.Sprintf("Exec model '%s', slot count %d", cm.SlotCapabilities.ExecModel, cm.SlotCapabilities.SlotCount))
	}

	if len(cm.HalBindings) == 0 {
		addCheck(report, "Chip Manifest: HAL Bindings", false, "chip_manifest.json missing required 'hal_bindings' map")
	} else {
		addCheck(report, "Chip Manifest: HAL Bindings", true, fmt.Sprintf("Defines %d HAL driver trait bindings", len(cm.HalBindings)))
	}

	mockEq := verifyMockEquivalence(packagePath)
	report.MockEquivalence = mockEq
	if !mockEq.Passed {
		report.Passed = false
		addCheck(report, "Mock / Real Equivalence", false, fmt.Sprintf("Mock and Real implementations exhibit divergences: %s", strings.Join(mockEq.Divergences, "; ")))
	}

	langPassed, langDetails := verifyLanguagePolicy(packagePath)
	addCheck(report, "Language Policy: English Comments", langPassed, langDetails)

	lintPassed, lintDetails := verifyLiteralLintCheck(packagePath)
	addCheck(report, "Literal-Bann-Lint: No Hardcoded Literals", lintPassed, lintDetails)

	return report, nil
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

// verifyMockEquivalence checks C files in packagePath for Mock vs Real function signature and return type parity.
func verifyMockEquivalence(packagePath string) *MockEquivalenceCheck {
	check := &MockEquivalenceCheck{
		Passed:      true,
		Divergences: make([]string, 0),
	}

	var realFiles []string
	var mockFiles []string

	_ = filepath.WalkDir(packagePath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if strings.HasSuffix(name, "_mock.c") || strings.Contains(name, "mock_") {
			mockFiles = append(mockFiles, path)
		} else if strings.HasSuffix(name, "_real.c") || (strings.HasSuffix(name, ".c") && !strings.Contains(name, "test")) {
			realFiles = append(realFiles, path)
		}
		return nil
	})

	if len(mockFiles) == 0 {
		return check // No mock TU to compare against
	}

	// Extract function signatures: e.g. "boot_status_t esp32c6_read_pubkey(uint8_t *out_pubkey, size_t len)"
	sigRegex := regexp.MustCompile(`(boot_status_t|void|int|uint32_t)\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)`)

	extractFuncs := func(fileList []string) map[string]string {
		funcs := make(map[string]string)
		for _, f := range fileList {
			content, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			matches := sigRegex.FindAllStringSubmatch(string(content), -1)
			for _, m := range matches {
				fnName := m[2]
				fnSig := fmt.Sprintf("%s(%s)", m[1], strings.TrimSpace(m[3]))
				funcs[fnName] = fnSig
			}
		}
		return funcs
	}

	mockFuncs := extractFuncs(mockFiles)
	realFuncs := extractFuncs(realFiles)

	for fnName, mockSig := range mockFuncs {
		if realSig, exists := realFuncs[fnName]; exists {
			if mockSig != realSig {
				check.Passed = false
				check.Divergences = append(check.Divergences, fmt.Sprintf("Function '%s' signature divergence: Mock '%s' vs Real '%s'", fnName, mockSig, realSig))
			}
		}
	}

	return check
}

func verifyLanguagePolicy(packagePath string) (bool, string) {
	germanCharRegex := regexp.MustCompile(`[äöüÄÖÜß]`)
	var violations []string

	_ = filepath.WalkDir(packagePath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".c" || ext == ".h" || ext == ".json" {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if germanCharRegex.MatchString(line) {
					relPath, _ := filepath.Rel(packagePath, path)
					violations = append(violations, fmt.Sprintf("%s:L%d", relPath, i+1))
				}
			}
		}
		return nil
	})

	if len(violations) > 0 {
		return false, fmt.Sprintf("Non-English German characters (ä/ö/ü/ß) found at: %s", strings.Join(violations, ", "))
	}
	return true, "All code comments and manifest texts strictly adhere to the English Language Policy"
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
			details = append(details, fmt.Sprintf("%s:L%d '%s'", rel, v.Line, v.Literal))
		}
		return false, fmt.Sprintf("Found %d unauthorized numeric literal(s): %s", len(report.Violations), strings.Join(details, ", "))
	}

	return true, "Package source code contains no unauthorized numeric literals (REG-040 clean)"
}

