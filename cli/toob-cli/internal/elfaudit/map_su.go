package elfaudit

import (
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type tuDomain string

const (
	domainCore    tuDomain = "core"
	domainHAL     tuDomain = "hal"
	domainCrypto  tuDomain = "crypto"
	domainApp     tuDomain = "app"
	domainUnknown tuDomain = "unknown"
)

var (
	// Matches GNU ld section+object lines:
	// " .text.foo  0x08001234  0x40  libtoob_core.a(boot_verify.c.obj)"
	mapSectionObjRe = regexp.MustCompile(`^\s*\.?[A-Za-z_.$][A-Za-z0-9_.$*-]*\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+(.+)$`)
	// Matches continuation object lines when section name wrapped:
	// "            0x08001234  0x40  libtoob_core.a(boot_verify.c.obj)"
	mapWrappedObjRe = regexp.MustCompile(`^\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+(.+)$`)
	// Matches GNU ld symbol assignment lines under an input section:
	// "            0x08001234        boot_verify_slot_image"
	mapSymbolLineRe = regexp.MustCompile(`^\s+0x[0-9a-fA-F]+\s+([A-Za-z_][A-Za-z0-9_.$]*)$`)
)

func classifyTUObjectDomain(objPath string) tuDomain {
	norm := strings.ToLower(filepath.ToSlash(strings.TrimSpace(objPath)))
	switch {
	case strings.Contains(norm, "libtoob_core.a"),
		strings.Contains(norm, "libtoob_utils.a"),
		strings.Contains(norm, "libtoob_heatshrink.a"),
		strings.Contains(norm, "toob_stage1_entry"),
		strings.Contains(norm, "toob_stage0.dir"),
		strings.Contains(norm, "toobloader/core/"),
		strings.Contains(norm, "toobloader/stage0/"):
		return domainCore
	case strings.Contains(norm, "libtoob_crypto"),
		strings.Contains(norm, "libtoob_recovery_crypto"),
		strings.Contains(norm, "/crypto/"):
		return domainCrypto
	case strings.Contains(norm, "libtoob_chip.a"),
		strings.Contains(norm, "libtoob_arch.a"),
		strings.Contains(norm, "libtoob_hal.a"),
		strings.Contains(norm, "generated_platform_wiring"),
		strings.Contains(norm, "/drivers/"),
		strings.Contains(norm, "/chips/"),
		strings.Contains(norm, "/arch/"),
		strings.Contains(norm, "/soc/"):
		return domainHAL
	case strings.Contains(norm, "libtoob_libtoob.a"),
		strings.Contains(norm, "toob_recovery.dir"),
		strings.Contains(norm, "/recovery/"),
		strings.Contains(norm, "/sdk/libtoob/"),
		strings.Contains(norm, "/app/"):
		return domainApp
	default:
		return domainUnknown
	}
}

func isCoreOwnedSymbol(sym string) bool {
	if sym == "boot_platform_init" {
		// boot_platform_init is generated in chip/HAL wiring and legitimately lives in domainHAL.
		return false
	}
	return strings.HasPrefix(sym, "boot_") ||
		strings.HasPrefix(sym, "stage0_") ||
		strings.HasPrefix(sym, "toob_boot_")
}

func isCryptoOwnedSymbol(sym string) bool {
	return strings.HasPrefix(sym, "crypto_") ||
		strings.HasPrefix(sym, "monocypher_") ||
		strings.HasPrefix(sym, "sha256_sw_") ||
		strings.HasPrefix(sym, "ml_dsa_")
}

var gccCloneSuffixes = []string{".constprop", ".isra", ".part", ".cold", ".lto_priv"}

func normalizeFuncName(name string) string {
	trimmed := strings.TrimSpace(name)
	for _, marker := range gccCloneSuffixes {
		if idx := strings.Index(trimmed, marker); idx > 0 {
			rest := trimmed[idx+len(marker):]
			if rest == "" || rest[0] == '.' {
				trimmed = trimmed[:idx]
			}
		}
	}
	return trimmed
}

func extractTextSectionFunc(sectionToken string) (string, bool) {
	for _, prefix := range []string{".iram1.text.", ".text.startup.", ".text.unlikely.", ".text."} {
		if strings.HasPrefix(sectionToken, prefix) {
			fn := normalizeFuncName(strings.TrimPrefix(sectionToken, prefix))
			if fn != "" {
				return fn, true
			}
		}
	}
	return "", false
}

func isAllowedRecoveryRuntimeSymbol(sym, objPath string) bool {
	switch sym {
	case "boot_main", "boot_panic", "boot_terminal_halt", "boot_secure_zeroize":
	default:
		return false
	}
	norm := strings.ToLower(filepath.ToSlash(strings.TrimSpace(objPath)))
	return strings.Contains(norm, "/recovery/recovery_port.c") ||
		strings.HasPrefix(norm, "recovery/recovery_port.c") ||
		(strings.Contains(norm, "toob_recovery.dir/") &&
			(strings.HasSuffix(norm, "recovery_port.c.obj") || strings.HasSuffix(norm, "recovery_port.o")))
}

// auditSymbolOwnership parses a GNU ld .map file to enforce per-TU domain
// ownership boundaries (core vs hal vs crypto vs app), detect duplicate or
// hijacked core symbols (CRIT-73), and collect normalized linked function names
// placed inside the active memory map (excluding Discarded input sections).
func auditSymbolOwnership(mapPath string, allowRecoveryRuntime bool, report *ELFAuditReport) map[string]struct{} {
	if strings.TrimSpace(mapPath) == "" {
		addCheck(report, "TU Symbol Ownership", true, "No linker .map path configured — check skipped")
		return nil
	}

	// #nosec G304 -- MapPath comes from build artifact discovery or explicit audit config.
	data, err := os.ReadFile(mapPath)
	if err != nil {
		addCheck(report, "TU Symbol Ownership", false, fmt.Sprintf("Failed to read linker map %q: %v", mapPath, err))
		return nil
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	inMemoryMap := false
	currentObj := ""
	currentDomain := domainUnknown
	seenSymOwner := make(map[string]string)
	linkedFuncs := make(map[string]struct{})
	var violations []string
	verifiedSyms := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inMemoryMap {
			if trimmed == "Linker script and memory map" {
				inMemoryMap = true
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "*(") || strings.HasPrefix(trimmed, "LOAD ") {
			continue
		}
		if strings.HasPrefix(trimmed, "OUTPUT(") || strings.HasPrefix(trimmed, "Cross Reference Table") {
			break
		}

		if fields := strings.Fields(trimmed); len(fields) > 0 {
			if fn, ok := extractTextSectionFunc(fields[0]); ok {
				linkedFuncs[fn] = struct{}{}
			}
		}

		if m := mapSectionObjRe.FindStringSubmatch(line); len(m) == 2 {
			obj := strings.TrimSpace(m[1])
			if !strings.HasPrefix(obj, "*fill*") {
				currentObj = obj
				currentDomain = classifyTUObjectDomain(obj)
			} else {
				currentObj = ""
				currentDomain = domainUnknown
			}
			continue
		}
		if m := mapWrappedObjRe.FindStringSubmatch(line); len(m) == 2 {
			obj := strings.TrimSpace(m[1])
			if !strings.HasPrefix(obj, "*fill*") {
				currentObj = obj
				currentDomain = classifyTUObjectDomain(obj)
			}
			continue
		}
		if currentObj == "" {
			continue
		}

		if m := mapSymbolLineRe.FindStringSubmatch(line); len(m) == 2 {
			sym := m[1]
			if strings.Contains(sym, "=") || strings.HasPrefix(sym, ".") {
				continue
			}
			if norm := normalizeFuncName(sym); norm != "" {
				linkedFuncs[norm] = struct{}{}
			}
			if strings.HasPrefix(sym, "__") {
				continue
			}
			verifiedSyms++

			if prevObj, dup := seenSymOwner[sym]; dup && prevObj != currentObj {
				violations = append(violations, fmt.Sprintf("duplicate symbol %q across %s and %s", sym, prevObj, currentObj))
				continue
			}
			seenSymOwner[sym] = currentObj

			if sym == "boot_platform_init" {
				if currentDomain != domainHAL && currentDomain != domainCore && currentDomain != domainApp {
					violations = append(violations, fmt.Sprintf("symbol %q owned by unexpected domain %s (%s)", sym, currentDomain, currentObj))
				}
				continue
			}

			if isCoreOwnedSymbol(sym) && currentDomain != domainCore {
				if !allowRecoveryRuntime || currentDomain != domainApp || !isAllowedRecoveryRuntimeSymbol(sym, currentObj) {
					violations = append(violations, fmt.Sprintf("core symbol %q hijacked by %s TU %s", sym, currentDomain, currentObj))
				}
			}
			if isCryptoOwnedSymbol(sym) && currentDomain != domainCrypto && currentDomain != domainCore {
				violations = append(violations, fmt.Sprintf("crypto symbol %q owned by non-crypto TU %s (%s)", sym, currentDomain, currentObj))
			}
		}
	}

	if !inMemoryMap {
		addCheck(report, "TU Symbol Ownership", false, fmt.Sprintf("Malformed linker map %q: missing 'Linker script and memory map' section", mapPath))
		return nil
	}
	if len(violations) > 0 {
		addCheck(report, "TU Symbol Ownership", false, strings.Join(violations, "; "))
		return linkedFuncs
	}
	addCheck(report, "TU Symbol Ownership", true, fmt.Sprintf("Verified TU ownership for %d mapped symbol(s) in %s", verifiedSyms, filepath.Base(mapPath)))
	return linkedFuncs
}

// auditSSP verifies __stack_chk_fail presence in the ELF symbol table when
// Stack Smashing Protection (-fstack-protector-strong) is required.
func auditSSP(f *elf.File, config ELFAuditConfig, report *ELFAuditReport) {
	if !config.RequireSSP {
		addCheck(report, "Stack Protector (SSP)", true, "SSP check not required — check skipped")
		return
	}
	syms, err := f.Symbols()
	if err != nil {
		addCheck(report, "Stack Protector (SSP)", false, fmt.Sprintf("SSP active but ELF symtab unreadable: %v", err))
		return
	}
	for _, s := range syms {
		if s.Name == "__stack_chk_fail" {
			addCheck(report, "Stack Protector (SSP)", true, "Verified __stack_chk_fail symbol present for SSP")
			return
		}
	}
	addCheck(report, "Stack Protector (SSP)", false, "SSP active but mandatory __stack_chk_fail symbol is missing from ELF")
}

// auditStackUsage parses GCC -fstack-usage (.su) files across configured
// directories and rejects dynamic/unbounded frames or functions exceeding budget.
// When MapPath is configured, only functions actively linked into the audited
// ELF (present in ELF STT_FUNC symtab or placed in the linker map) are checked.
func auditStackUsage(f *elf.File, config ELFAuditConfig, mapFuncs map[string]struct{}, report *ELFAuditReport) {
	if len(config.StackUsageDirs) == 0 {
		addCheck(report, "Stack Usage Budget (.su)", true, "No .su directories configured — check skipped")
		return
	}

	budget := config.MaxStackBytes
	if budget == 0 {
		if config.Profile == ProfileProduction {
			budget = DefaultMaxStackBytesProduction
		} else {
			budget = DefaultMaxStackBytesDev
		}
	}

	filterLinked := strings.TrimSpace(config.MapPath) != ""
	var activeFuncs map[string]struct{}
	if filterLinked {
		activeFuncs = make(map[string]struct{}, len(mapFuncs))
		for fn := range mapFuncs {
			activeFuncs[fn] = struct{}{}
		}
		if f != nil {
			if syms, symErr := f.Symbols(); symErr == nil {
				for _, sym := range syms {
					if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Name != "" {
						if norm := normalizeFuncName(sym.Name); norm != "" {
							activeFuncs[norm] = struct{}{}
						}
					}
				}
			}
		}
	}

	var suFiles []string
	for _, dir := range config.StackUsageDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, wErr error) error {
			if wErr != nil {
				return wErr
			}
			if !d.IsDir() && strings.EqualFold(filepath.Ext(d.Name()), ".su") {
				suFiles = append(suFiles, path)
			}
			return nil
		})
		if walkErr != nil {
			addCheck(report, "Stack Usage Budget (.su)", false, fmt.Sprintf("Failed scanning .su dir %q: %v", dir, walkErr))
			return
		}
	}

	if len(suFiles) == 0 {
		addCheck(report, "Stack Usage Budget (.su)", false, "StackUsageDirs configured, but no .su files were found")
		return
	}

	var violations []string
	var maxObserved uint64
	fnCount := 0

	for _, suPath := range suFiles {
		// #nosec G304 -- .su paths discovered under caller-configured build output directories.
		raw, readErr := os.ReadFile(suPath)
		if readErr != nil {
			violations = append(violations, fmt.Sprintf("unreadable %s: %v", filepath.Base(suPath), readErr))
			continue
		}
		lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
		for idx, rawLine := range lines {
			line := strings.TrimSpace(rawLine)
			if line == "" {
				continue
			}
			fields := strings.Split(line, "\t")
			if len(fields) < 3 {
				violations = append(violations, fmt.Sprintf("%s:L%d malformed .su entry %q", filepath.Base(suPath), idx+1, line))
				continue
			}
			fnSpec := fields[0]
			if filterLinked {
				fnName := suEntryFuncName(fnSpec)
				if _, ok := activeFuncs[fnName]; !ok {
					continue
				}
			}
			bytesVal, parseErr := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
			if parseErr != nil {
				violations = append(violations, fmt.Sprintf("%s:L%d invalid stack byte count %q", filepath.Base(suPath), idx+1, fields[1]))
				continue
			}
			kind := strings.ToLower(strings.TrimSpace(fields[2]))
			fnCount++
			if bytesVal > maxObserved {
				maxObserved = bytesVal
			}
			if strings.Contains(kind, "dynamic") {
				violations = append(violations, fmt.Sprintf("%s uses unbounded dynamic stack allocation (%d bytes)", fnSpec, bytesVal))
				continue
			}
			if bytesVal > budget {
				violations = append(violations, fmt.Sprintf("%s stack frame %d bytes exceeds %s budget of %d bytes", fnSpec, bytesVal, config.Profile, budget))
			}
		}
	}

	if fnCount == 0 && len(violations) == 0 {
		addCheck(report, "Stack Usage Budget (.su)", false, "StackUsageDirs configured, but zero linked functions matched .su entries")
		return
	}
	if len(violations) > 0 {
		addCheck(report, "Stack Usage Budget (.su)", false, strings.Join(violations, "; "))
		return
	}
	addCheck(report, "Stack Usage Budget (.su)", true,
		fmt.Sprintf("Verified %d function stack frames across %d .su file(s) (max %d <= %d bytes)", fnCount, len(suFiles), maxObserved, budget))
}

func suEntryFuncName(fnSpec string) string {
	trimmed := strings.TrimSpace(fnSpec)
	if idx := strings.LastIndexByte(trimmed, ':'); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	return normalizeFuncName(trimmed)
}
