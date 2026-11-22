package build

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"math/bits"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// VerifyResult captures the outcome of a single plausibility check.
type VerifyResult struct {
	Check   string // Check ID, e.g. "ADDR-001"
	Name    string // Human-readable check name
	Passed  bool   // False only on hard errors; true on PASS and non-fatal WARNINGs (HIGH-18).
	Warning bool   // True when advisory / vendor-heuristic warning was raised.
	Details string
}

// provenanceRef links an auditable element to its provenance annotation.
type provenanceRef struct {
	category string
	name     string
	prov     *Provenance
}

// Recognized provenance source types for CRA traceability.
var allowedSources = map[string]bool{
	"trm":        true, // Technical Reference Manual
	"datasheet":  true, // Vendor datasheet
	"vendor_sdk": true, // Vendor SDK headers/source
	"rom_disasm": true, // ROM disassembly
	"errata":     true, // Errata document
	"scan":       true, // Automated scan (marks element as UNVERIFIED)
}

var allowedResetClasses = map[string]bool{
	"power":       true,
	"intentional": true,
	"crash":       true,
}

// VerifyHardwareProvenance runs all chip-agnostic plausibility checks against a hardware description.
// Each check returns a single result. The caller decides whether failures are fatal.
func VerifyHardwareProvenance(hj *HardwareJson) []VerifyResult {
	checkers := []func(*HardwareJson) VerifyResult{
		// Provenance annotation checks
		checkSourceAllowList,
		checkVerifiedDateFormat,
		checkProvenanceCoverage,
		// Register address checks
		checkRegisterBaseAlignment,
		checkRegisterOffsetBounds,
		checkPeripheralAddressRange,
		checkNoDuplicateBaseAddresses,
		checkFlatRegisterDedup,
		// Flash geometry checks
		checkFlashRegionContinuity,
		checkFlashSectorArithmetic,
		checkFlashSizeSanity,
		checkXipBaseAboveFlash,
		// Memory layout checks
		checkIramSanity,
		checkLpRAMNoOverlapIram,
		checkReservedRAMOverlaps,
		checkReservedRAMBounds,
		// Reset cause checks
		checkResetCodeUniqueness,
		checkResetCodeFitsMask,
		checkResetClassVocabulary,
		// Constant checks
		checkHexConstantWidth,
	}

	results := make([]VerifyResult, 0, len(checkers))
	for _, check := range checkers {
		results = append(results, check(hj))
	}
	return results
}

// HasVerificationFailures returns true if any check in the results failed.
func HasVerificationFailures(results []VerifyResult) bool {
	for i := range results {
		if !results[i].Passed {
			return true
		}
	}
	return false
}

// FormatVerificationErrors returns a human-readable summary of all failed checks.
func FormatVerificationErrors(results []VerifyResult) string {
	var lines []string
	for _, r := range results {
		if !r.Passed {
			lines = append(lines, fmt.Sprintf("  [FAIL] %s: %s — %s", r.Check, r.Name, r.Details))
		}
	}
	return strings.Join(lines, "\n")
}

// --- Helpers ---

// parseAddrLiteral parses an unsigned integer literal using C rules (0x/0X hex
// or non-zero-prefixed base-10), preventing hex-vs-decimal differentials with
// code generation (MED-16).
func parseAddrLiteral(raw string) (uint64, error) {
	digits, base := raw, 10
	if len(raw) > 2 && (raw[:2] == "0x" || raw[:2] == "0X") {
		digits, base = raw[2:], 16
	} else if len(raw) > 1 && raw[0] == '0' {
		return 0, fmt.Errorf("literal %q has a leading zero (octal ambiguity)", raw)
	}
	if digits == "" {
		return 0, errors.New("empty literal")
	}
	return strconv.ParseUint(digits, base, 64)
}

func isPowerOfTwo(n uint64) bool {
	return n > 0 && bits.OnesCount64(n) == 1
}

// collectAllProvenance gathers provenance annotations from all auditable elements.
func collectAllProvenance(hj *HardwareJson) []provenanceRef {
	var refs []provenanceRef
	inheritTop := func(p *Provenance) *Provenance {
		if p != nil {
			return p
		}
		return hj.Provenance
	}

	p := hj.Flash.Provenance
	if p == nil {
		p = hj.Provenance
	}
	refs = append(refs, provenanceRef{"Flash Geometry", hj.ChipFamily + "_flash", p})

	for _, reg := range hj.Flash.Regions {
		name := reg.Name
		if name == "" {
			name = fmt.Sprintf("region_0x%08x", reg.Base)
		}
		refs = append(refs, provenanceRef{"Flash Region", name, reg.Provenance})
	}

	if hj.Memory.IramBase != "" || hj.Memory.Provenance != nil {
		refs = append(refs, provenanceRef{"Memory Layout", hj.ChipFamily + "_memory", inheritTop(hj.Memory.Provenance)})
	}
	if hj.CryptoCapabilities.ArenaSize > 0 || hj.CryptoCapabilities.Provenance != nil {
		refs = append(refs, provenanceRef{"Crypto Capabilities", hj.ChipFamily + "_crypto", inheritTop(hj.CryptoCapabilities.Provenance)})
	}
	if hj.BootromImage != nil {
		refs = append(refs, provenanceRef{"BootROM Image", hj.ChipFamily + "_bootrom_image", inheritTop(hj.BootromImage.Provenance)})
	}

	for _, ram := range hj.ReservedRamRegions {
		refs = append(refs, provenanceRef{"Reserved RAM", ram.Name, ram.Provenance})
	}

	for _, name := range slices.Sorted(maps.Keys(hj.RegisterBlocks)) {
		block := hj.RegisterBlocks[name]
		refs = append(refs, provenanceRef{"Register Block", name, block.Provenance})
	}
	for _, flatName := range slices.Sorted(maps.Keys(hj.RegistersFlat)) {
		refs = append(refs, provenanceRef{"Flat Register", flatName, hj.Provenance})
	}
	for _, regName := range slices.Sorted(maps.Keys(hj.Registers)) {
		refs = append(refs, provenanceRef{"Legacy Register", regName, hj.Provenance})
	}
	if len(hj.Constants) > 0 {
		refs = append(refs, provenanceRef{"Hardware Constants", hj.ChipFamily + "_constants", hj.Provenance})
	}

	if hj.ResetCauses != nil {
		for _, code := range hj.ResetCauses.Codes {
			refs = append(refs, provenanceRef{"Reset Cause", code.Name, code.Provenance})
		}
	}

	return refs
}

// collectPresentProvenance extends collectAllProvenance with optional section-level
// provenance blocks whenever present so their sources and dates are also validated.
func collectPresentProvenance(hj *HardwareJson) []provenanceRef {
	refs := collectAllProvenance(hj)
	if hj.Provenance != nil {
		refs = append(refs, provenanceRef{"Top-Level Hardware", hj.ChipFamily, hj.Provenance})
	}
	if hj.Flash.Provenance != nil {
		refs = append(refs, provenanceRef{"Flash Section", hj.ChipFamily + "_flash_section", hj.Flash.Provenance})
	}
	if hj.ResetCauses != nil && hj.ResetCauses.Provenance != nil {
		refs = append(refs, provenanceRef{"Reset Causes", hj.ChipFamily + "_reset_causes", hj.ResetCauses.Provenance})
	}
	return refs
}

// === Provenance Annotation Checks (PROV-xxx) ===

func checkSourceAllowList(hj *HardwareJson) VerifyResult {
	refs := collectPresentProvenance(hj)
	var invalid []string
	for _, ref := range refs {
		if ref.prov == nil {
			continue
		}
		src := strings.TrimSpace(ref.prov.Source)
		if src == "" || !allowedSources[src] {
			invalid = append(invalid, fmt.Sprintf("%s '%s' (source: '%s')", ref.category, ref.name, ref.prov.Source))
			continue
		}
		if src != "scan" && strings.TrimSpace(ref.prov.Ref) == "" {
			invalid = append(invalid, fmt.Sprintf("%s '%s' (source '%s' requires non-empty 'ref')", ref.category, ref.name, src))
		}
	}

	if len(invalid) > 0 {
		allowed := make([]string, 0, len(allowedSources))
		for k := range allowedSources {
			allowed = append(allowed, k)
		}
		sort.Strings(allowed)
		return VerifyResult{
			Check: "PROV-001", Name: "Source Allow-List", Passed: false,
			Details: fmt.Sprintf("Invalid source/reference annotation(s): %s. Allowed sources: [%s]",
				strings.Join(invalid, "; "), strings.Join(allowed, ", ")),
		}
	}
	return VerifyResult{
		Check: "PROV-001", Name: "Source Allow-List", Passed: true,
		Details: fmt.Sprintf("All %d provenance annotations use recognized sources and references", len(refs)),
	}
}

// checkVerifiedDateFormat ensures all verification dates are ISO-8601, >= 2000-01-01,
// and not in the future (allowing up to UTC+14 local date, LOW-15 / MED-36).
func checkVerifiedDateFormat(hj *HardwareJson) VerifyResult {
	refs := collectPresentProvenance(hj)
	latestAllowed := time.Now().UTC().Add(14 * time.Hour)
	var invalid []string

	for _, ref := range refs {
		if ref.prov == nil {
			continue
		}
		src := strings.TrimSpace(ref.prov.Source)
		if ref.prov.Verified == "" {
			if src != "" && src != "scan" {
				invalid = append(invalid, fmt.Sprintf("%s '%s': missing 'verified' date for non-scan source '%s'", ref.category, ref.name, src))
			}
			continue
		}
		parsed, err := time.Parse("2006-01-02", ref.prov.Verified)
		if err != nil {
			invalid = append(invalid, fmt.Sprintf("%s '%s': '%s' is not YYYY-MM-DD", ref.category, ref.name, ref.prov.Verified))
			continue
		}
		if parsed.Year() < 2000 {
			invalid = append(invalid, fmt.Sprintf("%s '%s': date '%s' precedes 2000-01-01", ref.category, ref.name, ref.prov.Verified))
			continue
		}
		if parsed.After(latestAllowed) {
			invalid = append(invalid, fmt.Sprintf("%s '%s': date '%s' is in the future", ref.category, ref.name, ref.prov.Verified))
		}
	}

	if len(invalid) > 0 {
		return VerifyResult{
			Check: "PROV-002", Name: "Verified Date Format", Passed: false,
			Details: strings.Join(invalid, "; "),
		}
	}
	return VerifyResult{
		Check: "PROV-002", Name: "Verified Date Format", Passed: true,
		Details: "All verification dates are valid ISO-8601 and not in the future",
	}
}

func checkProvenanceCoverage(hj *HardwareJson) VerifyResult {
	refs := collectAllProvenance(hj)
	var missing []string
	for _, ref := range refs {
		if ref.prov == nil || strings.TrimSpace(ref.prov.Source) == "" {
			missing = append(missing, fmt.Sprintf("%s '%s'", ref.category, ref.name))
		}
	}

	if len(missing) > 0 {
		return VerifyResult{
			Check: "PROV-003", Name: "Provenance Coverage", Passed: false,
			Details: fmt.Sprintf("%d element(s) lack provenance: %s", len(missing), strings.Join(missing, "; ")),
		}
	}
	return VerifyResult{
		Check: "PROV-003", Name: "Provenance Coverage", Passed: true,
		Details: fmt.Sprintf("All %d auditable elements have provenance annotations", len(refs)),
	}
}

// === Register Address Checks (ADDR-xxx) ===

func checkRegisterBaseAlignment(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-001", Name: "Register Base Alignment", Passed: true, Details: "No register blocks defined"}
	}

	var violations []string
	for _, name := range slices.Sorted(maps.Keys(hj.RegisterBlocks)) {
		if !isCIdentifier(name) {
			violations = append(violations, fmt.Sprintf("'%s': invalid C identifier", name))
			continue
		}
		block := hj.RegisterBlocks[name]
		addr, err := parseAddrLiteral(block.Base)
		if err != nil {
			violations = append(violations, fmt.Sprintf("'%s': invalid address '%s'", name, block.Base))
			continue
		}
		if addr > math.MaxUint32 {
			violations = append(violations, fmt.Sprintf("'%s' at %s exceeds 32-bit address space", name, block.Base))
			continue
		}
		if addr%4 != 0 {
			violations = append(violations, fmt.Sprintf("'%s' at %s (not 4-byte aligned)", name, block.Base))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "ADDR-001", Name: "Register Base Alignment", Passed: false,
			Details: "Unaligned or invalid register base(s): " + strings.Join(violations, "; "),
		}
	}
	return VerifyResult{
		Check: "ADDR-001", Name: "Register Base Alignment", Passed: true,
		Details: fmt.Sprintf("%d register blocks, all 4-byte aligned", len(hj.RegisterBlocks)),
	}
}

// checkRegisterOffsetBounds checks register offsets; offsets >= 64KB emit an
// advisory WARNING rather than failing non-ESP peripheral maps (HIGH-18).
func checkRegisterOffsetBounds(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-002", Name: "Register Offset Bounds", Passed: true, Details: "No register blocks defined"}
	}

	const maxTypicalOffset uint64 = 0x10000
	var hardErrors, warnings []string
	for _, blockName := range slices.Sorted(maps.Keys(hj.RegisterBlocks)) {
		block := hj.RegisterBlocks[blockName]
		baseAddr, baseErr := parseAddrLiteral(block.Base)
		for _, regName := range slices.Sorted(maps.Keys(block.Regs)) {
			if !isCIdentifier(regName) {
				hardErrors = append(hardErrors, fmt.Sprintf("'%s.%s': invalid C identifier", blockName, regName))
				continue
			}
			offsetStr := block.Regs[regName]
			offset, err := parseAddrLiteral(offsetStr)
			if err != nil {
				hardErrors = append(hardErrors, fmt.Sprintf("'%s.%s': invalid offset '%s'", blockName, regName, offsetStr))
				continue
			}
			if baseErr == nil {
				if baseAddr <= math.MaxUint32 && (offset > math.MaxUint32 || baseAddr+offset > math.MaxUint32) {
					hardErrors = append(hardErrors, fmt.Sprintf("'%s.%s' base + offset exceeds 32-bit address space", blockName, regName))
					continue
				}
				if baseAddr > math.MaxUint32 && offset > math.MaxUint64-baseAddr {
					hardErrors = append(hardErrors, fmt.Sprintf("'%s.%s' base + offset overflows 64-bit address space", blockName, regName))
					continue
				}
			}
			if offset >= maxTypicalOffset {
				warnings = append(warnings, fmt.Sprintf("'%s.%s' offset %s >= 64KB", blockName, regName, offsetStr))
			}
		}
	}

	if len(hardErrors) > 0 {
		return VerifyResult{
			Check: "ADDR-002", Name: "Register Offset Bounds", Passed: false,
			Details: "Invalid register offset(s): " + strings.Join(hardErrors, "; "),
		}
	}
	if len(warnings) > 0 {
		return VerifyResult{
			Check: "ADDR-002", Name: "Register Offset Bounds", Passed: true, Warning: true,
			Details: "Large register offset(s): " + strings.Join(warnings, "; "),
		}
	}
	return VerifyResult{
		Check: "ADDR-002", Name: "Register Offset Bounds", Passed: true,
		Details: "All register offsets are within 64KB peripheral window",
	}
}

// checkPeripheralAddressRange warns (rather than failing) when register bases
// lie below 0x40000000 (e.g. RISC-V CLINT at 0x02000000) (HIGH-18).
func checkPeripheralAddressRange(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-003", Name: "Peripheral Address Range", Passed: true, Details: "No register blocks defined"}
	}

	const minTypicalMMIO uint64 = 0x40000000
	var warnings []string
	for _, name := range slices.Sorted(maps.Keys(hj.RegisterBlocks)) {
		block := hj.RegisterBlocks[name]
		addr, err := parseAddrLiteral(block.Base)
		if err != nil {
			continue
		}
		if addr < minTypicalMMIO {
			warnings = append(warnings, fmt.Sprintf("'%s' at %s (< 0x%08X typical MMIO base)", name, block.Base, minTypicalMMIO))
		}
	}

	if len(warnings) > 0 {
		return VerifyResult{
			Check: "ADDR-003", Name: "Peripheral Address Range", Passed: true, Warning: true,
			Details: "Register block(s) outside typical MMIO range: " + strings.Join(warnings, "; "),
		}
	}
	return VerifyResult{
		Check: "ADDR-003", Name: "Peripheral Address Range", Passed: true,
		Details: fmt.Sprintf("%d register blocks within MMIO range (>= 0x%08X)", len(hj.RegisterBlocks), minTypicalMMIO),
	}
}

func checkNoDuplicateBaseAddresses(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-004", Name: "No Duplicate Base Addresses", Passed: true, Details: "No register blocks defined"}
	}

	seen := make(map[uint64]string)
	var dupes []string
	for _, name := range slices.Sorted(maps.Keys(hj.RegisterBlocks)) {
		block := hj.RegisterBlocks[name]
		addr, err := parseAddrLiteral(block.Base)
		if err != nil {
			continue
		}
		if existing, ok := seen[addr]; ok {
			dupes = append(dupes, fmt.Sprintf("'%s' and '%s' share base %s", existing, name, block.Base))
		} else {
			seen[addr] = name
		}
	}

	if len(dupes) > 0 {
		return VerifyResult{
			Check: "ADDR-004", Name: "No Duplicate Base Addresses", Passed: false,
			Details: "Duplicate base(s): " + strings.Join(dupes, "; "),
		}
	}
	return VerifyResult{
		Check: "ADDR-004", Name: "No Duplicate Base Addresses", Passed: true,
		Details: fmt.Sprintf("%d register blocks, all unique base addresses", len(hj.RegisterBlocks)),
	}
}

func checkFlatRegisterDedup(hj *HardwareJson) VerifyResult {
	if len(hj.RegistersFlat) == 0 {
		return VerifyResult{Check: "ADDR-005", Name: "Flat Register Dedup", Passed: true, Details: "No flat registers defined"}
	}

	blockBases := make(map[uint64]string)
	for _, name := range slices.Sorted(maps.Keys(hj.RegisterBlocks)) {
		block := hj.RegisterBlocks[name]
		if addr, err := parseAddrLiteral(block.Base); err == nil {
			blockBases[addr] = name
		}
	}

	seenFlat := make(map[uint64]string, len(hj.RegistersFlat))
	var violations, warnings []string
	for _, flatName := range slices.Sorted(maps.Keys(hj.RegistersFlat)) {
		if !isCIdentifier(flatName) {
			violations = append(violations, fmt.Sprintf("flat '%s' is not a valid C identifier", flatName))
			continue
		}
		flatAddr := hj.RegistersFlat[flatName]
		addr, err := parseAddrLiteral(flatAddr)
		if err != nil {
			violations = append(violations, fmt.Sprintf("flat '%s' has invalid address '%s'", flatName, flatAddr))
			continue
		}
		if addr > math.MaxUint32 {
			violations = append(violations, fmt.Sprintf("flat '%s' (%s) exceeds 32-bit address space", flatName, flatAddr))
			continue
		}
		if blockName, ok := blockBases[addr]; ok {
			violations = append(violations, fmt.Sprintf("flat '%s' (%s) duplicates block '%s' base", flatName, flatAddr, blockName))
		}
		if prevFlat, ok := seenFlat[addr]; ok {
			warnings = append(warnings, fmt.Sprintf("flat '%s' and '%s' share address %s", prevFlat, flatName, flatAddr))
		} else {
			seenFlat[addr] = flatName
		}
		if addr%4 != 0 {
			warnings = append(warnings, fmt.Sprintf("flat '%s' at %s is not 4-byte aligned (e.g. Thumb/byte pointer)", flatName, flatAddr))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "ADDR-005", Name: "Flat Register Dedup", Passed: false,
			Details: "Flat register violation(s): " + strings.Join(violations, "; "),
		}
	}
	if len(warnings) > 0 {
		return VerifyResult{
			Check: "ADDR-005", Name: "Flat Register Dedup", Passed: true, Warning: true,
			Details: strings.Join(warnings, "; "),
		}
	}
	return VerifyResult{
		Check: "ADDR-005", Name: "Flat Register Dedup", Passed: true,
		Details: "No flat registers duplicate block base addresses",
	}
}

// === Flash Geometry Checks (FLASH-xxx) ===

func regionEffectiveSize(r FlashRegion) uint64 {
	if r.Size > 0 {
		return uint64(r.Size)
	}
	if r.SectorSize > 0 && r.Count > 0 {
		return uint64(r.SectorSize) * uint64(r.Count)
	}
	return 0
}

func regionDisplayName(r FlashRegion) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("region_0x%08x", r.Base)
}

// checkFlashRegionContinuity verifies flash regions are non-overlapping and fit
// within [windowBase, windowBase + flash.size], allowing Dual-Bank gaps (CRIT-20 / HIGH-53).
func checkFlashRegionContinuity(hj *HardwareJson) VerifyResult {
	if len(hj.Flash.Regions) == 0 {
		return VerifyResult{Check: "FLASH-001", Name: "Flash Region Continuity", Passed: true, Details: "No flash regions defined"}
	}

	physBase, _, err := resolveFlashBase(&hj.Flash)
	if err != nil {
		return VerifyResult{Check: "FLASH-001", Name: "Flash Region Continuity", Passed: false, Details: err.Error()}
	}
	if uint64(physBase)+uint64(hj.Flash.Size) > 0x100000000 {
		return VerifyResult{
			Check: "FLASH-001", Name: "Flash Region Continuity", Passed: false,
			Details: fmt.Sprintf("flash.base (0x%08X) + flash.size (0x%08X) exceeds 32-bit address space", physBase, hj.Flash.Size),
		}
	}

	type ri struct {
		name string
		base uint64
		size uint64
	}
	regions := make([]ri, 0, len(hj.Flash.Regions))
	var violations []string
	var totalCapacity uint64
	writableCount := 0
	for _, r := range hj.Flash.Regions {
		sz := regionEffectiveSize(r)
		if sz == 0 {
			violations = append(violations, fmt.Sprintf("'%s' has zero effective size", regionDisplayName(r)))
		}
		if isWritableRegion(r) {
			writableCount++
		}
		totalCapacity += sz
		regions = append(regions, ri{regionDisplayName(r), uint64(r.Base), sz})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].base < regions[j].base })

	maxEnd := regions[0].base + regions[0].size
	maxName := regions[0].name
	for i := 1; i < len(regions); i++ {
		if regions[i].base < maxEnd {
			violations = append(violations, fmt.Sprintf("'%s' overlaps '%s' at 0x%08X",
				regions[i].name, maxName, regions[i].base))
		}
		if end := regions[i].base + regions[i].size; end > maxEnd {
			maxEnd = end
			maxName = regions[i].name
		}
	}

	windowBase := uint64(physBase)
	windowEnd := windowBase + uint64(hj.Flash.Size)
	if totalCapacity > uint64(hj.Flash.Size) {
		violations = append(violations, fmt.Sprintf("regions total %d bytes exceeds flash.size %d", totalCapacity, hj.Flash.Size))
	}
	if regions[0].base >= windowEnd {
		violations = append(violations, fmt.Sprintf("first region '%s' starts at 0x%08X, outside [0x%08X..0x%X)",
			regions[0].name, regions[0].base, windowBase, windowEnd))
	}
	for _, r := range regions {
		end := r.base + r.size
		if r.base < windowBase || end > 0x100000000 || (writableCount < 2 && end > windowEnd) {
			violations = append(violations, fmt.Sprintf("'%s' [0x%08X..0x%X) exceeds flash window [0x%08X..0x%X)",
				r.name, r.base, end, windowBase, windowEnd))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "FLASH-001", Name: "Flash Region Continuity", Passed: false,
			Details: strings.Join(violations, "; "),
		}
	}
	return VerifyResult{
		Check: "FLASH-001", Name: "Flash Region Continuity", Passed: true,
		Details: fmt.Sprintf("%d regions, non-overlapping, within %d-byte flash capacity", len(regions), hj.Flash.Size),
	}
}

func checkFlashSectorArithmetic(hj *HardwareJson) VerifyResult {
	if len(hj.Flash.Regions) == 0 {
		return VerifyResult{Check: "FLASH-002", Name: "Flash Sector Arithmetic", Passed: true, Details: "No flash regions defined"}
	}

	var violations []string
	for _, r := range hj.Flash.Regions {
		if r.SectorSize == 0 && r.Count == 0 {
			continue
		}
		name := regionDisplayName(r)
		if r.SectorSize == 0 || r.Count == 0 {
			violations = append(violations, fmt.Sprintf("'%s': both sector_size (%d) and count (%d) must be non-zero",
				name, r.SectorSize, r.Count))
			continue
		}
		if !isPowerOfTwo(uint64(r.SectorSize)) {
			violations = append(violations, fmt.Sprintf("'%s': sector_size %d is not a power of 2", name, r.SectorSize))
		}
		computed := uint64(r.SectorSize) * uint64(r.Count)
		if computed > math.MaxUint32 {
			violations = append(violations, fmt.Sprintf("'%s': sector_size(%d) * count(%d) = %d overflows uint32",
				name, r.SectorSize, r.Count, computed))
			continue
		}
		if r.Size > 0 && uint64(r.Size) != computed {
			violations = append(violations, fmt.Sprintf("'%s': size %d != sector_size(%d) * count(%d) = %d",
				name, r.Size, r.SectorSize, r.Count, computed))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "FLASH-002", Name: "Flash Sector Arithmetic", Passed: false,
			Details: strings.Join(violations, "; "),
		}
	}
	return VerifyResult{
		Check: "FLASH-002", Name: "Flash Sector Arithmetic", Passed: true,
		Details: "All sectored regions have power-of-2 sector sizes and consistent arithmetic",
	}
}

// checkFlashSizeSanity downgrades non-power-of-two or >64MB flash sizes to WARNING (HIGH-18).
func checkFlashSizeSanity(hj *HardwareJson) VerifyResult {
	const minFlash uint32 = 64 * 1024
	const maxTypicalFlash uint32 = 64 * 1024 * 1024

	if hj.Flash.Size == 0 {
		return VerifyResult{
			Check: "FLASH-003", Name: "Flash Size Sanity", Passed: false,
			Details: "flash.size must be non-zero",
		}
	}
	if hj.Flash.Size < minFlash || hj.Flash.Size > maxTypicalFlash {
		return VerifyResult{
			Check: "FLASH-003", Name: "Flash Size Sanity", Passed: true, Warning: true,
			Details: fmt.Sprintf("flash.size = %d bytes outside typical [64KB..64MB] range", hj.Flash.Size),
		}
	}
	if !isPowerOfTwo(uint64(hj.Flash.Size)) {
		return VerifyResult{
			Check: "FLASH-003", Name: "Flash Size Sanity", Passed: true, Warning: true,
			Details: fmt.Sprintf("flash.size = %d bytes is not a power of 2", hj.Flash.Size),
		}
	}
	return VerifyResult{
		Check: "FLASH-003", Name: "Flash Size Sanity", Passed: true,
		Details: fmt.Sprintf("flash.size = %d bytes (%d KB), power-of-2", hj.Flash.Size, hj.Flash.Size/1024),
	}
}

// checkXipBaseAboveFlash allows xip_base == 0 (disabled) or == flash.base, and
// otherwise checks that a remapped XIP window fits 32-bit address space and does
// not partially alias physical flash (HIGH-18 / HIGH-46).
func checkXipBaseAboveFlash(hj *HardwareJson) VerifyResult {
	physBase32, _, fbErr := resolveFlashBase(&hj.Flash)
	if fbErr != nil {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: false,
			Details: fbErr.Error(),
		}
	}
	if hj.Flash.XipBase == "" {
		return VerifyResult{Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: true, Details: "No XIP base defined"}
	}

	xipBase, err := parseAddrLiteral(hj.Flash.XipBase)
	if err != nil {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: false,
			Details: fmt.Sprintf("Invalid xip_base '%s'", hj.Flash.XipBase),
		}
	}
	if xipBase == 0 {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: true,
			Details: "XIP base disabled (0x0); physical flash base addressing active",
		}
	}
	if xipBase > math.MaxUint32 || xipBase+uint64(hj.Flash.Size) > 0x100000000 {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: false,
			Details: fmt.Sprintf("xip_base 0x%X + flash.size 0x%X exceeds 32-bit address space", xipBase, hj.Flash.Size),
		}
	}

	physBase := uint64(physBase32)
	physEnd := physBase + uint64(hj.Flash.Size)
	xipEnd := xipBase + uint64(hj.Flash.Size)
	if physBase > 0 && xipBase == physBase {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: true,
			Details: fmt.Sprintf("Direct XIP mapping at physical flash.base 0x%08X", physBase),
		}
	}
	if xipBase < physEnd && physBase < xipEnd {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: false,
			Details: fmt.Sprintf("XIP window [0x%08X..0x%X) overlaps physical flash [0x%08X..0x%X)", xipBase, xipEnd, physBase, physEnd),
		}
	}
	return VerifyResult{
		Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: true,
		Details: fmt.Sprintf("XIP window [0x%X..0x%X) is disjoint from physical flash [0x%08X..0x%X)", xipBase, xipEnd, physBase, physEnd),
	}
}

// === Memory Layout Checks (MEM-xxx) ===

func checkIramSanity(hj *HardwareJson) VerifyResult {
	if hj.Memory.IramBase == "" && hj.Memory.IramSize == "" {
		return VerifyResult{Check: "MEM-001", Name: "IRAM Sanity", Passed: true, Details: "No IRAM defined"}
	}
	if hj.Memory.IramBase == "" || hj.Memory.IramSize == "" {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: "Both iram_base and iram_size must be specified together",
		}
	}

	base, err := parseAddrLiteral(hj.Memory.IramBase)
	if err != nil {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("Invalid iram_base '%s'", hj.Memory.IramBase),
		}
	}
	size, err := parseAddrLiteral(hj.Memory.IramSize)
	if err != nil {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("Invalid iram_size '%s': %v", hj.Memory.IramSize, err),
		}
	}

	const minIRAM uint64 = 4 * 1024
	const maxIRAM uint64 = 16 * 1024 * 1024

	if size < minIRAM || size > maxIRAM {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("iram_size 0x%X (%d KB) outside plausible range [4KB..16MB]", size, size/1024),
		}
	}
	if base%4 != 0 {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("iram_base 0x%X is not word-aligned", base),
		}
	}
	if base <= math.MaxUint32 && base+size > 0x100000000 {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("IRAM [0x%08X + 0x%X) exceeds 32-bit address space", base, size),
		}
	}
	if base > math.MaxUint32 && size > math.MaxUint64-base {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: "IRAM overflows 64-bit address space",
		}
	}
	if (hj.Memory.SramBase == "") != (hj.Memory.SramSize == "") {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: "Both sram_base and sram_size must be specified together",
		}
	}
	if hj.Memory.SramBase != "" {
		sBase, sErr1 := parseAddrLiteral(hj.Memory.SramBase)
		sSize, sErr2 := parseAddrLiteral(hj.Memory.SramSize)
		if sErr1 != nil || sErr2 != nil || sSize == 0 || sBase%4 != 0 ||
			(sBase <= math.MaxUint32 && sBase+sSize > 0x100000000) ||
			(sBase > math.MaxUint32 && sSize > math.MaxUint64-sBase) {
			return VerifyResult{
				Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
				Details: "Invalid or unaligned sram_base / sram_size",
			}
		}
	}
	if hj.CryptoCapabilities.ArenaSize != 0 && (hj.CryptoCapabilities.ArenaSize < 2048 || hj.CryptoCapabilities.ArenaSize%8 != 0) {
		return VerifyResult{
			Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("crypto_capabilities.arena_size (%d) must be >= 2048 and 8-byte aligned", hj.CryptoCapabilities.ArenaSize),
		}
	}
	return VerifyResult{
		Check: "MEM-001", Name: "IRAM Sanity", Passed: true,
		Details: fmt.Sprintf("IRAM at 0x%08X, %d KB", base, size/1024),
	}
}

func checkLpRAMNoOverlapIram(hj *HardwareJson) VerifyResult {
	if hj.Memory.LpRamBase == "" && hj.Memory.LpRamSize == "" {
		return VerifyResult{Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: true, Details: "No LP RAM defined"}
	}
	if hj.Memory.LpRamBase == "" || hj.Memory.LpRamSize == "" {
		return VerifyResult{
			Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
			Details: "Both lp_ram_base and lp_ram_size must be specified together",
		}
	}
	lpBase, err3 := parseAddrLiteral(hj.Memory.LpRamBase)
	lpSize, err4 := parseAddrLiteral(hj.Memory.LpRamSize)
	if err3 != nil || err4 != nil || lpSize == 0 || lpBase%4 != 0 || lpSize > math.MaxUint64-lpBase ||
		(lpBase <= math.MaxUint32 && lpBase+lpSize > 0x100000000) {
		return VerifyResult{
			Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
			Details: "LP RAM base/size must be word-aligned, non-zero, and within address space",
		}
	}
	if hj.Memory.IramBase == "" || hj.Memory.IramSize == "" {
		return VerifyResult{Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: true, Details: "No IRAM defined"}
	}

	iramBase, err1 := parseAddrLiteral(hj.Memory.IramBase)
	iramSize, err2 := parseAddrLiteral(hj.Memory.IramSize)
	for _, err := range []error{err1, err2} {
		if err != nil {
			return VerifyResult{
				Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
				Details: fmt.Sprintf("Address parse error: %v", err),
			}
		}
	}
	if iramSize == 0 || iramSize > math.MaxUint64-iramBase ||
		(iramBase <= math.MaxUint32 && iramBase+iramSize > 0x100000000) {
		return VerifyResult{
			Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
			Details: "IRAM base and size must be non-zero non-overflowing values",
		}
	}
	iramEnd := iramBase + iramSize
	lpEnd := lpBase + lpSize
	if lpBase < iramEnd && iramBase < lpEnd {
		return VerifyResult{
			Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
			Details: fmt.Sprintf("LP RAM [0x%08X..0x%08X) overlaps IRAM [0x%08X..0x%08X)",
				lpBase, lpEnd, iramBase, iramEnd),
		}
	}
	if hj.Memory.SramBase != "" && hj.Memory.SramSize != "" {
		if sramBase, errS1 := parseAddrLiteral(hj.Memory.SramBase); errS1 == nil {
			if sramSize, errS2 := parseAddrLiteral(hj.Memory.SramSize); errS2 == nil && sramSize <= math.MaxUint64-sramBase {
				sramEnd := sramBase + sramSize
				if lpBase < sramEnd && sramBase < lpEnd {
					return VerifyResult{
						Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
						Details: fmt.Sprintf("LP RAM [0x%08X..0x%08X) overlaps SRAM [0x%08X..0x%08X)",
							lpBase, lpEnd, sramBase, sramEnd),
					}
				}
			}
		}
	}
	return VerifyResult{
		Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: true,
		Details: fmt.Sprintf("LP RAM [0x%08X..0x%08X) and IRAM [0x%08X..0x%08X) are disjoint",
			lpBase, lpEnd, iramBase, iramEnd),
	}
}

func checkReservedRAMOverlaps(hj *HardwareJson) VerifyResult {
	if len(hj.ReservedRamRegions) == 0 {
		return VerifyResult{
			Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: true,
			Details: "No reserved RAM regions",
		}
	}

	type region struct {
		name string
		base uint64
		end  uint64
	}
	var regions []region
	for _, r := range hj.ReservedRamRegions {
		addr, err := parseAddrLiteral(r.Base)
		if err != nil || r.Size == 0 || uint64(r.Size) > math.MaxUint64-addr ||
			(addr <= math.MaxUint32 && addr+uint64(r.Size) > 0x100000000) {
			return VerifyResult{
				Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: false,
				Details: fmt.Sprintf("Invalid range for '%s' (base=%q size=%d)", r.Name, r.Base, r.Size),
			}
		}
		regions = append(regions, region{r.Name, addr, addr + uint64(r.Size)})
	}

	for i := range regions {
		for j := i + 1; j < len(regions); j++ {
			a, b := regions[i], regions[j]
			if a.base < b.end && b.base < a.end {
				return VerifyResult{
					Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: false,
					Details: fmt.Sprintf("'%s' [0x%08X..0x%08X) overlaps '%s' [0x%08X..0x%08X)",
						a.name, a.base, a.end, b.name, b.base, b.end),
				}
			}
		}
	}
	return VerifyResult{
		Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: true,
		Details: fmt.Sprintf("%d reserved RAM regions, no overlaps", len(regions)),
	}
}

// checkReservedRAMBounds validates reserved_ram_regions against the union of all
// declared RAM windows (iram, sram, lp_ram) (HIGH-18).
func checkReservedRAMBounds(hj *HardwareJson) VerifyResult {
	if len(hj.ReservedRamRegions) == 0 {
		return VerifyResult{
			Check: "MEM-004", Name: "Reserved RAM Within RAM Windows", Passed: true,
			Details: "No reserved RAM regions",
		}
	}

	type span struct{ start, end uint64 }
	var windows []span
	addWindow := func(label, rawBase, rawSize string) error {
		if rawBase == "" && rawSize == "" {
			return nil
		}
		if rawBase == "" || rawSize == "" {
			return fmt.Errorf("incomplete %s window", label)
		}
		b, err1 := parseAddrLiteral(rawBase)
		sz, err2 := parseAddrLiteral(rawSize)
		if err1 != nil || err2 != nil || sz == 0 || sz > math.MaxUint64-b ||
			(b <= math.MaxUint32 && b+sz > 0x100000000) {
			return fmt.Errorf("invalid %s base/size", label)
		}
		windows = append(windows, span{b, b + sz})
		return nil
	}
	for _, w := range []struct{ label, base, size string }{
		{"IRAM", hj.Memory.IramBase, hj.Memory.IramSize},
		{"SRAM", hj.Memory.SramBase, hj.Memory.SramSize},
		{"LP RAM", hj.Memory.LpRamBase, hj.Memory.LpRamSize},
	} {
		if err := addWindow(w.label, w.base, w.size); err != nil {
			return VerifyResult{
				Check: "MEM-004", Name: "Reserved RAM Within RAM Windows", Passed: false,
				Details: err.Error(),
			}
		}
	}
	if len(windows) == 0 {
		return VerifyResult{
			Check: "MEM-004", Name: "Reserved RAM Within RAM Windows", Passed: true,
			Details: "No RAM windows defined, skipping bounds check",
		}
	}

	sort.Slice(windows, func(i, j int) bool { return windows[i].start < windows[j].start })
	merged := []span{windows[0]}
	for _, w := range windows[1:] {
		last := &merged[len(merged)-1]
		if w.start <= last.end {
			last.end = max(last.end, w.end)
		} else {
			merged = append(merged, w)
		}
	}

	var violations []string
	for _, r := range hj.ReservedRamRegions {
		addr, err := parseAddrLiteral(r.Base)
		if err != nil || r.Size == 0 || uint64(r.Size) > math.MaxUint64-addr {
			violations = append(violations, fmt.Sprintf("'%s': invalid base/size", r.Name))
			continue
		}
		rEnd := addr + uint64(r.Size)
		inside := false
		for _, w := range merged {
			if addr >= w.start && rEnd <= w.end {
				inside = true
				break
			}
		}
		if !inside {
			violations = append(violations, fmt.Sprintf("'%s' [0x%08X..0x%08X) outside declared RAM windows",
				r.Name, addr, rEnd))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "MEM-004", Name: "Reserved RAM Within RAM Windows", Passed: false,
			Details: strings.Join(violations, "; "),
		}
	}
	return VerifyResult{
		Check: "MEM-004", Name: "Reserved RAM Within RAM Windows", Passed: true,
		Details: fmt.Sprintf("All %d reserved regions within declared RAM windows", len(hj.ReservedRamRegions)),
	}
}

// === Reset Cause Checks (RST-xxx) ===

func checkResetCodeUniqueness(hj *HardwareJson) VerifyResult {
	if hj.ResetCauses == nil || len(hj.ResetCauses.Codes) == 0 {
		return VerifyResult{Check: "RST-001", Name: "Reset Code Uniqueness", Passed: true, Details: "No reset causes defined"}
	}

	seen := make(map[[2]uint32]string, len(hj.ResetCauses.Codes))
	var dupes []string
	for _, code := range hj.ResetCauses.Codes {
		key := [2]uint32{uint32(code.Value), uint32(code.Mask)}
		if existing, ok := seen[key]; ok {
			dupes = append(dupes, fmt.Sprintf("value 0x%X (mask 0x%X): '%s' and '%s'",
				key[0], key[1], existing, code.Name))
		} else {
			seen[key] = code.Name
		}
	}

	if len(dupes) > 0 {
		return VerifyResult{
			Check: "RST-001", Name: "Reset Code Uniqueness", Passed: false,
			Details: "Duplicate reset cause value(s): " + strings.Join(dupes, "; "),
		}
	}
	return VerifyResult{
		Check: "RST-001", Name: "Reset Code Uniqueness", Passed: true,
		Details: fmt.Sprintf("%d reset codes, all unique", len(hj.ResetCauses.Codes)),
	}
}

// checkResetCodeFitsMask verifies every 32-bit reset code fits its per-code
// mask and (when specified) the global register mask (CRIT-21).
func checkResetCodeFitsMask(hj *HardwareJson) VerifyResult {
	if hj.ResetCauses == nil || len(hj.ResetCauses.Codes) == 0 {
		return VerifyResult{Check: "RST-002", Name: "Reset Code Fits Mask", Passed: true, Details: "No reset causes defined"}
	}

	var globalMask uint64
	hasGlobalMask := hj.ResetCauses.Mask != ""
	if hasGlobalMask {
		var err error
		globalMask, err = parseAddrLiteral(hj.ResetCauses.Mask)
		if err != nil || globalMask == 0 || globalMask > math.MaxUint32 {
			return VerifyResult{
				Check: "RST-002", Name: "Reset Code Fits Mask", Passed: false,
				Details: fmt.Sprintf("Invalid 32-bit mask '%s'", hj.ResetCauses.Mask),
			}
		}
	}

	var violations []string
	for _, code := range hj.ResetCauses.Codes {
		val, codeMask := uint64(code.Value), uint64(code.Mask)
		if codeMask != 0 && (val & ^codeMask) != 0 {
			violations = append(violations, fmt.Sprintf("'%s' (value 0x%X) has bits outside its mask 0x%X",
				code.Name, val, codeMask))
			continue
		}
		if hasGlobalMask {
			checkBits := val
			if codeMask != 0 {
				checkBits = codeMask
			}
			if checkBits & ^globalMask != 0 {
				violations = append(violations, fmt.Sprintf("'%s' (0x%X) exceeds register mask 0x%X",
					code.Name, checkBits, globalMask))
			}
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "RST-002", Name: "Reset Code Fits Mask", Passed: false,
			Details: strings.Join(violations, "; "),
		}
	}
	if hasGlobalMask {
		return VerifyResult{
			Check: "RST-002", Name: "Reset Code Fits Mask", Passed: true,
			Details: fmt.Sprintf("%d codes fit within %d-bit mask (0x%X)",
				len(hj.ResetCauses.Codes), bits.Len64(globalMask), globalMask),
		}
	}
	return VerifyResult{
		Check: "RST-002", Name: "Reset Code Fits Mask", Passed: true,
		Details: fmt.Sprintf("%d 32-bit reset codes validated", len(hj.ResetCauses.Codes)),
	}
}

func checkResetClassVocabulary(hj *HardwareJson) VerifyResult {
	if hj.ResetCauses == nil || len(hj.ResetCauses.Codes) == 0 {
		return VerifyResult{Check: "RST-003", Name: "Reset Class Vocabulary", Passed: true, Details: "No reset causes defined"}
	}

	var invalid []string
	for _, code := range hj.ResetCauses.Codes {
		if !allowedResetClasses[code.Class] {
			invalid = append(invalid, fmt.Sprintf("'%s' has class '%s'", code.Name, code.Class))
		}
	}

	if len(invalid) > 0 {
		return VerifyResult{
			Check: "RST-003", Name: "Reset Class Vocabulary", Passed: false,
			Details: fmt.Sprintf("Unrecognized class(es): %s. Allowed: [power, intentional, crash]",
				strings.Join(invalid, "; ")),
		}
	}
	return VerifyResult{
		Check: "RST-003", Name: "Reset Class Vocabulary", Passed: true,
		Details: fmt.Sprintf("%d reset codes use recognized classes", len(hj.ResetCauses.Codes)),
	}
}

// === Constant Checks (CONST-xxx) ===

func checkHexConstantWidth(hj *HardwareJson) VerifyResult {
	var violations []string
	hexCount := 0
	for _, name := range slices.Sorted(maps.Keys(hj.Constants)) {
		if !isCIdentifier(name) {
			violations = append(violations, fmt.Sprintf("'%s': invalid C identifier", name))
			continue
		}
		val := hj.Constants[name]
		parsed, err := parseConstantUint32(val)
		if err != nil {
			violations = append(violations, fmt.Sprintf("'%s': %v", name, err))
			continue
		}
		if str, ok := val.(string); ok && (strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X")) {
			hexCount++
		}
		if strings.EqualFold(name, "flash_erased_byte") && parsed != 0xFF {
			violations = append(violations, fmt.Sprintf("'%s' = 0x%X is unsupported (must be 0xFF)", name, parsed))
		}
	}
	for _, regName := range slices.Sorted(maps.Keys(hj.Registers)) {
		if !isCIdentifier(regName) {
			violations = append(violations, fmt.Sprintf("registers['%s']: invalid C identifier", regName))
			continue
		}
		if _, err := parseConstantUint32(hj.Registers[regName]); err != nil {
			violations = append(violations, fmt.Sprintf("registers['%s']: %v", regName, err))
		}
	}
	if hj.BootromImage != nil {
		mode := strings.ToLower(strings.TrimSpace(hj.Flash.Stage0ExecMode))
		if err := validateRawBootromSpec(hj.BootromImage, mode); err != nil {
			violations = append(violations, fmt.Sprintf("bootrom_image: %v", err))
		}
	}
	if hj.MultiCore != nil {
		for i, cp := range hj.MultiCore.Coprocessors {
			if err := ValidateName("coprocessor", cp.Name); err != nil {
				violations = append(violations, fmt.Sprintf("multi_core.coprocessors[%d]: %v", i, err))
			}
			if cp.AppAlignmentBytes != nil && !isPowerOfTwo(uint64(*cp.AppAlignmentBytes)) {
				violations = append(violations, fmt.Sprintf("multi_core.coprocessors[%d].app_alignment_bytes (%d) not power of 2", i, *cp.AppAlignmentBytes))
			}
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "CONST-001", Name: "Hex Constant Width", Passed: false,
			Details: strings.Join(violations, "; "),
		}
	}
	if len(hj.Constants) == 0 {
		return VerifyResult{Check: "CONST-001", Name: "Hex Constant Width", Passed: true, Details: "No constants defined"}
	}
	return VerifyResult{
		Check: "CONST-001", Name: "Hex Constant Width", Passed: true,
		Details: fmt.Sprintf("%d hex constants, all fit 32-bit register width", hexCount),
	}
}
