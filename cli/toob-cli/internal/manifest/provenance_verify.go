package manifest

import (
	"fmt"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"time"
)

// VerifyResult captures the outcome of a single plausibility check.
type VerifyResult struct {
	Check   string // Check ID, e.g. "ADDR-001"
	Name    string // Human-readable check name
	Passed  bool
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
		checkLpRamNoOverlapIram,
		checkReservedRamOverlaps,
		checkReservedRamBounds,
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

func parseHexAddr(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, fmt.Errorf("empty hex string")
	}
	return strconv.ParseUint(s, 16, 64)
}

func isPowerOfTwo(n uint64) bool {
	return n > 0 && bits.OnesCount64(n) == 1
}

// collectAllProvenance gathers provenance annotations from all auditable elements.
// Mirrors the collection logic in AuditProvenance but preserves nil provenance pointers
// for completeness checking.
func collectAllProvenance(hj *HardwareJson) []provenanceRef {
	var refs []provenanceRef

	// Top-level / Flash geometry (use top-level, fall back to flash-level)
	p := hj.Provenance
	if p == nil {
		p = hj.Flash.Provenance
	}
	refs = append(refs, provenanceRef{"Flash Geometry", hj.ChipFamily + "_flash", p})

	for _, reg := range hj.Flash.Regions {
		name := reg.Name
		if name == "" {
			name = fmt.Sprintf("region_0x%08x", reg.Base)
		}
		refs = append(refs, provenanceRef{"Flash Region", name, reg.Provenance})
	}

	for _, ram := range hj.ReservedRamRegions {
		refs = append(refs, provenanceRef{"Reserved RAM", ram.Name, ram.Provenance})
	}

	for name, block := range hj.RegisterBlocks {
		refs = append(refs, provenanceRef{"Register Block", name, block.Provenance})
	}

	if hj.ResetCauses != nil {
		for _, code := range hj.ResetCauses.Codes {
			refs = append(refs, provenanceRef{"Reset Cause", code.Name, code.Provenance})
		}
	}

	return refs
}

// === Provenance Annotation Checks (PROV-xxx) ===

// checkSourceAllowList verifies all provenance sources are from the recognized vocabulary.
func checkSourceAllowList(hj *HardwareJson) VerifyResult {
	refs := collectAllProvenance(hj)
	var invalid []string
	for _, ref := range refs {
		if ref.prov != nil && ref.prov.Source != "" && !allowedSources[ref.prov.Source] {
			invalid = append(invalid, fmt.Sprintf("%s '%s' (source: '%s')", ref.category, ref.name, ref.prov.Source))
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
			Details: fmt.Sprintf("Unrecognized source(s): %s. Allowed: [%s]",
				strings.Join(invalid, "; "), strings.Join(allowed, ", ")),
		}
	}
	return VerifyResult{
		Check: "PROV-001", Name: "Source Allow-List", Passed: true,
		Details: fmt.Sprintf("All %d provenance annotations use recognized sources", len(refs)),
	}
}

// checkVerifiedDateFormat ensures all verification dates are ISO-8601 and not in the future.
func checkVerifiedDateFormat(hj *HardwareJson) VerifyResult {
	refs := collectAllProvenance(hj)
	now := time.Now()
	var invalid []string

	for _, ref := range refs {
		if ref.prov == nil || ref.prov.Verified == "" {
			continue // Missing provenance handled by PROV-003
		}
		parsed, err := time.Parse("2006-01-02", ref.prov.Verified)
		if err != nil {
			invalid = append(invalid, fmt.Sprintf("%s '%s': '%s' is not YYYY-MM-DD", ref.category, ref.name, ref.prov.Verified))
			continue
		}
		if parsed.After(now) {
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

// checkProvenanceCoverage ensures every auditable element has a provenance annotation.
func checkProvenanceCoverage(hj *HardwareJson) VerifyResult {
	refs := collectAllProvenance(hj)
	var missing []string
	for _, ref := range refs {
		if ref.prov == nil {
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

// checkRegisterBaseAlignment verifies all register block base addresses are 4-byte aligned.
func checkRegisterBaseAlignment(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-001", Name: "Register Base Alignment", Passed: true, Details: "No register blocks defined"}
	}

	var violations []string
	for name, block := range hj.RegisterBlocks {
		addr, err := parseHexAddr(block.Base)
		if err != nil {
			violations = append(violations, fmt.Sprintf("'%s': invalid address '%s'", name, block.Base))
			continue
		}
		if addr%4 != 0 {
			violations = append(violations, fmt.Sprintf("'%s' at %s (not 4-byte aligned)", name, block.Base))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "ADDR-001", Name: "Register Base Alignment", Passed: false,
			Details: fmt.Sprintf("Unaligned register base(s): %s", strings.Join(violations, "; ")),
		}
	}
	return VerifyResult{
		Check: "ADDR-001", Name: "Register Base Alignment", Passed: true,
		Details: fmt.Sprintf("%d register blocks, all 4-byte aligned", len(hj.RegisterBlocks)),
	}
}

// checkRegisterOffsetBounds verifies all register offsets are within a 64 KB peripheral window.
func checkRegisterOffsetBounds(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-002", Name: "Register Offset Bounds", Passed: true, Details: "No register blocks defined"}
	}

	const maxOffset uint64 = 0x10000 // 64 KB — typical peripheral register space upper bound
	var violations []string
	for blockName, block := range hj.RegisterBlocks {
		for regName, offsetStr := range block.Regs {
			offset, err := parseHexAddr(offsetStr)
			if err != nil {
				violations = append(violations, fmt.Sprintf("'%s.%s': invalid offset '%s'", blockName, regName, offsetStr))
				continue
			}
			if offset >= maxOffset {
				violations = append(violations, fmt.Sprintf("'%s.%s' offset %s >= 64KB", blockName, regName, offsetStr))
			}
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "ADDR-002", Name: "Register Offset Bounds", Passed: false,
			Details: fmt.Sprintf("Oversized register offset(s): %s", strings.Join(violations, "; ")),
		}
	}
	return VerifyResult{
		Check: "ADDR-002", Name: "Register Offset Bounds", Passed: true,
		Details: "All register offsets are within 64KB peripheral window",
	}
}

// checkPeripheralAddressRange verifies register bases are in MMIO space (>= 0x40000000),
// not in Flash/ROM/SRAM regions. Valid for all 32-bit MCU families (ARM, RISC-V, Xtensa).
func checkPeripheralAddressRange(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-003", Name: "Peripheral Address Range", Passed: true, Details: "No register blocks defined"}
	}

	const minMMIO uint64 = 0x40000000
	var violations []string
	for name, block := range hj.RegisterBlocks {
		addr, err := parseHexAddr(block.Base)
		if err != nil {
			continue // Caught by ADDR-001
		}
		if addr < minMMIO {
			violations = append(violations, fmt.Sprintf("'%s' at %s (below MMIO threshold 0x%08X)", name, block.Base, minMMIO))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{
			Check: "ADDR-003", Name: "Peripheral Address Range", Passed: false,
			Details: fmt.Sprintf("Register block(s) in non-MMIO range: %s", strings.Join(violations, "; ")),
		}
	}
	return VerifyResult{
		Check: "ADDR-003", Name: "Peripheral Address Range", Passed: true,
		Details: fmt.Sprintf("%d register blocks within MMIO range (>= 0x%08X)", len(hj.RegisterBlocks), minMMIO),
	}
}

// checkNoDuplicateBaseAddresses catches copy-paste errors where two blocks share a base.
func checkNoDuplicateBaseAddresses(hj *HardwareJson) VerifyResult {
	if len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-004", Name: "No Duplicate Base Addresses", Passed: true, Details: "No register blocks defined"}
	}

	seen := make(map[uint64]string)
	var dupes []string
	for name, block := range hj.RegisterBlocks {
		addr, err := parseHexAddr(block.Base)
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
			Details: fmt.Sprintf("Duplicate base(s): %s", strings.Join(dupes, "; ")),
		}
	}
	return VerifyResult{
		Check: "ADDR-004", Name: "No Duplicate Base Addresses", Passed: true,
		Details: fmt.Sprintf("%d register blocks, all unique base addresses", len(hj.RegisterBlocks)),
	}
}

// checkFlatRegisterDedup ensures no flat register duplicates a register block base address.
func checkFlatRegisterDedup(hj *HardwareJson) VerifyResult {
	if len(hj.RegistersFlat) == 0 || len(hj.RegisterBlocks) == 0 {
		return VerifyResult{Check: "ADDR-005", Name: "Flat Register Dedup", Passed: true, Details: "No cross-reference needed"}
	}

	blockBases := make(map[uint64]string)
	for name, block := range hj.RegisterBlocks {
		if addr, err := parseHexAddr(block.Base); err == nil {
			blockBases[addr] = name
		}
	}

	var dupes []string
	for flatName, flatAddr := range hj.RegistersFlat {
		if addr, err := parseHexAddr(flatAddr); err == nil {
			if blockName, ok := blockBases[addr]; ok {
				dupes = append(dupes, fmt.Sprintf("flat '%s' (%s) duplicates block '%s' base", flatName, flatAddr, blockName))
			}
		}
	}

	if len(dupes) > 0 {
		return VerifyResult{
			Check: "ADDR-005", Name: "Flat Register Dedup", Passed: false,
			Details: fmt.Sprintf("Redundant flat register(s): %s", strings.Join(dupes, "; ")),
		}
	}
	return VerifyResult{
		Check: "ADDR-005", Name: "Flat Register Dedup", Passed: true,
		Details: "No flat registers duplicate block base addresses",
	}
}

// === Flash Geometry Checks (FLASH-xxx) ===

// regionEffectiveSize returns the effective byte size of a flash region,
// computed from explicit Size or SectorSize * Count.
func regionEffectiveSize(r FlashRegion) uint32 {
	if r.Size > 0 {
		return r.Size
	}
	if r.SectorSize > 0 && r.Count > 0 {
		return r.SectorSize * r.Count
	}
	return 0
}

func regionDisplayName(r FlashRegion) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("region_0x%08x", r.Base)
}

// checkFlashRegionContinuity verifies flash regions are non-overlapping and fit within flash.size.
func checkFlashRegionContinuity(hj *HardwareJson) VerifyResult {
	if len(hj.Flash.Regions) == 0 {
		return VerifyResult{Check: "FLASH-001", Name: "Flash Region Continuity", Passed: true, Details: "No flash regions defined"}
	}

	type ri struct {
		name string
		base uint32
		size uint32
	}
	regions := make([]ri, 0, len(hj.Flash.Regions))
	for _, r := range hj.Flash.Regions {
		regions = append(regions, ri{regionDisplayName(r), r.Base, regionEffectiveSize(r)})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].base < regions[j].base })

	var violations []string

	// Overlap check (sequential after sort)
	for i := 1; i < len(regions); i++ {
		prevEnd := regions[i-1].base + regions[i-1].size
		if regions[i].base < prevEnd {
			violations = append(violations, fmt.Sprintf("'%s' overlaps '%s' at 0x%08X",
				regions[i].name, regions[i-1].name, regions[i].base))
		}
	}

	// Bounds check
	for _, r := range regions {
		end := r.base + r.size
		if end > hj.Flash.Size {
			violations = append(violations, fmt.Sprintf("'%s' [0x%08X..0x%08X) exceeds flash size 0x%08X",
				r.name, r.base, end, hj.Flash.Size))
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
		Details: fmt.Sprintf("%d regions, non-overlapping, within %d-byte flash", len(regions), hj.Flash.Size),
	}
}

// checkFlashSectorArithmetic verifies sector_size is power-of-2 and size == sector_size * count.
func checkFlashSectorArithmetic(hj *HardwareJson) VerifyResult {
	if len(hj.Flash.Regions) == 0 {
		return VerifyResult{Check: "FLASH-002", Name: "Flash Sector Arithmetic", Passed: true, Details: "No flash regions defined"}
	}

	var violations []string
	for _, r := range hj.Flash.Regions {
		if r.SectorSize == 0 || r.Count == 0 {
			continue // Not a sectored region
		}
		name := regionDisplayName(r)
		if !isPowerOfTwo(uint64(r.SectorSize)) {
			violations = append(violations, fmt.Sprintf("'%s': sector_size %d is not a power of 2", name, r.SectorSize))
		}
		computed := r.SectorSize * r.Count
		if r.Size > 0 && r.Size != computed {
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

// checkFlashSizeSanity verifies flash.size is a power-of-2 within [64KB, 64MB].
func checkFlashSizeSanity(hj *HardwareJson) VerifyResult {
	const minFlash uint32 = 64 * 1024       // 64 KB
	const maxFlash uint32 = 64 * 1024 * 1024 // 64 MB

	if hj.Flash.Size < minFlash || hj.Flash.Size > maxFlash {
		return VerifyResult{
			Check: "FLASH-003", Name: "Flash Size Sanity", Passed: false,
			Details: fmt.Sprintf("flash.size = %d bytes; expected [%d..%d]", hj.Flash.Size, minFlash, maxFlash),
		}
	}
	if !isPowerOfTwo(uint64(hj.Flash.Size)) {
		return VerifyResult{
			Check: "FLASH-003", Name: "Flash Size Sanity", Passed: false,
			Details: fmt.Sprintf("flash.size = %d bytes is not a power of 2", hj.Flash.Size),
		}
	}
	return VerifyResult{
		Check: "FLASH-003", Name: "Flash Size Sanity", Passed: true,
		Details: fmt.Sprintf("flash.size = %d bytes (%d KB), power-of-2", hj.Flash.Size, hj.Flash.Size/1024),
	}
}

// checkXipBaseAboveFlash verifies the XIP base address is above physical flash.
func checkXipBaseAboveFlash(hj *HardwareJson) VerifyResult {
	if hj.Flash.XipBase == "" {
		return VerifyResult{Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: true, Details: "No XIP base defined"}
	}

	xipBase, err := parseHexAddr(hj.Flash.XipBase)
	if err != nil {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: false,
			Details: fmt.Sprintf("Invalid xip_base '%s': %v", hj.Flash.XipBase, err),
		}
	}

	flashEnd := uint64(hj.Flash.Size)
	if xipBase < flashEnd {
		return VerifyResult{
			Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: false,
			Details: fmt.Sprintf("xip_base 0x%08X is within physical flash [0x0..0x%08X)", xipBase, flashEnd),
		}
	}
	return VerifyResult{
		Check: "FLASH-004", Name: "XIP Base Above Flash", Passed: true,
		Details: fmt.Sprintf("XIP base 0x%08X is above physical flash end (0x%08X)", xipBase, flashEnd),
	}
}

// === Memory Layout Checks (MEM-xxx) ===

// checkIramSanity verifies IRAM size is within [4KB, 16MB] and base is word-aligned.
func checkIramSanity(hj *HardwareJson) VerifyResult {
	if hj.Memory.IramBase == "" || hj.Memory.IramSize == "" {
		return VerifyResult{Check: "MEM-001", Name: "IRAM Sanity", Passed: true, Details: "No IRAM defined"}
	}

	base, err := parseHexAddr(hj.Memory.IramBase)
	if err != nil {
		return VerifyResult{Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("Invalid iram_base '%s': %v", hj.Memory.IramBase, err)}
	}
	size, err := parseHexAddr(hj.Memory.IramSize)
	if err != nil {
		return VerifyResult{Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("Invalid iram_size '%s': %v", hj.Memory.IramSize, err)}
	}

	const minIRAM uint64 = 4 * 1024         // 4 KB
	const maxIRAM uint64 = 16 * 1024 * 1024 // 16 MB

	if size < minIRAM || size > maxIRAM {
		return VerifyResult{Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("iram_size 0x%X (%d KB) outside plausible range [4KB..16MB]", size, size/1024)}
	}
	if base%4 != 0 {
		return VerifyResult{Check: "MEM-001", Name: "IRAM Sanity", Passed: false,
			Details: fmt.Sprintf("iram_base 0x%X is not word-aligned", base)}
	}
	return VerifyResult{Check: "MEM-001", Name: "IRAM Sanity", Passed: true,
		Details: fmt.Sprintf("IRAM at 0x%08X, %d KB", base, size/1024)}
}

// checkLpRamNoOverlapIram verifies LP RAM and IRAM address ranges are disjoint.
func checkLpRamNoOverlapIram(hj *HardwareJson) VerifyResult {
	if hj.Memory.LpRamBase == "" || hj.Memory.LpRamSize == "" {
		return VerifyResult{Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: true, Details: "No LP RAM defined"}
	}
	if hj.Memory.IramBase == "" || hj.Memory.IramSize == "" {
		return VerifyResult{Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: true, Details: "No IRAM defined"}
	}

	iramBase, err1 := parseHexAddr(hj.Memory.IramBase)
	iramSize, err2 := parseHexAddr(hj.Memory.IramSize)
	lpBase, err3 := parseHexAddr(hj.Memory.LpRamBase)
	lpSize, err4 := parseHexAddr(hj.Memory.LpRamSize)
	for _, err := range []error{err1, err2, err3, err4} {
		if err != nil {
			return VerifyResult{Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
				Details: fmt.Sprintf("Address parse error: %v", err)}
		}
	}

	iramEnd := iramBase + iramSize
	lpEnd := lpBase + lpSize
	if lpBase < iramEnd && iramBase < lpEnd {
		return VerifyResult{Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: false,
			Details: fmt.Sprintf("LP RAM [0x%08X..0x%08X) overlaps IRAM [0x%08X..0x%08X)",
				lpBase, lpEnd, iramBase, iramEnd)}
	}
	return VerifyResult{Check: "MEM-002", Name: "LP RAM No Overlap IRAM", Passed: true,
		Details: fmt.Sprintf("LP RAM [0x%08X..0x%08X) and IRAM [0x%08X..0x%08X) are disjoint",
			lpBase, lpEnd, iramBase, iramEnd)}
}

// checkReservedRamOverlaps verifies no two reserved RAM regions overlap (migrated from generator.go).
func checkReservedRamOverlaps(hj *HardwareJson) VerifyResult {
	if len(hj.ReservedRamRegions) < 2 {
		return VerifyResult{Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: true,
			Details: "Fewer than 2 reserved RAM regions"}
	}

	type region struct {
		name string
		base uint64
		size uint32
	}
	var regions []region
	for _, r := range hj.ReservedRamRegions {
		addr, err := parseHexAddr(r.Base)
		if err != nil {
			return VerifyResult{Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: false,
				Details: fmt.Sprintf("Invalid base for '%s': %v", r.Name, err)}
		}
		regions = append(regions, region{r.Name, addr, r.Size})
	}

	for i := 0; i < len(regions); i++ {
		for j := i + 1; j < len(regions); j++ {
			a, b := regions[i], regions[j]
			if a.base < b.base+uint64(b.size) && b.base < a.base+uint64(a.size) {
				return VerifyResult{Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: false,
					Details: fmt.Sprintf("'%s' [0x%08X..0x%08X) overlaps '%s' [0x%08X..0x%08X)",
						a.name, a.base, a.base+uint64(a.size),
						b.name, b.base, b.base+uint64(b.size))}
			}
		}
	}
	return VerifyResult{Check: "MEM-003", Name: "Reserved RAM No Overlaps", Passed: true,
		Details: fmt.Sprintf("%d reserved RAM regions, no overlaps", len(regions))}
}

// checkReservedRamBounds verifies all reserved RAM regions are within LP RAM (migrated from generator.go).
func checkReservedRamBounds(hj *HardwareJson) VerifyResult {
	if len(hj.ReservedRamRegions) == 0 {
		return VerifyResult{Check: "MEM-004", Name: "Reserved RAM Within LP RAM", Passed: true,
			Details: "No reserved RAM regions"}
	}
	if hj.Memory.LpRamBase == "" || hj.Memory.LpRamSize == "" {
		return VerifyResult{Check: "MEM-004", Name: "Reserved RAM Within LP RAM", Passed: true,
			Details: "No LP RAM defined, skipping bounds check"}
	}

	lpBase, err1 := parseHexAddr(hj.Memory.LpRamBase)
	lpSize, err2 := parseHexAddr(hj.Memory.LpRamSize)
	if err1 != nil || err2 != nil {
		return VerifyResult{Check: "MEM-004", Name: "Reserved RAM Within LP RAM", Passed: false,
			Details: "Cannot parse LP RAM base/size"}
	}
	lpEnd := lpBase + lpSize

	var violations []string
	for _, r := range hj.ReservedRamRegions {
		addr, err := parseHexAddr(r.Base)
		if err != nil {
			violations = append(violations, fmt.Sprintf("'%s': invalid base", r.Name))
			continue
		}
		regionEnd := addr + uint64(r.Size)
		if addr < lpBase || regionEnd > lpEnd {
			violations = append(violations, fmt.Sprintf("'%s' [0x%08X..0x%08X) outside LP RAM [0x%08X..0x%08X)",
				r.Name, addr, regionEnd, lpBase, lpEnd))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{Check: "MEM-004", Name: "Reserved RAM Within LP RAM", Passed: false,
			Details: strings.Join(violations, "; ")}
	}
	return VerifyResult{Check: "MEM-004", Name: "Reserved RAM Within LP RAM", Passed: true,
		Details: fmt.Sprintf("All %d reserved regions within LP RAM [0x%08X..0x%08X)",
			len(hj.ReservedRamRegions), lpBase, lpEnd)}
}

// === Reset Cause Checks (RST-xxx) ===

// checkResetCodeUniqueness verifies all reset cause values are unique.
func checkResetCodeUniqueness(hj *HardwareJson) VerifyResult {
	if hj.ResetCauses == nil || len(hj.ResetCauses.Codes) == 0 {
		return VerifyResult{Check: "RST-001", Name: "Reset Code Uniqueness", Passed: true, Details: "No reset causes defined"}
	}

	seen := make(map[int]string)
	var dupes []string
	for _, code := range hj.ResetCauses.Codes {
		if existing, ok := seen[code.Value]; ok {
			dupes = append(dupes, fmt.Sprintf("value %d: '%s' and '%s'", code.Value, existing, code.Name))
		} else {
			seen[code.Value] = code.Name
		}
	}

	if len(dupes) > 0 {
		return VerifyResult{Check: "RST-001", Name: "Reset Code Uniqueness", Passed: false,
			Details: fmt.Sprintf("Duplicate reset cause value(s): %s", strings.Join(dupes, "; "))}
	}
	return VerifyResult{Check: "RST-001", Name: "Reset Code Uniqueness", Passed: true,
		Details: fmt.Sprintf("%d reset codes, all unique", len(hj.ResetCauses.Codes))}
}

// checkResetCodeFitsMask verifies every reset code value fits within the declared register mask.
func checkResetCodeFitsMask(hj *HardwareJson) VerifyResult {
	if hj.ResetCauses == nil || len(hj.ResetCauses.Codes) == 0 {
		return VerifyResult{Check: "RST-002", Name: "Reset Code Fits Mask", Passed: true, Details: "No reset causes defined"}
	}

	mask, err := parseHexAddr(hj.ResetCauses.Mask)
	if err != nil {
		return VerifyResult{Check: "RST-002", Name: "Reset Code Fits Mask", Passed: false,
			Details: fmt.Sprintf("Invalid mask '%s': %v", hj.ResetCauses.Mask, err)}
	}

	var violations []string
	for _, code := range hj.ResetCauses.Codes {
		if uint64(code.Value) & ^mask != 0 {
			violations = append(violations, fmt.Sprintf("'%s' (value %d / 0x%X) exceeds mask 0x%X",
				code.Name, code.Value, code.Value, mask))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{Check: "RST-002", Name: "Reset Code Fits Mask", Passed: false,
			Details: strings.Join(violations, "; ")}
	}
	return VerifyResult{Check: "RST-002", Name: "Reset Code Fits Mask", Passed: true,
		Details: fmt.Sprintf("%d codes fit within %d-bit mask (0x%X)",
			len(hj.ResetCauses.Codes), bits.Len64(mask), mask)}
}

// checkResetClassVocabulary verifies all reset cause class names are recognized.
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
		return VerifyResult{Check: "RST-003", Name: "Reset Class Vocabulary", Passed: false,
			Details: fmt.Sprintf("Unrecognized class(es): %s. Allowed: [power, intentional, crash]",
				strings.Join(invalid, "; "))}
	}
	return VerifyResult{Check: "RST-003", Name: "Reset Class Vocabulary", Passed: true,
		Details: fmt.Sprintf("%d reset codes use recognized classes", len(hj.ResetCauses.Codes))}
}

// === Constant Checks (CONST-xxx) ===

// checkHexConstantWidth verifies all hex-string constants fit within 32-bit register width.
// Numeric constants (JSON numbers) are skipped — only hex strings (e.g. "0x50D83AA1")
// represent register-width values that need this constraint.
func checkHexConstantWidth(hj *HardwareJson) VerifyResult {
	if hj.Constants == nil || len(hj.Constants) == 0 {
		return VerifyResult{Check: "CONST-001", Name: "Hex Constant Width", Passed: true, Details: "No constants defined"}
	}

	var violations []string
	hexCount := 0
	for name, val := range hj.Constants {
		str, ok := val.(string)
		if !ok {
			continue // Numeric constants (float64 from JSON) don't represent register values
		}
		if !strings.HasPrefix(str, "0x") && !strings.HasPrefix(str, "0X") {
			continue // Non-hex strings are not register values
		}
		hexCount++
		parsed, err := parseHexAddr(str)
		if err != nil {
			violations = append(violations, fmt.Sprintf("'%s': cannot parse '%s'", name, str))
			continue
		}
		if parsed > 0xFFFFFFFF {
			violations = append(violations, fmt.Sprintf("'%s' = 0x%X exceeds 32-bit register width", name, parsed))
		}
	}

	if len(violations) > 0 {
		return VerifyResult{Check: "CONST-001", Name: "Hex Constant Width", Passed: false,
			Details: strings.Join(violations, "; ")}
	}
	return VerifyResult{Check: "CONST-001", Name: "Hex Constant Width", Passed: true,
		Details: fmt.Sprintf("%d hex constants, all fit 32-bit register width", hexCount)}
}

