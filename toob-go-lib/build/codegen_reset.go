package build

import (
	"cmp"
	"errors"
	"fmt"
	"math/bits"
	"slices"
)

// resetClassMacros maps hardware.json reset classes to CHIP_RST_CLASS_* values.
var resetClassMacros = map[string]string{
	"power":       "CHIP_RST_CLASS_POWER",
	"intentional": "CHIP_RST_CLASS_INTENTIONAL",
	"crash":       "CHIP_RST_CLASS_CRASH",
}

func resetClassPriority(class string) int {
	switch class {
	case "crash":
		return 3
	case "intentional":
		return 2
	case "power":
		return 1
	default:
		return 0
	}
}

// renderResetCauses renders generated_reset_causes.h with the 32-bit bitmask
// and priority-ordered classification table (CRIT-21, MED-47).
func renderResetCauses(rc *ResetCauses) (*cSource, error) {
	if rc == nil {
		return nil, errors.New("reset causes table is nil")
	}
	if len(rc.Codes) == 0 {
		return nil, errors.New("reset_causes.codes must contain at least one entry")
	}
	if rc.ClearReg != "" && !isCSymbol(rc.ClearReg) {
		return nil, fmt.Errorf("reset_causes.clear_reg %q is not a valid C identifier", rc.ClearReg)
	}
	var globalMaskLit string
	if rc.Mask != "" {
		lit, err := cU32Literal(rc.Mask)
		if err != nil {
			return nil, fmt.Errorf("reset_causes.mask: %w", err)
		}
		globalMaskLit = lit
	}

	codes := slices.Clone(rc.Codes)
	for _, code := range codes {
		if !isCSymbol(code.Name) {
			return nil, fmt.Errorf("reset cause name %q is not a valid C identifier", code.Name)
		}
		if code.ClearReg != "" && !isCSymbol(code.ClearReg) {
			return nil, fmt.Errorf("reset cause '%s' clear_reg %q is not a valid C identifier", code.Name, code.ClearReg)
		}
		val, mask := uint32(code.Value), uint32(code.Mask)
		if mask != 0 && (val & ^mask) != 0 {
			return nil, fmt.Errorf("reset cause '%s' value 0x%X has bits outside its mask 0x%X", code.Name, val, mask)
		}
		if _, ok := resetClassMacros[code.Class]; !ok {
			return nil, fmt.Errorf("reset cause '%s' has unknown class '%s' (must be power, intentional or crash)",
				code.Name, code.Class)
		}
	}

	// Order crash > intentional > power, placing specific bitmasks and non-zero
	// codes ahead of 0-valued POR defaults while preserving author order on ties.
	slices.SortStableFunc(codes, func(a, b ResetCauseCode) int {
		if c := cmp.Compare(resetClassPriority(b.Class), resetClassPriority(a.Class)); c != 0 {
			return c
		}
		aZero := a.Value == 0 && a.Mask == 0
		bZero := b.Value == 0 && b.Mask == 0
		if aZero != bZero {
			if aZero {
				return 1
			}
			return -1
		}
		return cmp.Compare(bits.OnesCount32(uint32(b.Mask)), bits.OnesCount32(uint32(a.Mask)))
	})

	s := newCHeader("GENERATED_RESET_CAUSES_H")
	s.line("#include <stdint.h>")
	s.blank()
	s.define("CHIP_RST_CLASS_UNKNOWN", "0U")
	s.define("CHIP_RST_CLASS_POWER", "1U")
	s.define("CHIP_RST_CLASS_INTENTIONAL", "2U")
	s.define("CHIP_RST_CLASS_CRASH", "3U")
	if rc.ClearReg != "" {
		defineLayoutHint(s, "CHIP_RST_CLEAR_REG", rc.ClearReg)
		defineLayoutHint(s, "CHIP_RST_CLEAR_MASK", hex32(uint32(rc.ClearMask)))
	}
	s.blank()
	s.line("typedef struct {")
	s.line("    uint32_t hw_code;")
	s.line("    uint32_t mask;")
	s.line("    uint8_t  rst_class;")
	s.line("} chip_reset_cause_entry_t;")
	s.blank()
	s.line("static const chip_reset_cause_entry_t CHIP_RESET_CAUSE_TABLE[] = {")
	for _, code := range codes {
		val, mask := uint32(code.Value), uint32(code.Mask)
		class := resetClassMacros[code.Class]
		valStr := fmt.Sprintf("0x%08XU", val)
		if val <= 0xFF && mask == 0 {
			valStr = fmt.Sprintf("%3dU", val)
		}
		maskStr := "0U"
		if mask != 0 {
			maskStr = fmt.Sprintf("0x%08XU", mask)
		}
		s.linef("    { %s, %s, %-28s }, /* %s */", valStr, maskStr, class, code.Name)
	}
	s.line("};")
	s.definef("CHIP_RESET_CAUSE_TABLE_LEN", "%dU", len(codes))
	s.blank()
	s.line("/**")
	s.line(" * @brief Lookup reset class for a 32-bit hardware reset register/code.")
	s.line(" *        Entries are evaluated in severity/specificity order (crash > intentional > power);")
	s.line(" *        entries with mask != 0 evaluate ((hw_code & mask) == value), mask == 0 matches exact equality.")
	s.line(" * @return CHIP_RST_CLASS_* constant.")
	s.line(" */")
	s.line("static inline uint8_t chip_rst_class_lookup(uint32_t hw_code)")
	s.line("{")
	if globalMaskLit != "" {
		s.linef("    hw_code &= %s;", globalMaskLit)
	}
	s.line("    for (uint32_t i = 0U; i < CHIP_RESET_CAUSE_TABLE_LEN; i++) {")
	s.line("        uint32_t mask = CHIP_RESET_CAUSE_TABLE[i].mask;")
	s.line("        if ((mask != 0U) ? ((hw_code & mask) == CHIP_RESET_CAUSE_TABLE[i].hw_code)")
	s.line("                         : (hw_code == CHIP_RESET_CAUSE_TABLE[i].hw_code)) {")
	s.line("            return CHIP_RESET_CAUSE_TABLE[i].rst_class;")
	s.line("        }")
	s.line("    }")
	s.line("    return CHIP_RST_CLASS_UNKNOWN;")
	s.line("}")
	s.blank()
	return s, nil
}
