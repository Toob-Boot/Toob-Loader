package elfaudit

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testELFBuilder struct {
	sections []testSection
	symbols  []testSymbol
	progs    []testProg
}

type testSection struct {
	name  string
	addr  uint64
	size  uint64
	flags uint64
	typ   uint32
}

type testSymbol struct {
	name    string
	symType elf.SymType
}

type testProg struct {
	typ    uint32
	vaddr  uint64
	paddr  uint64
	filesz uint64
	memsz  uint64
}

func (b *testELFBuilder) writeELF(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	const elfHeaderSize = 52
	const phEntSize = 32
	const shEntSize = 40

	shstrtab := buildStringTable([]string{".shstrtab"}, b.sections, b.symbols)

	var strtab []byte
	if len(b.symbols) > 0 {
		strtab = buildSymbolStringTable(b.symbols)
	}

	numSections := 1 + len(b.sections) + 1
	hasSymbols := len(b.symbols) > 0
	if hasSymbols {
		numSections += 2
	}

	numProgs := len(b.progs)

	phOff := uint32(elfHeaderSize)
	shstrtabOff := phOff + uint32(numProgs)*phEntSize
	strtabOff := shstrtabOff + uint32(len(shstrtab.data))
	symtabOff := strtabOff
	if hasSymbols {
		symtabOff = strtabOff + uint32(len(strtab))
	}
	shOff := symtabOff
	if hasSymbols {
		symEntSize := uint32(16)
		shOff = symtabOff + uint32(1+len(b.symbols))*symEntSize
	}

	var hdr [elfHeaderSize]byte
	hdr[0] = 0x7f
	hdr[1] = 'E'
	hdr[2] = 'L'
	hdr[3] = 'F'
	hdr[4] = 1
	hdr[5] = 1
	hdr[6] = 1
	hdr[7] = 0
	binary.LittleEndian.PutUint16(hdr[16:], 2)
	binary.LittleEndian.PutUint16(hdr[18:], 243)
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	binary.LittleEndian.PutUint32(hdr[24:], 0)
	binary.LittleEndian.PutUint32(hdr[28:], phOff)
	binary.LittleEndian.PutUint32(hdr[32:], shOff)
	binary.LittleEndian.PutUint32(hdr[36:], 0)
	binary.LittleEndian.PutUint16(hdr[40:], elfHeaderSize)
	binary.LittleEndian.PutUint16(hdr[42:], phEntSize)
	binary.LittleEndian.PutUint16(hdr[44:], uint16(numProgs))
	binary.LittleEndian.PutUint16(hdr[46:], shEntSize)
	binary.LittleEndian.PutUint16(hdr[48:], uint16(numSections))

	shstrtabIdx := uint16(1 + len(b.sections))
	binary.LittleEndian.PutUint16(hdr[50:], shstrtabIdx)

	_, _ = f.Write(hdr[:])

	for _, p := range b.progs {
		var ph [phEntSize]byte
		binary.LittleEndian.PutUint32(ph[0:], p.typ)
		binary.LittleEndian.PutUint32(ph[4:], 0)
		binary.LittleEndian.PutUint32(ph[8:], uint32(p.vaddr))
		binary.LittleEndian.PutUint32(ph[12:], uint32(p.paddr))
		binary.LittleEndian.PutUint32(ph[16:], uint32(p.filesz))
		binary.LittleEndian.PutUint32(ph[20:], uint32(p.memsz))
		binary.LittleEndian.PutUint32(ph[24:], 0)
		binary.LittleEndian.PutUint32(ph[28:], 0)
		_, _ = f.Write(ph[:])
	}

	_, _ = f.Write(shstrtab.data)

	if hasSymbols {
		_, _ = f.Write(strtab)
	}

	if hasSymbols {
		var nullSym [16]byte
		_, _ = f.Write(nullSym[:])

		for _, sym := range b.symbols {
			var symEntry [16]byte
			nameIdx := findInStringTable(strtab, sym.name)
			binary.LittleEndian.PutUint32(symEntry[0:], uint32(nameIdx))
			stType := sym.symType
			if stType == 0 {
				stType = elf.STT_FUNC
			}
			bind := byte(elf.STB_GLOBAL)
			shndx := uint16(1)
			if stType == elf.STT_FILE {
				bind = byte(elf.STB_LOCAL)
				shndx = uint16(elf.SHN_ABS)
			}
			symEntry[12] = (bind << 4) | byte(stType)
			binary.LittleEndian.PutUint16(symEntry[14:], shndx)
			_, _ = f.Write(symEntry[:])
		}
	}

	var nullSH [shEntSize]byte
	_, _ = f.Write(nullSH[:])

	for _, sec := range b.sections {
		var sh [shEntSize]byte
		nameOff := findInStringTable(shstrtab.data, sec.name)
		binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))
		binary.LittleEndian.PutUint32(sh[4:], sec.typ)
		binary.LittleEndian.PutUint32(sh[8:], uint32(sec.flags))
		binary.LittleEndian.PutUint32(sh[12:], uint32(sec.addr))
		binary.LittleEndian.PutUint32(sh[16:], 0)
		binary.LittleEndian.PutUint32(sh[20:], uint32(sec.size))
		binary.LittleEndian.PutUint32(sh[32:], 1)
		_, _ = f.Write(sh[:])
	}

	{
		var sh [shEntSize]byte
		nameOff := findInStringTable(shstrtab.data, ".shstrtab")
		binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))
		binary.LittleEndian.PutUint32(sh[4:], 3)
		binary.LittleEndian.PutUint32(sh[16:], shstrtabOff)
		binary.LittleEndian.PutUint32(sh[20:], uint32(len(shstrtab.data)))
		_, _ = f.Write(sh[:])
	}

	if hasSymbols {
		strtabShIdx := uint32(shstrtabIdx + 1)

		{
			var sh [shEntSize]byte
			nameOff := findInStringTable(shstrtab.data, ".strtab")
			binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))
			binary.LittleEndian.PutUint32(sh[4:], 3)
			binary.LittleEndian.PutUint32(sh[16:], strtabOff)
			binary.LittleEndian.PutUint32(sh[20:], uint32(len(strtab)))
			_, _ = f.Write(sh[:])
		}
		{
			var sh [shEntSize]byte
			nameOff := findInStringTable(shstrtab.data, ".symtab")
			binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))
			binary.LittleEndian.PutUint32(sh[4:], 2)
			binary.LittleEndian.PutUint32(sh[16:], symtabOff)
			numSymEntries := uint32(1 + len(b.symbols))
			binary.LittleEndian.PutUint32(sh[20:], numSymEntries*16)
			binary.LittleEndian.PutUint32(sh[24:], strtabShIdx)
			binary.LittleEndian.PutUint32(sh[28:], 1)
			binary.LittleEndian.PutUint32(sh[36:], 16)
			_, _ = f.Write(sh[:])
		}
	}

	return nil
}

type stringTableBuilder struct {
	data []byte
}

func buildStringTable(extra []string, sections []testSection, symbols []testSymbol) stringTableBuilder {
	var b stringTableBuilder
	b.data = append(b.data, 0)
	for _, name := range extra {
		b.data = append(b.data, []byte(name)...)
		b.data = append(b.data, 0)
	}
	for _, sec := range sections {
		b.data = append(b.data, []byte(sec.name)...)
		b.data = append(b.data, 0)
	}
	if len(symbols) > 0 {
		b.data = append(b.data, []byte(".strtab")...)
		b.data = append(b.data, 0)
		b.data = append(b.data, []byte(".symtab")...)
		b.data = append(b.data, 0)
	}
	return b
}

func buildSymbolStringTable(symbols []testSymbol) []byte {
	var data []byte
	data = append(data, 0)
	for _, sym := range symbols {
		data = append(data, []byte(sym.name)...)
		data = append(data, 0)
	}
	return data
}

func findInStringTable(table []byte, name string) int {
	nameBytes := []byte(name)
	for i := 0; i <= len(table)-len(nameBytes); i++ {
		if i > 0 && table[i-1] != 0 {
			continue
		}
		match := true
		for j := range nameBytes {
			if table[i+j] != nameBytes[j] {
				match = false
				break
			}
		}
		if match && (i+len(nameBytes) >= len(table) || table[i+len(nameBytes)] == 0) {
			return i
		}
	}
	return 0
}

func TestProfileValidation_FailClosed(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "test.elf")
	builder := &testELFBuilder{
		sections: []testSection{{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1}},
		symbols:  []testSymbol{{name: "boot_main"}},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatal(err)
	}

	for _, badProfile := range []string{"", "prod", "sandbox", "PRODUCTION", "development"} {
		if _, err := AuditELF(elfPath, ELFAuditConfig{Profile: badProfile}); err == nil {
			t.Fatalf("expected invalid profile %q to fail closed", badProfile)
		}
	}
}

func TestPoisonPill_MockSymbol_Fails(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
		},
		symbols: []testSymbol{
			{name: "boot_main"},
			{name: "sandbox_crypto_mock"},
			{name: "efuse_read_dslc_mock"},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{Profile: ProfileProduction})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if report.Passed {
		t.Errorf("expected report.Passed == false due to mock symbols in production binary")
	}
}

func TestPoisonPill_GCStrippedMockTUFileSymbol_Fails(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "gc_mock_tu.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x08000000, size: 1024, flags: 0x6, typ: 1},
			// Empty 0-byte .toob_mock_section left by linker script after --gc-sections:
			{name: ".toob_mock_section", addr: 0x08000400, size: 0, flags: 0x2, typ: 1},
		},
		symbols: []testSymbol{
			{name: "boot_main"},
			// STT_FILE left in .symtab when efuse_mock.c was linked into production!
			{name: "efuse_mock.c", symType: elf.STT_FILE},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatal(err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{Profile: ProfileProduction})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatal("expected STT_FILE mock TU symbol to fail production Poison-Pill check")
	}
}

func TestPoisonPill_EmptyMockSectionAlone_Passes(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "empty_mock_sec.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x08000000, size: 1024, flags: 0x6, typ: 1},
			{name: ".toob_mock_section", addr: 0x08000400, size: 0, flags: 0x2, typ: 1},
		},
		symbols: []testSymbol{
			{name: "efuse_real.c", symType: elf.STT_FILE},
			{name: "boot_main"},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatal(err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{Profile: ProfileProduction})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected 0-byte .toob_mock_section without mock symbols to pass, checks: %+v", report.Checks)
	}
}

func TestPoisonPill_DevProfile_Skipped(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
		},
		symbols: []testSymbol{
			{name: "some_mock_function"},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{Profile: ProfileDev})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if !report.Passed {
		t.Errorf("expected dev profile to pass even with mock symbols")
	}
}

func TestMemoryOverlap_Collision_Fails(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".noinit", addr: 0x50000000, size: 256, flags: 0x3, typ: 1},
		},
		symbols: []testSymbol{{name: "boot_main"}},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	config := ELFAuditConfig{
		Profile: ProfileProduction,
		ReservedRegions: []MemoryRegion{
			{Name: "Confirm-RTC-RAM", Base: 0x50000000, Size: 64},
		},
	}
	report, err := AuditELF(elfPath, config)
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if report.Passed {
		t.Errorf("expected report.Passed == false due to memory overlap")
	}
}

func TestMemoryOverlap_NoCollision_Passes(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".noinit", addr: 0x50001000, size: 256, flags: 0x3, typ: 1},
		},
		symbols: []testSymbol{{name: "boot_main"}},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	config := ELFAuditConfig{
		Profile: ProfileProduction,
		ReservedRegions: []MemoryRegion{
			{Name: "Confirm-RTC-RAM", Base: 0x50000000, Size: 64},
		},
	}
	report, err := AuditELF(elfPath, config)
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if !report.Passed {
		t.Errorf("expected report.Passed == true when sections do not overlap reserved regions")
	}
}

func TestFlashBounds_UsesLMAPaddrNotVMA(t *testing.T) {
	dir := t.TempDir()
	validELF := filepath.Join(dir, "valid_data_lma.elf")

	// .data has VMA in SRAM (0x20000000) and LMA in Flash (0x08004000).
	validBuilder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x08000000, size: 16384, flags: 0x6, typ: 1},
			{name: ".data", addr: 0x20000000, size: 512, flags: 0x3, typ: 1},
		},
		symbols: []testSymbol{{name: "boot_main"}},
		progs: []testProg{
			{typ: 1, vaddr: 0x08000000, paddr: 0x08000000, filesz: 16384, memsz: 16384},
			{typ: 1, vaddr: 0x20000000, paddr: 0x08004000, filesz: 512, memsz: 512},
		},
	}
	if err := validBuilder.writeELF(validELF); err != nil {
		t.Fatal(err)
	}

	flashWin := &MemoryRegion{Name: "Stage1A", Base: 0x08000000, Size: 32768}
	report, err := AuditELF(validELF, ELFAuditConfig{
		Profile:        ProfileProduction,
		FlashBounds:    flashWin,
		Stage1MaxBytes: 32768,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("expected SRAM VMA with Flash LMA to pass FlashBounds check: %+v", report.Checks)
	}

	// Now place .data LMA outside the Stage1A flash window -> must fail!
	badELF := filepath.Join(dir, "bad_data_lma.elf")
	badBuilder := &testELFBuilder{
		sections: []testSection{{name: ".text", addr: 0x08000000, size: 16384, flags: 0x6, typ: 1}},
		symbols:  []testSymbol{{name: "boot_main"}},
		progs: []testProg{
			{typ: 1, vaddr: 0x08000000, paddr: 0x08000000, filesz: 16384, memsz: 16384},
			{typ: 1, vaddr: 0x20000000, paddr: 0x20000000, filesz: 512, memsz: 512},
		},
	}
	if wErr := badBuilder.writeELF(badELF); wErr != nil {
		t.Fatal(wErr)
	}
	badReport, err := AuditELF(badELF, ELFAuditConfig{
		Profile:     ProfileProduction,
		FlashBounds: flashWin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if badReport.Passed {
		t.Fatal("expected segment with SRAM LMA outside FlashBounds to fail")
	}
}

func TestBudgetFootprint_AlignmentGapSpanOverflow_Fails(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "gap_overflow.elf")

	// sum(Filesz) = 16384 + 4096 = 20480 <= 32768,
	// BUT occupied flash image span = (0x08008000 + 4096) - 0x08000000 = 36864 > 32768!
	builder := &testELFBuilder{
		sections: []testSection{{name: ".text", addr: 0x08000000, size: 16384, flags: 0x6, typ: 1}},
		symbols:  []testSymbol{{name: "boot_main"}},
		progs: []testProg{
			{typ: 1, vaddr: 0x08000000, paddr: 0x08000000, filesz: 16384, memsz: 16384},
			{typ: 1, vaddr: 0x20000000, paddr: 0x08008000, filesz: 4096, memsz: 4096},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatal(err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{
		Profile:        ProfileProduction,
		Stage1MaxBytes: 32768,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected LMA alignment gap span (36864 > 32768) to fail Budget Footprint")
	}
}

func TestBudgetFootprint_Exceeded_Fails(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
		},
		symbols: []testSymbol{{name: "boot_main"}},
		progs: []testProg{
			{typ: 1, filesz: 65536, memsz: 65536},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{
		Profile:        ProfileProduction,
		Stage1MaxBytes: 32768,
	})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if report.Passed {
		t.Errorf("expected report.Passed == false due to budget exceeded")
	}
}

func TestBudgetFootprint_WithinBudget_Passes(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
		},
		symbols: []testSymbol{{name: "boot_main"}},
		progs: []testProg{
			{typ: 1, paddr: 0x40000000, filesz: 16384, memsz: 16384},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{
		Profile:        ProfileProduction,
		Stage1MaxBytes: 32768,
	})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if !report.Passed {
		t.Errorf("expected report.Passed == true when within budget")
	}
}

func TestBudgetFootprint_BSSIgnoredForFlashBudget(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "bss.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x42000000, size: 16384, flags: 0x6, typ: 1},
			{name: ".bss", addr: 0x40800000, size: 32768, flags: 0x3, typ: 8},
		},
		symbols: []testSymbol{{name: "boot_main"}},
		progs: []testProg{
			{typ: 1, vaddr: 0x42000000, paddr: 0x42000000, filesz: 16384, memsz: 16384},
			{typ: 1, vaddr: 0x40800000, paddr: 0x40800000, filesz: 0, memsz: 32768},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{
		Profile:        ProfileProduction,
		Stage1MaxBytes: 32768,
	})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected SRAM .bss PT_LOAD (Filesz=0, Memsz=32768) not to count against Flash budget: %+v", report.Checks)
	}
}

func TestPoisonPill_StrippedProductionELF_Fails(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "stripped.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write stripped test ELF: %v", err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{Profile: ProfileProduction})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatal("expected stripped production ELF (missing symbol table) to fail AuditELF")
	}
}

func TestPoisonPill_MockSection_Fails(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "mocksec.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
			{name: ".toob_mock_section", addr: 0x40000400, size: 4, flags: 0x2, typ: 1},
		},
		symbols: []testSymbol{{name: "boot_main"}},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write mock-section ELF: %v", err)
	}

	report, err := AuditELF(elfPath, ELFAuditConfig{Profile: ProfileProduction})
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatal("expected production ELF with .toob_mock_section to fail AuditELF")
	}
}

func TestExportReportJSON_PropagatesWriteError(t *testing.T) {
	dir := t.TempDir()
	report := &ELFAuditReport{Profile: ProfileProduction, Passed: true}

	validOut := filepath.Join(dir, "sub", "audit.json")
	if err := ExportReportJSON(report, validOut); err != nil {
		t.Fatalf("ExportReportJSON failed on valid path: %v", err)
	}

	// Attempting to write to an existing directory path must fail and propagate the os.WriteFile error.
	if err := ExportReportJSON(report, dir); err == nil {
		t.Fatal("expected ExportReportJSON to return error when outPath is an existing directory")
	}
	if err := ExportReportJSON(nil, validOut); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil report error, got %v", err)
	}
}
