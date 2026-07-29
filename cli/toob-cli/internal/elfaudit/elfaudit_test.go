package elfaudit

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalELF constructs a minimal valid ELF32 binary in memory.
// Sections and symbols can be injected for testing specific audit paths.
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
	typ   uint32 // SHT_PROGBITS etc.
}

type testSymbol struct {
	name string
}

type testProg struct {
	typ   uint32
	memsz uint64
}

// writeELF writes a minimal ELF32 little-endian RISC-V binary that debug/elf can parse.
func (b *testELFBuilder) writeELF(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// We'll build a minimal ELF with:
	// - ELF header (52 bytes for ELF32)
	// - Program headers (if any)
	// - Section headers (null + sections + shstrtab + optional symtab+strtab)
	// - String tables

	const elfHeaderSize = 52
	const phEntSize = 32  // ELF32 program header entry size
	const shEntSize = 40  // ELF32 section header entry size

	// Build section name string table (.shstrtab)
	shstrtab := buildStringTable([]string{".shstrtab"}, b.sections, b.symbols)

	// Build symbol string table (.strtab) if symbols exist
	var strtab []byte
	if len(b.symbols) > 0 {
		strtab = buildSymbolStringTable(b.symbols)
	}

	// Count sections: null + user sections + .shstrtab [+ .symtab + .strtab]
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
		symEntSize := uint32(16) // ELF32 Sym entry size
		shOff = symtabOff + uint32(1+len(b.symbols))*symEntSize
	}

	// ELF header
	var hdr [elfHeaderSize]byte
	// e_ident
	hdr[0] = 0x7f; hdr[1] = 'E'; hdr[2] = 'L'; hdr[3] = 'F'
	hdr[4] = 1  // ELFCLASS32
	hdr[5] = 1  // ELFDATA2LSB
	hdr[6] = 1  // EV_CURRENT
	hdr[7] = 0  // ELFOSABI_NONE
	binary.LittleEndian.PutUint16(hdr[16:], 2)                     // e_type = ET_EXEC
	binary.LittleEndian.PutUint16(hdr[18:], 243)                   // e_machine = EM_RISCV
	binary.LittleEndian.PutUint32(hdr[20:], 1)                     // e_version
	binary.LittleEndian.PutUint32(hdr[24:], 0)                     // e_entry
	binary.LittleEndian.PutUint32(hdr[28:], phOff)                 // e_phoff
	binary.LittleEndian.PutUint32(hdr[32:], shOff)                 // e_shoff
	binary.LittleEndian.PutUint32(hdr[36:], 0)                     // e_flags
	binary.LittleEndian.PutUint16(hdr[40:], elfHeaderSize)         // e_ehsize
	binary.LittleEndian.PutUint16(hdr[42:], phEntSize)             // e_phentsize
	binary.LittleEndian.PutUint16(hdr[44:], uint16(numProgs))      // e_phnum
	binary.LittleEndian.PutUint16(hdr[46:], shEntSize)             // e_shentsize
	binary.LittleEndian.PutUint16(hdr[48:], uint16(numSections))   // e_shnum

	// e_shstrndx: index of .shstrtab section (right after user sections)
	shstrtabIdx := uint16(1 + len(b.sections))
	binary.LittleEndian.PutUint16(hdr[50:], shstrtabIdx)

	f.Write(hdr[:])

	// Program headers
	for _, p := range b.progs {
		var ph [phEntSize]byte
		binary.LittleEndian.PutUint32(ph[0:], p.typ)      // p_type
		binary.LittleEndian.PutUint32(ph[4:], 0)           // p_offset
		binary.LittleEndian.PutUint32(ph[8:], 0)           // p_vaddr
		binary.LittleEndian.PutUint32(ph[12:], 0)          // p_paddr
		binary.LittleEndian.PutUint32(ph[16:], 0)          // p_filesz
		binary.LittleEndian.PutUint32(ph[20:], uint32(p.memsz)) // p_memsz
		binary.LittleEndian.PutUint32(ph[24:], 0)          // p_flags
		binary.LittleEndian.PutUint32(ph[28:], 0)          // p_align
		f.Write(ph[:])
	}

	// .shstrtab data
	f.Write(shstrtab.data)

	// .strtab data
	if hasSymbols {
		f.Write(strtab)
	}

	// Symbol table entries (if any)
	if hasSymbols {
		// Null symbol
		var nullSym [16]byte
		f.Write(nullSym[:])

		for _, sym := range b.symbols {
			var symEntry [16]byte
			nameIdx := findInStringTable(strtab, sym.name)
			binary.LittleEndian.PutUint32(symEntry[0:], uint32(nameIdx)) // st_name
			binary.LittleEndian.PutUint32(symEntry[4:], 0)               // st_value
			binary.LittleEndian.PutUint32(symEntry[8:], 0)               // st_size
			symEntry[12] = (1 << 4) | 2                                   // STB_GLOBAL | STT_FUNC
			symEntry[13] = 0                                               // st_other
			binary.LittleEndian.PutUint16(symEntry[14:], 1)               // st_shndx (section 1)
			f.Write(symEntry[:])
		}
	}

	// Section headers
	// [0] Null section header
	var nullSH [shEntSize]byte
	f.Write(nullSH[:])

	// User sections
	for _, sec := range b.sections {
		var sh [shEntSize]byte
		nameOff := findInStringTable(shstrtab.data, sec.name)
		binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))     // sh_name
		binary.LittleEndian.PutUint32(sh[4:], sec.typ)              // sh_type (SHT_PROGBITS=1)
		binary.LittleEndian.PutUint32(sh[8:], uint32(sec.flags))    // sh_flags
		binary.LittleEndian.PutUint32(sh[12:], uint32(sec.addr))    // sh_addr
		binary.LittleEndian.PutUint32(sh[16:], 0)                   // sh_offset
		binary.LittleEndian.PutUint32(sh[20:], uint32(sec.size))    // sh_size
		binary.LittleEndian.PutUint32(sh[24:], 0)                   // sh_link
		binary.LittleEndian.PutUint32(sh[28:], 0)                   // sh_info
		binary.LittleEndian.PutUint32(sh[32:], 1)                   // sh_addralign
		binary.LittleEndian.PutUint32(sh[36:], 0)                   // sh_entsize
		f.Write(sh[:])
	}

	// .shstrtab section header
	{
		var sh [shEntSize]byte
		nameOff := findInStringTable(shstrtab.data, ".shstrtab")
		binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))   // sh_name
		binary.LittleEndian.PutUint32(sh[4:], 3)                  // sh_type = SHT_STRTAB
		binary.LittleEndian.PutUint32(sh[8:], 0)                  // sh_flags
		binary.LittleEndian.PutUint32(sh[12:], 0)                 // sh_addr
		binary.LittleEndian.PutUint32(sh[16:], shstrtabOff)       // sh_offset
		binary.LittleEndian.PutUint32(sh[20:], uint32(len(shstrtab.data))) // sh_size
		f.Write(sh[:])
	}

	// .strtab + .symtab section headers
	if hasSymbols {
		strtabShIdx := uint32(shstrtabIdx + 1)
		symtabShIdx := strtabShIdx + 1
		_ = symtabShIdx

		// .strtab
		{
			var sh [shEntSize]byte
			nameOff := findInStringTable(shstrtab.data, ".strtab")
			binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))
			binary.LittleEndian.PutUint32(sh[4:], 3) // SHT_STRTAB
			binary.LittleEndian.PutUint32(sh[16:], strtabOff)
			binary.LittleEndian.PutUint32(sh[20:], uint32(len(strtab)))
			f.Write(sh[:])
		}
		// .symtab
		{
			var sh [shEntSize]byte
			nameOff := findInStringTable(shstrtab.data, ".symtab")
			binary.LittleEndian.PutUint32(sh[0:], uint32(nameOff))
			binary.LittleEndian.PutUint32(sh[4:], 2) // SHT_SYMTAB
			binary.LittleEndian.PutUint32(sh[16:], symtabOff)
			numSymEntries := uint32(1 + len(b.symbols))
			binary.LittleEndian.PutUint32(sh[20:], numSymEntries*16)
			binary.LittleEndian.PutUint32(sh[24:], strtabShIdx) // sh_link = .strtab index
			binary.LittleEndian.PutUint32(sh[28:], 1)            // sh_info (first global symbol)
			binary.LittleEndian.PutUint32(sh[36:], 16)           // sh_entsize
			f.Write(sh[:])
		}
	}

	return nil
}

type stringTableBuilder struct {
	data []byte
}

func buildStringTable(extra []string, sections []testSection, symbols []testSymbol) stringTableBuilder {
	var b stringTableBuilder
	b.data = append(b.data, 0) // null byte at index 0
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
	data = append(data, 0) // null byte
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
		for j := 0; j < len(nameBytes); j++ {
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

// --- Tests ---

func TestPoisonPill_MockSymbol_Fails(t *testing.T) {
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "test.elf")

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

	config := ELFAuditConfig{
		Profile: "production",
	}
	report, err := AuditELF(elfPath, config)
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}

	if report.Passed {
		t.Errorf("expected report.Passed == false due to mock symbols in production binary")
	}

	foundPoisonFail := false
	for _, chk := range report.Checks {
		if chk.Name == "Mock Poison-Pill" && !chk.Passed {
			foundPoisonFail = true
		}
	}
	if !foundPoisonFail {
		t.Errorf("expected Mock Poison-Pill check failure")
	}
}

func TestPoisonPill_Sandbox_Skipped(t *testing.T) {
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "test.elf")

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

	config := ELFAuditConfig{Profile: "sandbox"}
	report, err := AuditELF(elfPath, config)
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}

	if !report.Passed {
		t.Errorf("expected sandbox profile to pass even with mock symbols")
	}
}

func TestMemoryOverlap_Collision_Fails(t *testing.T) {
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			// .noinit placed at 0x50000000, overlapping with reserved Confirm-RTC
			{name: ".noinit", addr: 0x50000000, size: 256, flags: 0x3, typ: 1},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	config := ELFAuditConfig{
		Profile: "production",
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

	foundOverlapFail := false
	for _, chk := range report.Checks {
		if chk.Name == "Memory Overlap" && !chk.Passed {
			foundOverlapFail = true
		}
	}
	if !foundOverlapFail {
		t.Errorf("expected Memory Overlap check failure")
	}
}

func TestMemoryOverlap_NoCollision_Passes(t *testing.T) {
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			// .noinit far away from reserved region
			{name: ".noinit", addr: 0x50001000, size: 256, flags: 0x3, typ: 1},
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	config := ELFAuditConfig{
		Profile: "production",
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

func TestBudgetFootprint_Exceeded_Fails(t *testing.T) {
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
		},
		progs: []testProg{
			{typ: 1, memsz: 65536}, // PT_LOAD with 64KB
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	config := ELFAuditConfig{
		Profile:        "production",
		Stage1MaxBytes: 32768, // 32KB budget, but 64KB loaded
	}
	report, err := AuditELF(elfPath, config)
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}

	if report.Passed {
		t.Errorf("expected report.Passed == false due to budget exceeded")
	}

	foundBudgetFail := false
	for _, chk := range report.Checks {
		if chk.Name == "Budget Footprint" && !chk.Passed {
			foundBudgetFail = true
		}
	}
	if !foundBudgetFail {
		t.Errorf("expected Budget Footprint check failure")
	}
}

func TestBudgetFootprint_WithinBudget_Passes(t *testing.T) {
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "test.elf")

	builder := &testELFBuilder{
		sections: []testSection{
			{name: ".text", addr: 0x40000000, size: 1024, flags: 0x6, typ: 1},
		},
		progs: []testProg{
			{typ: 1, memsz: 16384}, // PT_LOAD with 16KB
		},
	}
	if err := builder.writeELF(elfPath); err != nil {
		t.Fatalf("failed to write test ELF: %v", err)
	}

	config := ELFAuditConfig{
		Profile:        "production",
		Stage1MaxBytes: 32768, // 32KB budget, 16KB used
	}
	report, err := AuditELF(elfPath, config)
	if err != nil {
		t.Fatalf("AuditELF unexpected error: %v", err)
	}

	if !report.Passed {
		t.Errorf("expected report.Passed == true when within budget")
	}
}
