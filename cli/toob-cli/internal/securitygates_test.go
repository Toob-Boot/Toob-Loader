package internal

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/toob-boot/toob/internal/buildrunner"
	"github.com/toob-boot/toob/internal/conformance"
	"github.com/toob-boot/toob/internal/elfaudit"
	"github.com/toob-boot/toob/internal/literallint"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/resolve"
)

func repoRootDir(t *testing.T) string {
	t.Helper()
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "CMakeLists.txt")); err != nil {
		t.Fatalf("failed to locate repository root from %s: %v", root, err)
	}
	return root
}

func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(repoRootDir(t), "test", "fixtures", "malicious_packages", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("missing fixture directory %s: %v", p, err)
	}
	return p
}

type synthSection struct {
	name  string
	addr  uint64
	size  uint64
	flags uint64
	typ   uint32
}

type synthProg struct {
	typ    uint32
	flags  uint32
	vaddr  uint64
	paddr  uint64
	filesz uint64
	memsz  uint64
}

type synthSym struct {
	name string
}

// writeSyntheticGateELF emits a valid 32-bit RISC-V ELF with optional PT_LOAD
// segments, sections, and .symtab for Tier 3D gate integration testing.
func writeSyntheticGateELF(t *testing.T, path string, secs []synthSection, progs []synthProg, syms []synthSym) {
	t.Helper()

	const (
		elfHdrBytes = 52
		phEntBytes  = 32
		shEntBytes  = 40
		symEntBytes = 16
	)

	var shstrtab strings.Builder
	shstrtab.WriteByte(0)
	secNameOff := make([]uint32, len(secs))
	for i, s := range secs {
		secNameOff[i] = uint32(shstrtab.Len())
		shstrtab.WriteString(s.name)
		shstrtab.WriteByte(0)
	}
	shstrtabSecOff := uint32(shstrtab.Len())
	shstrtab.WriteString(".shstrtab\x00")
	strtabSecOff := uint32(shstrtab.Len())
	shstrtab.WriteString(".strtab\x00")
	symtabSecOff := uint32(shstrtab.Len())
	shstrtab.WriteString(".symtab\x00")
	shstrBytes := []byte(shstrtab.String())

	var strtab strings.Builder
	strtab.WriteByte(0)
	symNameOff := make([]uint32, len(syms))
	for i, s := range syms {
		symNameOff[i] = uint32(strtab.Len())
		strtab.WriteString(s.name)
		strtab.WriteByte(0)
	}
	strBytes := []byte(strtab.String())

	hasSyms := len(syms) > 0
	numSecs := 1 + len(secs) + 1
	if hasSyms {
		numSecs += 2
	}

	phOff := uint32(elfHdrBytes)
	payloadOff := phOff + uint32(len(progs))*phEntBytes
	var maxFilesz uint32
	for _, p := range progs {
		if p.filesz > uint64(maxFilesz) {
			maxFilesz = uint32(p.filesz)
		}
	}
	shstrOff := payloadOff + maxFilesz
	strOff := shstrOff + uint32(len(shstrBytes))
	symOff := strOff
	if hasSyms {
		symOff += uint32(len(strBytes))
	}
	shOff := symOff
	if hasSyms {
		shOff += uint32(1+len(syms)) * symEntBytes
	}

	var hdr [elfHdrBytes]byte
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x7f, 'E', 'L', 'F'
	hdr[4], hdr[5], hdr[6] = 1, 1, 1
	binary.LittleEndian.PutUint16(hdr[16:], 2)
	binary.LittleEndian.PutUint16(hdr[18:], 243)
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	binary.LittleEndian.PutUint32(hdr[28:], phOff)
	binary.LittleEndian.PutUint32(hdr[32:], shOff)
	binary.LittleEndian.PutUint16(hdr[40:], elfHdrBytes)
	binary.LittleEndian.PutUint16(hdr[42:], phEntBytes)
	binary.LittleEndian.PutUint16(hdr[44:], uint16(len(progs)))
	binary.LittleEndian.PutUint16(hdr[46:], shEntBytes)
	binary.LittleEndian.PutUint16(hdr[48:], uint16(numSecs))
	binary.LittleEndian.PutUint16(hdr[50:], uint16(1+len(secs)))

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create ELF %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	writeBytes := func(b []byte) {
		t.Helper()
		if _, wErr := f.Write(b); wErr != nil {
			t.Fatalf("write ELF %s: %v", path, wErr)
		}
	}

	writeBytes(hdr[:])

	for _, p := range progs {
		var ph [phEntBytes]byte
		binary.LittleEndian.PutUint32(ph[0:], p.typ)
		binary.LittleEndian.PutUint32(ph[4:], payloadOff)
		binary.LittleEndian.PutUint32(ph[8:], uint32(p.vaddr))
		binary.LittleEndian.PutUint32(ph[12:], uint32(p.paddr))
		binary.LittleEndian.PutUint32(ph[16:], uint32(p.filesz))
		binary.LittleEndian.PutUint32(ph[20:], uint32(p.memsz))
		binary.LittleEndian.PutUint32(ph[24:], p.flags)
		binary.LittleEndian.PutUint32(ph[28:], 4)
		writeBytes(ph[:])
	}

	if maxFilesz > 0 {
		writeBytes(make([]byte, maxFilesz))
	}
	writeBytes(shstrBytes)
	if hasSyms {
		writeBytes(strBytes)
		var nullSym [symEntBytes]byte
		writeBytes(nullSym[:])
		for i := range syms {
			var sym [symEntBytes]byte
			binary.LittleEndian.PutUint32(sym[0:], symNameOff[i])
			sym[12] = (byte(elf.STB_GLOBAL) << 4) | byte(elf.STT_FUNC)
			binary.LittleEndian.PutUint16(sym[14:], 1)
			writeBytes(sym[:])
		}
	}

	var nullSH [shEntBytes]byte
	writeBytes(nullSH[:])
	for i, s := range secs {
		var sh [shEntBytes]byte
		binary.LittleEndian.PutUint32(sh[0:], secNameOff[i])
		binary.LittleEndian.PutUint32(sh[4:], s.typ)
		binary.LittleEndian.PutUint32(sh[8:], uint32(s.flags))
		binary.LittleEndian.PutUint32(sh[12:], uint32(s.addr))
		binary.LittleEndian.PutUint32(sh[16:], payloadOff)
		binary.LittleEndian.PutUint32(sh[20:], uint32(s.size))
		binary.LittleEndian.PutUint32(sh[32:], 4)
		writeBytes(sh[:])
	}

	var shstrSH [shEntBytes]byte
	binary.LittleEndian.PutUint32(shstrSH[0:], shstrtabSecOff)
	binary.LittleEndian.PutUint32(shstrSH[4:], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint32(shstrSH[16:], shstrOff)
	binary.LittleEndian.PutUint32(shstrSH[20:], uint32(len(shstrBytes)))
	writeBytes(shstrSH[:])

	if hasSyms {
		var strSH [shEntBytes]byte
		binary.LittleEndian.PutUint32(strSH[0:], strtabSecOff)
		binary.LittleEndian.PutUint32(strSH[4:], uint32(elf.SHT_STRTAB))
		binary.LittleEndian.PutUint32(strSH[16:], strOff)
		binary.LittleEndian.PutUint32(strSH[20:], uint32(len(strBytes)))
		writeBytes(strSH[:])

		var symSH [shEntBytes]byte
		binary.LittleEndian.PutUint32(symSH[0:], symtabSecOff)
		binary.LittleEndian.PutUint32(symSH[4:], uint32(elf.SHT_SYMTAB))
		binary.LittleEndian.PutUint32(symSH[16:], symOff)
		binary.LittleEndian.PutUint32(symSH[20:], uint32(1+len(syms))*symEntBytes)
		binary.LittleEndian.PutUint32(symSH[24:], uint32(2+len(secs)))
		binary.LittleEndian.PutUint32(symSH[28:], 1)
		binary.LittleEndian.PutUint32(symSH[32:], 4)
		binary.LittleEndian.PutUint32(symSH[36:], symEntBytes)
		writeBytes(symSH[:])
	}
}

func TestTier3D_MaliciousPackageAndSecurityGates(t *testing.T) {
	t.Run("00_valid_baseline passes conformance, literallint, macro_audit, ValidateCompilerFlag, elfaudit, and buildrunner gates", func(t *testing.T) {
		baseDir := fixtureDir(t, "00_valid_baseline")

		confRep, err := conformance.AuditPackage(baseDir)
		if err != nil || !confRep.Passed {
			t.Fatalf("baseline conformance failed: err=%v checks=%+v", err, confRep)
		}
		lintRep, err := literallint.RunLint(literallint.DefaultConfig(baseDir))
		if err != nil || !lintRep.Passed {
			t.Fatalf("baseline literallint failed: err=%v rep=%+v", err, lintRep)
		}
		if macroErr := build.AuditPackageMacros([]string{baseDir}, nil); macroErr != nil {
			t.Fatalf("baseline AuditPackageMacros failed: %v", macroErr)
		}
		for _, f := range []string{"-Os", "-mcpu=cortex-m4", "-mthumb"} {
			if flagErr := build.ValidateCompilerFlag("c_flags", f); flagErr != nil {
				t.Fatalf("baseline ValidateCompilerFlag(%q) failed: %v", f, flagErr)
			}
		}

		// End-to-end buildrunner.RunPostLinkGates positive control with Stage-0 + Stage-1A + .map + .su + SSP.
		buildDir := t.TempDir()
		s0ELF := filepath.Join(buildDir, "toob_stage0.elf")
		s1ELF := filepath.Join(buildDir, "toob_stage1.elf")
		writeSyntheticGateELF(t, s0ELF,
			[]synthSection{{name: ".text", addr: 0x08000000, size: 512, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08000000, paddr: 0x08000000, filesz: 512, memsz: 512}},
			[]synthSym{{name: "stage0_main"}, {name: "__stack_chk_fail"}},
		)
		writeSyntheticGateELF(t, s1ELF,
			[]synthSection{{name: ".text", addr: 0x08008000, size: 1024, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08008000, paddr: 0x08008000, filesz: 1024, memsz: 1024}},
			[]synthSym{{name: "boot_main"}, {name: "__stack_chk_fail"}},
		)
		mapBytes, err := os.ReadFile(filepath.Join(baseDir, "baseline.map"))
		if err != nil {
			t.Fatal(err)
		}
		suBytes, err := os.ReadFile(filepath.Join(baseDir, "baseline.su"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"toob_stage0.map", "toob_stage1.map"} {
			if wErr := os.WriteFile(filepath.Join(buildDir, p), mapBytes, 0o600); wErr != nil {
				t.Fatal(wErr)
			}
		}
		if wErr := os.WriteFile(filepath.Join(buildDir, "baseline.su"), suBytes, 0o600); wErr != nil {
			t.Fatal(wErr)
		}

		res, err := buildrunner.RunPostLinkGates(buildrunner.PostLinkGateOptions{
			BuildDir: buildDir,
			Profile:  resolve.ProfileProduction,
			Plan:     &resolve.Plan{},
			ManifestCtx: &manifest.Context{
				Hardware: &manifest.HardwareJson{
					BootromImage: &build.BootromImageSpec{Layout: build.BootromLayoutFlat},
				},
			},
			ManifestResult: &manifest.Result{
				Layout: &manifest.PartitionLayout{
					FlashBase: 0x08000000,
					Stage0:    build.PartitionSlot{Name: "Stage0", Addr: 0x08000000, Budget: 0x8000},
					Stage1A:   build.PartitionSlot{Name: "Stage1A", Addr: 0x08008000, Budget: 0x8000},
					Wal:       build.PartitionSlot{Name: "WAL", Addr: 0x08010000, Budget: 0x4000},
				},
			},
		})
		if err != nil {
			t.Fatalf("baseline RunPostLinkGates failed: %v", err)
		}
		if len(res.AuditReports) != 2 {
			t.Fatalf("expected 2 ELF audit reports (stage0 + stage1), got %d", len(res.AuditReports))
		}
	})

	t.Run("01_dup_core_symbol rejected by elfaudit map ownership", func(t *testing.T) {
		fDir := fixtureDir(t, "01_dup_core_symbol")
		elfPath := filepath.Join(t.TempDir(), "hijack.elf")
		writeSyntheticGateELF(t, elfPath,
			[]synthSection{{name: ".text", addr: 0x08008000, size: 256, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08008000, paddr: 0x08008000, filesz: 256, memsz: 256}},
			[]synthSym{{name: "boot_main"}, {name: "boot_verify_slot_image"}, {name: "__stack_chk_fail"}},
		)
		rep, err := elfaudit.AuditELF(elfPath, elfaudit.ELFAuditConfig{
			Profile:    elfaudit.ProfileProduction,
			MapPath:    filepath.Join(fDir, "hijack.map"),
			RequireSSP: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Passed {
			t.Fatal("expected hijacked boot_verify_slot_image in HAL TU to fail elfaudit")
		}
	})

	t.Run("02_macro_poisoning rejected by AuditPackageMacros", func(t *testing.T) {
		fDir := fixtureDir(t, "02_macro_poisoning")
		pkgA := filepath.Join(fDir, "pkg_a")
		pkgB := filepath.Join(fDir, "pkg_b")

		if err := build.AuditPackageMacros([]string{pkgA}, nil); err == nil || !strings.Contains(err.Error(), "#undef") {
			t.Fatalf("expected pkg_a macro poisoning (#undef / BOOT_SECURE_REQUIRE / unguarded CHIP_) to fail, got %v", err)
		}

		// Also verify colliding #define SHARED_HAL_LIMIT across composed package headers independently.
		tmpA := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpA, "a.h"), []byte("#ifndef A_H\n#define A_H\n#define SHARED_HAL_LIMIT 16U\n#endif\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := build.AuditPackageMacros([]string{tmpA, pkgB}, nil); err == nil || !strings.Contains(err.Error(), "colliding header") {
			t.Fatalf("expected colliding header macro across composed packages to fail, got %v", err)
		}
	})

	t.Run("03_init_array_constructor rejected by conformance and elfaudit", func(t *testing.T) {
		fDir := fixtureDir(t, "03_init_array_constructor")
		confRep, err := conformance.AuditPackage(fDir)
		if err != nil {
			t.Fatal(err)
		}
		if confRep.Passed {
			t.Fatal("expected conformance to reject __attribute__((constructor)) / .init_array before stripping")
		}

		elfPath := filepath.Join(t.TempDir(), "ctor.elf")
		writeSyntheticGateELF(t, elfPath,
			[]synthSection{
				{name: ".text", addr: 0x08008000, size: 256, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)},
				{name: ".init_array", addr: 0x08008100, size: 4, flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), typ: uint32(elf.SHT_INIT_ARRAY)},
			},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08008000, paddr: 0x08008000, filesz: 256, memsz: 256}},
			[]synthSym{{name: "boot_main"}, {name: "__stack_chk_fail"}},
		)
		elfRep, err := elfaudit.AuditELF(elfPath, elfaudit.ELFAuditConfig{Profile: elfaudit.ProfileProduction})
		if err != nil {
			t.Fatal(err)
		}
		if elfRep.Passed {
			t.Fatal("expected elfaudit to reject .init_array ELF section")
		}
	})

	t.Run("04_wx_section rejected by elfaudit W^X and literallint bypass checks", func(t *testing.T) {
		fDir := fixtureDir(t, "04_wx_section")
		lintRep, err := literallint.RunLint(literallint.DefaultConfig(fDir))
		if err != nil {
			t.Fatal(err)
		}
		if lintRep.Passed {
			t.Fatal("expected literallint to reject statement-macro & forged string lint-allow bypasses")
		}

		elfPath := filepath.Join(t.TempDir(), "wx.elf")
		writeSyntheticGateELF(t, elfPath,
			[]synthSection{{name: ".text_rw", addr: 0x20001000, size: 128, flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_W | elf.PF_X), vaddr: 0x20001000, paddr: 0x20001000, filesz: 128, memsz: 128}},
			[]synthSym{{name: "boot_main"}},
		)
		elfRep, err := elfaudit.AuditELF(elfPath, elfaudit.ELFAuditConfig{Profile: elfaudit.ProfileProduction})
		if err != nil {
			t.Fatal(err)
		}
		if elfRep.Passed {
			t.Fatal("expected elfaudit to reject W^X PT_LOAD PF_W|PF_X")
		}
	})

	t.Run("05_heap_symbols rejected by elfaudit heap ban", func(t *testing.T) {
		_ = fixtureDir(t, "05_heap_symbols")
		elfPath := filepath.Join(t.TempDir(), "heap.elf")
		writeSyntheticGateELF(t, elfPath,
			[]synthSection{{name: ".text", addr: 0x08008000, size: 256, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08008000, paddr: 0x08008000, filesz: 256, memsz: 256}},
			[]synthSym{{name: "boot_main"}, {name: "malloc"}, {name: "free"}},
		)
		rep, err := elfaudit.AuditELF(elfPath, elfaudit.ELFAuditConfig{Profile: elfaudit.ProfileProduction})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Passed {
			t.Fatal("expected elfaudit to reject malloc/free heap symbols")
		}
	})

	t.Run("06_flash_bounds_overlap rejected by buildrunner gates and elfaudit", func(t *testing.T) {
		fDir := fixtureDir(t, "06_flash_bounds_overlap")
		raw, err := os.ReadFile(filepath.Join(fDir, "bounds.json"))
		if err != nil {
			t.Fatal(err)
		}
		var spec struct {
			BadSegmentLMA  string `json:"bad_segment_lma"`
			BadSegmentSize string `json:"bad_segment_size"`
		}
		if uErr := json.Unmarshal(raw, &spec); uErr != nil {
			t.Fatal(uErr)
		}
		if spec.BadSegmentLMA != "0x08010000" {
			t.Fatalf("unexpected fixture spec: %+v", spec)
		}

		buildDir := t.TempDir()
		writeSyntheticGateELF(t, filepath.Join(buildDir, "toob_stage0.elf"),
			[]synthSection{{name: ".text", addr: 0x08000000, size: 512, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08000000, paddr: 0x08000000, filesz: 512, memsz: 512}},
			[]synthSym{{name: "stage0_main"}},
		)
		// Stage-1 ELF placed into WAL flash [0x08010000..0x08011000).
		writeSyntheticGateELF(t, filepath.Join(buildDir, "toob_stage1.elf"),
			[]synthSection{{name: ".text", addr: 0x08010000, size: 1024, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08010000, paddr: 0x08010000, filesz: 1024, memsz: 1024}},
			[]synthSym{{name: "boot_main"}},
		)

		_, gateErr := buildrunner.RunPostLinkGates(buildrunner.PostLinkGateOptions{
			BuildDir: buildDir,
			Profile:  resolve.ProfileProduction,
			Plan:     &resolve.Plan{},
			ManifestCtx: &manifest.Context{
				Hardware: &manifest.HardwareJson{
					BootromImage: &build.BootromImageSpec{Layout: build.BootromLayoutFlat},
				},
			},
			ManifestResult: &manifest.Result{
				Layout: &manifest.PartitionLayout{
					FlashBase: 0x08000000,
					Stage0:    build.PartitionSlot{Name: "Stage0", Addr: 0x08000000, Budget: 0x8000},
					Stage1A:   build.PartitionSlot{Name: "Stage1A", Addr: 0x08008000, Budget: 0x8000},
					Wal:       build.PartitionSlot{Name: "WAL", Addr: 0x08010000, Budget: 0x4000},
				},
			},
		})
		if gateErr == nil || !strings.Contains(gateErr.Error(), "Forbidden Flash Regions") && !strings.Contains(gateErr.Error(), "Flash LMA Bounds") {
			t.Fatalf("expected buildrunner.RunPostLinkGates to fail on FlashBounds/ForbiddenFlashRegions overlap, got %v", gateErr)
		}
	})

	t.Run("07_stack_blowup_no_ssp rejected by .su budget and SSP checks", func(t *testing.T) {
		fDir := fixtureDir(t, "07_stack_blowup_no_ssp")
		elfPath := filepath.Join(t.TempDir(), "nossp.elf")
		writeSyntheticGateELF(t, elfPath,
			[]synthSection{{name: ".text", addr: 0x08008000, size: 256, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)}},
			[]synthProg{{typ: uint32(elf.PT_LOAD), flags: uint32(elf.PF_R | elf.PF_X), vaddr: 0x08008000, paddr: 0x08008000, filesz: 256, memsz: 256}},
			[]synthSym{{name: "boot_main"}},
		)
		rep, err := elfaudit.AuditELF(elfPath, elfaudit.ELFAuditConfig{
			Profile:        elfaudit.ProfileProduction,
			RequireSSP:     true,
			StackUsageDirs: []string{fDir},
		})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Passed || len(rep.Violations) < 2 {
			t.Fatalf("expected both SSP and .su stack budget checks to fail, got checks=%+v", rep.Checks)
		}
	})

	t.Run("08_hal_contract_violation rejected by conformance", func(t *testing.T) {
		fDir := fixtureDir(t, "08_hal_contract_violation")
		rep, err := conformance.AuditPackage(fDir)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Passed {
			t.Fatal("expected keystore missing mandatory HAL symbols and vendor weak attribute to fail conformance")
		}
	})

	t.Run("09_malicious_compiler_flags rejected by ValidateCompilerFlag and conformance", func(t *testing.T) {
		fDir := fixtureDir(t, "09_malicious_compiler_flags")
		raw, err := os.ReadFile(filepath.Join(fDir, "chip_flags", "evil_flags.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			CompilerFlags build.CompilerFlags `json:"compiler_flags"`
		}
		if jErr := json.Unmarshal(raw, &doc); jErr != nil {
			t.Fatal(jErr)
		}
		if flagErr := build.ValidateCompilerFlags("evil_flags", &doc.CompilerFlags); flagErr == nil {
			t.Fatal("expected ValidateCompilerFlags to reject -D / -I / -Wl,--wrap / -Wl,--allow-multiple-definition")
		}

		tcRep, err := conformance.AuditPackage(filepath.Join(fDir, "toolchain_pkg"))
		if err != nil {
			t.Fatal(err)
		}
		if tcRep.Passed {
			t.Fatal("expected malicious toolchain.cmake to fail conformance")
		}
	})

	t.Run("10_prod_mock_downgrade rejected by build.Load, elfaudit, and CMake production guard", func(t *testing.T) {
		fDir := fixtureDir(t, "10_prod_mock_downgrade")
		hwPath := filepath.Join(t.TempDir(), "hardware.json")
		hwJSON := `{
			"chip_family": "esp32c6",
			"flash": {
				"size": 4194304,
				"write_alignment": 4,
				"app_alignment": 65536,
				"base": "0x0",
				"xip_base": "0x42000000",
				"regions": [{"type": "writable", "base": 0, "sector_size": 4096, "count": 1024}]
			},
			"crypto_capabilities": {
				"aes": {"hw_present": true, "boot_usable": true},
				"ed25519": {"hw_present": false, "boot_usable": false},
				"rng": {"hw_present": true, "boot_usable": true},
				"sha256": {"hw_present": true, "boot_usable": true},
				"pka": {"hw_present": false, "boot_usable": false},
				"arena_size": 32768
			},
			"memory": {"iram_base": "0x40800000", "iram_size": "0x20000"},
			"constants": {"cpu_freq_hz": 160000000}
		}`
		if wErr := os.WriteFile(hwPath, []byte(hwJSON), 0o600); wErr != nil {
			t.Fatal(wErr)
		}
		dt, parseErr := build.ParseToml(filepath.Join(fDir, "device.toml"))
		if parseErr != nil {
			t.Fatalf("ParseToml: %v", parseErr)
		}
		srcDir := t.TempDir()
		outDir := filepath.Join(t.TempDir(), "out")
		ctx, loadErr := build.Load(build.Inputs{
			Device:       dt,
			CoreDir:      filepath.Join(repoRootDir(t), "toobloader", "core"),
			HardwarePath: hwPath,
			SourceDirs:   []string{srcDir},
			OutDir:       outDir,
		}, build.NopLogger{})
		if loadErr != nil {
			t.Fatalf("build.Load unexpected error: %v", loadErr)
		}
		if _, genErr := build.Generate(ctx); genErr == nil || !strings.Contains(genErr.Error(), "build.mock") {
			t.Fatalf("expected production profile + build.mock in device.toml to fail build.Generate, got %v", genErr)
		}

		// Also verify .toob_mock_section in production ELF fails elfaudit poison-pill.
		mockELF := filepath.Join(t.TempDir(), "prod_mock.elf")
		writeSyntheticGateELF(t, mockELF,
			[]synthSection{
				{name: ".text", addr: 0x42008000, size: 256, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), typ: uint32(elf.SHT_PROGBITS)},
				{name: ".toob_mock_section", addr: 0x42008100, size: 4, flags: uint64(elf.SHF_ALLOC), typ: uint32(elf.SHT_PROGBITS)},
			},
			nil,
			[]synthSym{{name: "boot_main"}},
		)
		rep, err := elfaudit.AuditELF(mockELF, elfaudit.ELFAuditConfig{Profile: elfaudit.ProfileProduction})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Passed {
			t.Fatal("expected production ELF containing .toob_mock_section to fail elfaudit")
		}
	})
}
