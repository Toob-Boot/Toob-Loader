package build

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeConsumerSource writes a C file referencing every macro the audit
// requires for ctx, so Generate can pass the consumption audit.
func writeConsumerSource(t *testing.T, ctx *Context) {
	t.Helper()
	cfg, layout := testLayout(t, ctx)
	out, err := renderArtifacts(ctx, cfg, layout, nil)
	if err != nil {
		t.Fatalf("renderArtifacts: %v", err)
	}
	var b strings.Builder
	b.WriteString("#include \"generated_boot_config.h\"\nstatic const unsigned long consumers[] = {\n")
	b.WriteString("    (unsigned long)CHIP_FLASH_IMMUTABLE_BOOT_END,\n")
	for _, m := range out.auditMacros {
		b.WriteString("    (unsigned long)" + m + ",\n")
	}
	b.WriteString("};\n")
	writeTempFile(t, ctx.SourceDirs[0], "consumer.c", b.String())
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestGenerateEndToEnd(t *testing.T) {
	in := writeFixtureInputs(t, testHardware(t))
	log := &recordingLogger{}
	ctx, err := Load(in, log)
	if err != nil {
		t.Fatal(err)
	}
	writeConsumerSource(t, ctx)
	writeTempFile(t, in.OutDir, "generated_platform_wiring.inc", "obsolete")

	res, err := Generate(ctx)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if res.Config.Transport != TransportPointer || res.Layout.Stage0.Addr != 0x40000 {
		t.Errorf("unexpected result: transport=%s stage0=0x%X", res.Config.Transport, res.Layout.Stage0.Addr)
	}

	want := []string{
		fileBootConfig, fileChipConfig, fileBootLayout, fileLayoutAssert, fileMemoryLD,
		fileStage0LD, fileFlashLD, fileFlashStage1BLD, fileRecoveryLD, fileResetCauses, filePlatformWiring, fileProvenanceReport,
	}
	slices.Sort(want)
	got := listDir(t, in.OutDir)
	if !slices.Equal(got, want) {
		t.Errorf("output directory mismatch:\n got  %v\n want %v", got, want)
	}
	resNames := slices.Sorted(slices.Values(res.Artifacts))
	if !slices.Equal(resNames, want) {
		t.Errorf("Result.Artifacts mismatch: %v", resNames)
	}
	if !slices.ContainsFunc(log.infos, func(s string) bool { return strings.Contains(s, "Auto-selected transport provider 'pointer'") }) {
		t.Error("expected the transport auto-selection to be logged")
	}
	if !slices.ContainsFunc(log.warns, func(s string) bool { return strings.Contains(s, "'Stage 0' skipped") }) {
		t.Errorf("expected the reserved-region gap warning, got %v", log.warns)
	}

	// A second run with unchanged inputs must reproduce identical output.
	before, err := os.ReadFile(filepath.Join(in.OutDir, fileBootConfig))
	if err != nil {
		t.Fatal(err)
	}
	if _, gErr := Generate(ctx); gErr != nil {
		t.Fatalf("second Generate failed: %v", gErr)
	}
	after, err := os.ReadFile(filepath.Join(in.OutDir, fileBootConfig))
	if err != nil || !bytes.Equal(before, after) {
		t.Error("generation must be deterministic")
	}
}

func TestGenerateFailsOnUnconsumedMacros(t *testing.T) {
	ctx, err := Load(writeFixtureInputs(t, testHardware(t)), NopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(ctx); err == nil || !strings.Contains(err.Error(), "NEVER referenced") {
		t.Fatalf("expected the macro audit to fail, got %v", err)
	}
	if _, statErr := os.Stat(ctx.OutDir); !os.IsNotExist(statErr) {
		t.Errorf("a failed audit must not create any output, stat err = %v", statErr)
	}
}

func TestGenerateRemovesStaleWiringWithoutDrivers(t *testing.T) {
	in := writeFixtureInputs(t, testHardware(t))
	in.DriverDirs = nil
	log := &recordingLogger{}
	ctx, err := Load(in, log)
	if err != nil {
		t.Fatal(err)
	}
	writeConsumerSource(t, ctx)
	writeTempFile(t, in.OutDir, filePlatformWiring, "/* stale */")

	if _, err := Generate(ctx); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(in.OutDir, filePlatformWiring)); !os.IsNotExist(err) {
		t.Error("stale platform wiring must be removed")
	}
	if !slices.ContainsFunc(log.warns, func(s string) bool { return strings.Contains(s, "No driver manifests bound") }) {
		t.Errorf("expected a warning about the skipped wiring, got %v", log.warns)
	}
}

func TestGenerateRenderFailureWritesNothing(t *testing.T) {
	hw := testHardware(t)
	delete(hw.Constants, "flash_erased_byte")
	ctx, err := Load(writeFixtureInputs(t, hw), NopLogger{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = Generate(ctx)
	if err == nil || !strings.Contains(err.Error(), "CHIP_FLASH_ERASED_BYTE") {
		t.Fatalf("expected a missing wiring macro error, got %v", err)
	}
	if _, statErr := os.Stat(ctx.OutDir); !os.IsNotExist(statErr) {
		t.Errorf("a render failure must not create any output, stat err = %v", statErr)
	}
}

func TestGenerateProvenanceFailureWritesOnlyReport(t *testing.T) {
	hw := testHardware(t)
	hw.ResetCauses.Codes[0].Class = "watchdog" // RST-003
	ctx, err := Load(writeFixtureInputs(t, hw), NopLogger{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = Generate(ctx)
	if err == nil || !strings.Contains(err.Error(), "FATAL [PROVENANCE]") || !strings.Contains(err.Error(), "RST-003") {
		t.Fatalf("expected a provenance failure naming RST-003, got %v", err)
	}
	if got := listDir(t, ctx.OutDir); !slices.Equal(got, []string{fileProvenanceReport}) {
		t.Errorf("expected only the provenance report, got %v", got)
	}
}

func TestVerifyProvenanceWarnsOnUnverifiedSources(t *testing.T) {
	ctx := testContext(t)
	log := &recordingLogger{}
	ctx.Log = log
	ctx.Hardware.Flash.Regions[1].Provenance = &Provenance{Source: "scan", Ref: "toobfuzzer", Verified: "2026-01-15"}

	if _, err := verifyProvenance(ctx); err != nil {
		t.Fatalf("scan sources are allowed but unverified, got %v", err)
	}
	if !slices.ContainsFunc(log.warns, func(s string) bool { return strings.Contains(s, "PROVENANCE_UNVERIFIED") }) {
		t.Errorf("expected an unverified provenance warning, got %v", log.warns)
	}
}

func TestGenerateNilContext(t *testing.T) {
	if _, err := Generate(nil); err == nil {
		t.Fatal("expected an error for a nil context")
	}
}

func TestCheckUniqueMacros(t *testing.T) {
	a, b := newCFile(), newCFile()
	a.define("CHIP_SHARED", "1U")
	b.define("CHIP_OTHER", "1U")
	if err := checkUniqueMacros([]namedSource{{"a.h", a}, {"b.h", b}}); err != nil {
		t.Fatalf("distinct macros must pass, got %v", err)
	}

	b.define("CHIP_SHARED", "2U")
	err := checkUniqueMacros([]namedSource{{"a.h", a}, {"b.h", b}})
	if err == nil || !strings.Contains(err.Error(), "CHIP_SHARED is defined by both a.h and b.h") {
		t.Fatalf("expected a cross-source collision, got %v", err)
	}
}

func TestRenderArtifactsRejectsCrossSourceMacroCollision(t *testing.T) {
	ctx := testContext(t)
	// Collides with CHIP_RST_CLASS_POWER from generated_reset_causes.h.
	ctx.Hardware.ResetCauses.Codes = append(ctx.Hardware.ResetCauses.Codes,
		ResetCauseCode{Name: "class_power", Value: 200, Class: "power"})
	cfg, layout := testLayout(t, ctx)

	_, err := renderArtifacts(ctx, cfg, layout, nil)
	if err == nil || !strings.Contains(err.Error(), "CHIP_RST_CLASS_POWER is defined by both") {
		t.Fatalf("expected a cross-source collision, got %v", err)
	}
}

func TestGenerateIgnoresCommentOnlyConsumers(t *testing.T) {
	in := writeFixtureInputs(t, testHardware(t))
	ctx, err := Load(in, NopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	writeConsumerSource(t, ctx)
	consumer := filepath.Join(in.SourceDirs[0], "consumer.c")
	data, err := os.ReadFile(consumer)
	if err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, in.SourceDirs[0], "consumer.c", "/*\n"+strings.ReplaceAll(string(data), "*/", "* /")+"*/\n")

	if _, err := Generate(ctx); err == nil || !strings.Contains(err.Error(), "NEVER referenced") {
		t.Fatalf("macros referenced only inside comments must fail the audit, got %v", err)
	}
}
