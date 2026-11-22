package build

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// Result summarizes a successful build.
type Result struct {
	Config    *ResolvedConfig
	Layout    *PartitionLayout
	Artifacts []string // File names written to OutDir.
}

// Generate runs the manifest pipeline on a loaded context:
//
//	resolve config -> verify provenance -> plan layout -> render -> audit -> write
func Generate(ctx *Context) (*Result, error) {
	if ctx == nil {
		return nil, errors.New("build.Generate: context must not be nil")
	}
	if ctx.Device == nil {
		return nil, errors.New("build.Generate: Context.Device must not be nil")
	}
	if ctx.Hardware == nil {
		return nil, errors.New("build.Generate: Context.Hardware must not be nil")
	}
	if strings.TrimSpace(ctx.OutDir) == "" {
		return nil, errors.New("build.Generate: Context.OutDir must not be empty")
	}
	log := ctx.Log
	if log == nil {
		log = NopLogger{}
		ctx.Log = log
	}

	cfg, err := resolveConfig(ctx)
	if err != nil {
		return nil, err
	}

	report, err := verifyProvenance(ctx)
	if err != nil {
		return nil, err
	}

	layout, err := planLayout(ctx.Device, ctx.Hardware, cfg)
	if err != nil {
		return nil, err
	}
	for _, g := range layout.Gaps {
		log.Warn("Allocation for '%s' skipped %d bytes of flash at 0x%08X (reserved region / alignment).",
			g.Partition, g.Size, g.From)
	}
	for _, r := range ctx.Hardware.ReservedRamRegions {
		log.Info("  Reserved RAM: %-20s at %s (%d bytes) — %s", r.Name, r.Base, r.Size, r.Description)
	}

	out, err := renderArtifacts(ctx, cfg, layout, report)
	if err != nil {
		return nil, err
	}

	log.Step("Validating macro consumption in C code...")
	if err := auditMacroUsage(out.auditMacros, ctx.SourceDirs, ctx.OutDir); err != nil {
		return nil, err
	}
	log.Success("All generated macros are perfectly synchronized with the C code!")

	if err := writeArtifacts(ctx.OutDir, out.artifacts); err != nil {
		return nil, fmt.Errorf("failed to write generated artifacts: %w", err)
	}
	if err := removeStaleArtifacts(ctx.OutDir, out.artifacts); err != nil {
		return nil, err
	}
	log.Success("Manifest Compiler (Go Native): Successfully generated headers and ld scripts to %s", ctx.OutDir)

	names := make([]string, len(out.artifacts))
	for i, a := range out.artifacts {
		names[i] = a.name
	}
	return &Result{Config: cfg, Layout: layout, Artifacts: names}, nil
}

// verifyProvenance audits hardware provenance and runs the plausibility checks.
// On failure it purges stale generated headers, persists the report as evidence, and aborts.
func verifyProvenance(ctx *Context) ([]byte, error) {
	hw := ctx.Hardware
	items := AuditProvenance(hw)
	isProd := ctx.Device != nil && ctx.Device.Build.Profile == "production"
	var unverifiedProd []string
	for _, item := range items {
		if item.Unverified() {
			if isProd {
				unverifiedProd = append(unverifiedProd, fmt.Sprintf("  [FAIL] PROVENANCE_UNVERIFIED: %s '%s' (%s)", item.Category, item.Name, item.Status))
			} else {
				ctx.Log.Warn("WARNING [PROVENANCE_UNVERIFIED]: Hardware constant '%s' (%s) relies on unverified scan source (ref: %s)",
					item.Name, item.Category, item.Ref)
			}
		}
	}

	results := VerifyHardwareProvenance(hw)
	for _, r := range results {
		if r.Passed && r.Warning {
			ctx.Log.Warn("WARNING [PROVENANCE]: %s: %s — %s", r.Check, r.Name, r.Details)
		}
	}
	report, err := renderProvenanceReportWithRaw(hw, ctx.HardwareRaw, items, results)
	if err != nil {
		return nil, err
	}
	if !HasVerificationFailures(results) && len(unverifiedProd) == 0 {
		return report, nil
	}

	var reasons []string
	if len(unverifiedProd) > 0 {
		reasons = append(reasons, strings.Join(unverifiedProd, "\n"))
	}
	if HasVerificationFailures(results) {
		reasons = append(reasons, FormatVerificationErrors(results))
	}
	verifyErr := fmt.Errorf("FATAL [PROVENANCE]: Hardware plausibility verification failed:\n%s",
		strings.Join(reasons, "\n"))
	purgeGeneratedCodeArtifacts(ctx.OutDir)
	if err := writeArtifacts(ctx.OutDir, []artifact{{fileProvenanceReport, report}}); err != nil {
		return nil, errors.Join(verifyErr, fmt.Errorf("failed to write %s: %w", fileProvenanceReport, err))
	}
	return nil, fmt.Errorf("%w\nSee %s", verifyErr, filepath.Join(ctx.OutDir, fileProvenanceReport))
}

// renderedOutput is the complete in-memory result of the render stage.
type renderedOutput struct {
	artifacts   []artifact
	auditMacros []string // Config macros that C sources must consume.
}

// namedSource pairs a rendered source with its output file name.
type namedSource struct {
	name string
	src  *cSource
}

// renderArtifacts renders every output file without touching the file system.
func renderArtifacts(ctx *Context, cfg *ResolvedConfig, layout *PartitionLayout, report []byte) (*renderedOutput, error) {
	config, err := renderBootConfig(ctx, cfg, layout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileBootConfig, err)
	}
	bootLayout := renderBootLayout(layout)

	sources := []namedSource{
		{fileBootConfig, config},
		{fileChipConfig, renderChipConfigShim()},
		{fileBootLayout, bootLayout},
		{fileLayoutAssert, renderLayoutAsserts(cfg, ctx.Hardware, layout)},
		{fileMemoryLD, renderMemoryLD(ctx, cfg, layout)},
		{fileStage0LD, renderStage0LDForContext(ctx, ctx.Hardware)},
		{fileFlashLD, renderFlashLD(ctx, cfg, layout)},
	}
	if layout.Stage1B.Budget > 0 {
		sources = append(sources, namedSource{fileFlashStage1BLD, renderFlashStage1BLD(ctx, cfg, layout)})
	}
	sources = append(sources, namedSource{fileRecoveryLD, renderRecoveryLD(ctx, cfg, layout)})

	available := slices.Concat(config.defines, bootLayout.defines)
	if rc := ctx.Hardware.ResetCauses; rc != nil && len(rc.Codes) > 0 {
		resetSrc, rErr := renderResetCauses(rc)
		if rErr != nil {
			return nil, fmt.Errorf("%s: %w", fileResetCauses, rErr)
		}
		sources = append(sources, namedSource{fileResetCauses, resetSrc})
		available = append(available, resetSrc.defines...)
	}

	auditList := auditableMacros(config.defines)
	out := &renderedOutput{}
	for _, s := range sources {
		data, fErr := s.src.finish()
		if fErr != nil {
			return nil, fmt.Errorf("%s: %w", s.name, fErr)
		}
		out.artifacts = append(out.artifacts, artifact{s.name, data})
	}
	if uErr := checkUniqueMacros(sources); uErr != nil {
		return nil, uErr
	}

	wiring, wiringConsumed, err := renderWiringArtifact(ctx, available)
	if err != nil {
		return nil, err
	}
	if wiring != nil {
		out.artifacts = append(out.artifacts, *wiring)
		if len(wiringConsumed) > 0 {
			auditList = slices.DeleteFunc(auditList, func(m string) bool {
				return slices.Contains(wiringConsumed, m)
			})
		}
	}
	out.auditMacros = auditList

	out.artifacts = append(out.artifacts, artifact{fileProvenanceReport, report})
	return out, nil
}

// checkUniqueMacros rejects a macro that is defined by more than one generated
// source. Duplicates inside one source are caught by cSource itself.
func checkUniqueMacros(sources []namedSource) error {
	owner := make(map[string]string)
	for _, s := range sources {
		for m := range s.src.seen {
			if prev, dup := owner[m]; dup && prev != s.name {
				return fmt.Errorf("FATAL: macro %s is defined by both %s and %s", m, prev, s.name)
			}
			owner[m] = s.name
		}
	}
	return nil
}

// renderWiringArtifact renders the platform wiring if drivers are bound and
// checks that every macro it references is actually generated.
func renderWiringArtifact(ctx *Context, available []string) (*artifact, []string, error) {
	if len(ctx.Drivers) == 0 {
		ctx.Log.Warn("No driver manifests bound; skipping %s", filePlatformWiring)
		return nil, nil, nil
	}
	data, required, consumed, err := renderPlatformWiringWithConsumed(ctx)
	if err != nil {
		return nil, nil, err
	}
	var missing []string
	for _, m := range required {
		if !slices.Contains(available, m) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("FATAL: %s references macros that hardware.json does not define: %s",
			filePlatformWiring, strings.Join(missing, ", "))
	}
	return &artifact{filePlatformWiring, data}, consumed, nil
}
