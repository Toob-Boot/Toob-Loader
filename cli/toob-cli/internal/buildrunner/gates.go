package buildrunner

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/toob-boot/toob/internal/elfaudit"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/resolve"
)

// PostLinkGateOptions configures post-link BootROM packing, partition budget
// enforcement, and fail-closed ELF security audits.
type PostLinkGateOptions struct {
	BuildDir       string
	PackagesDir    string
	Profile        string
	Plan           *resolve.Plan
	Device         *manifest.DeviceToml
	ManifestCtx    *manifest.Context
	ManifestResult *manifest.Result
	Stage0Only     bool
}

// PostLinkResult summarizes verified binaries, budget reports, and ELF audits.
type PostLinkResult struct {
	Stage0BinPath string
	Budgets       []*manifest.BudgetReport
	AuditReports  []*elfaudit.ELFAuditReport
}

// RunPostLinkGates executes Stage-0 BootROM image packing, partition budget
// enforcement, and fail-closed ELF security audits across all built stages.
func RunPostLinkGates(opts PostLinkGateOptions) (*PostLinkResult, error) {
	if strings.TrimSpace(opts.BuildDir) == "" {
		return nil, errors.New("post-link gates: BuildDir is required")
	}
	if opts.Plan == nil {
		return nil, errors.New("post-link gates: Plan is required")
	}
	if opts.ManifestResult == nil || opts.ManifestResult.Layout == nil {
		return nil, errors.New("post-link gates: ManifestResult.Layout is required")
	}

	layout := opts.ManifestResult.Layout
	auditProfile := elfaudit.ProfileProduction
	if strings.EqualFold(strings.TrimSpace(opts.Profile), resolve.ProfileDev) {
		auditProfile = elfaudit.ProfileDev
	}

	var hw *manifest.HardwareJson
	if opts.ManifestCtx != nil {
		hw = opts.ManifestCtx.Hardware
	}
	reservedRAM, err := parseReservedRAMRegions(hw)
	if err != nil {
		return nil, err
	}

	packagesDir := resolvePackagesDir(opts)
	out := &PostLinkResult{}

	stage0ELF, err := requireBuildArtifact(opts.BuildDir, "toob_stage0", "toob_stage0.elf")
	if err != nil {
		return nil, fmt.Errorf("stage0 post-link gate: %w", err)
	}

	packed, err := packStage0Image(stage0ELF, hw, opts.Plan.Chip.HardwarePath, packagesDir)
	if err != nil {
		return nil, fmt.Errorf("pack Stage-0 BootROM image: %w", err)
	}

	stage0Bin := filepath.Join(opts.BuildDir, "toob_stage0.bin")
	if writeErr := build.WriteFileAtomic(stage0Bin, packed); writeErr != nil {
		return nil, fmt.Errorf("write %s: %w", stage0Bin, writeErr)
	}
	out.Stage0BinPath = stage0Bin

	s0Budget, err := manifest.CheckBudgetWithLayout(layout, stage0Bin, "stage0")
	if err != nil {
		return nil, err
	}
	out.Budgets = append(out.Budgets, s0Budget)

	hasSU := hasStackUsageArtifacts(opts.BuildDir)
	s0Cfg := newStageAuditConfig(opts.BuildDir, "toob_stage0", "stage0", auditProfile, reservedRAM, layout, hw, uint64(layout.Stage0.Budget), hasSU)
	s0Report, err := auditELFStrict(stage0ELF, s0Cfg)
	if err != nil {
		return nil, fmt.Errorf("stage0 ELF audit: %w", err)
	}
	out.AuditReports = append(out.AuditReports, s0Report)

	if opts.Stage0Only {
		return out, nil
	}

	if err := runStage1AndRecoveryGates(opts, layout, hw, auditProfile, reservedRAM, hasSU, out); err != nil {
		return nil, err
	}
	return out, nil
}

func runStage1AndRecoveryGates(
	opts PostLinkGateOptions,
	layout *manifest.PartitionLayout,
	hw *manifest.HardwareJson,
	auditProfile string,
	reservedRAM []elfaudit.MemoryRegion,
	hasSU bool,
	out *PostLinkResult,
) error {
	stage1ELF, err := requireBuildArtifact(opts.BuildDir, "toob_stage1", "toob_stage1.elf")
	if err != nil {
		return fmt.Errorf("stage1 post-link gate: %w", err)
	}

	s1Cfg := newStageAuditConfig(opts.BuildDir, "toob_stage1", "stage1a", auditProfile, reservedRAM, layout, hw, uint64(layout.Stage1A.Budget), hasSU)
	s1Report, err := auditELFStrict(stage1ELF, s1Cfg)
	if err != nil {
		return fmt.Errorf("stage1 ELF audit: %w", err)
	}
	out.AuditReports = append(out.AuditReports, s1Report)

	if s1Bin := findBuildArtifact(opts.BuildDir, "toob_stage1.bin"); s1Bin != "" {
		rep, budgetErr := manifest.CheckBudgetWithLayout(layout, s1Bin, "stage1")
		if budgetErr != nil {
			return budgetErr
		}
		out.Budgets = append(out.Budgets, rep)
	}

	stage1bELF := findBuildArtifact(opts.BuildDir, "toob_stage1b", "toob_stage1b.elf")
	if layout.Stage1B.Budget > 0 && stage1bELF == "" {
		return errors.New("stage1b partition budgeted in layout, but toob_stage1b ELF artifact is missing")
	}
	if stage1bELF != "" {
		budget := layout.Stage1B.Budget
		if budget == 0 {
			budget = layout.Stage1A.Budget
		}
		s1bCfg := newStageAuditConfig(opts.BuildDir, "toob_stage1b", "stage1b", auditProfile, reservedRAM, layout, hw, uint64(budget), hasSU)
		s1bReport, s1bErr := auditELFStrict(stage1bELF, s1bCfg)
		if s1bErr != nil {
			return fmt.Errorf("stage1b ELF audit: %w", s1bErr)
		}
		out.AuditReports = append(out.AuditReports, s1bReport)

		if layout.Stage1B.Budget > 0 {
			if s1bBin := findBuildArtifact(opts.BuildDir, "toob_stage1b.bin"); s1bBin != "" {
				rep, budgetErr := manifest.CheckBudgetWithLayout(layout, s1bBin, "stage1b")
				if budgetErr != nil {
					return budgetErr
				}
				out.Budgets = append(out.Budgets, rep)
			}
		}
	}

	recoveryRequired := opts.Plan.Recovery.Declared && opts.Device != nil && opts.Device.Partitions.RecoverySize > 0
	recELF := findBuildArtifact(opts.BuildDir, "toob_recovery", "toob_recovery.elf")
	if recoveryRequired && recELF == "" {
		return errors.New("recovery OS declared and recovery_size > 0, but toob_recovery ELF artifact is missing")
	}
	if recELF != "" {
		recCfg := newStageAuditConfig(opts.BuildDir, "toob_recovery", "recovery", auditProfile, reservedRAM, layout, hw, uint64(layout.Recovery.Budget), hasSU)
		recReport, recErr := auditELFStrict(recELF, recCfg)
		if recErr != nil {
			return fmt.Errorf("recovery ELF audit: %w", recErr)
		}
		out.AuditReports = append(out.AuditReports, recReport)
	}

	if recoveryRequired {
		recBin, recBinErr := requireBuildArtifact(opts.BuildDir, "toob_recovery.bin", "toob_recovery.raw.bin")
		if recBinErr != nil {
			return fmt.Errorf("recovery OS declared and recovery_size > 0: %w", recBinErr)
		}
		rep, budgetErr := manifest.CheckBudgetWithLayout(layout, recBin, "recovery")
		if budgetErr != nil {
			return budgetErr
		}
		out.Budgets = append(out.Budgets, rep)
	}

	return nil
}

func auditELFStrict(elfPath string, cfg elfaudit.ELFAuditConfig) (*elfaudit.ELFAuditReport, error) {
	rep, err := elfaudit.AuditELF(elfPath, cfg)
	if err != nil {
		return nil, err
	}
	if rep == nil {
		return nil, fmt.Errorf("ELF audit of %s returned nil report", elfPath)
	}
	if !rep.Passed {
		return rep, formatAuditFailures(elfPath, rep)
	}
	return rep, nil
}

func formatAuditFailures(elfPath string, rep *elfaudit.ELFAuditReport) error {
	var msgs []string
	for _, v := range rep.Violations {
		msgs = append(msgs, fmt.Sprintf("%s (%s)", v.Name, v.Details))
	}
	if len(msgs) == 0 {
		for _, c := range rep.Checks {
			if !c.Passed {
				msgs = append(msgs, fmt.Sprintf("%s (%s)", c.Name, c.Details))
			}
		}
	}
	if len(msgs) == 0 {
		msgs = append(msgs, "unknown violation")
	}
	return fmt.Errorf("ELF security audit failed for %s: %s", filepath.Base(elfPath), strings.Join(msgs, "; "))
}

func packStage0Image(elfPath string, hw *manifest.HardwareJson, hardwareJSONPath, packagesDir string) ([]byte, error) {
	if hw != nil {
		return manifest.PackStage0ELFWithPackagesDir(elfPath, hw, packagesDir)
	}
	if strings.TrimSpace(hardwareJSONPath) != "" {
		return manifest.PackStage0FromHardwareJSON(elfPath, hardwareJSONPath)
	}
	return nil, errors.New("neither loaded HardwareJson nor Chip.HardwarePath is available for Stage-0 packing")
}

func resolvePackagesDir(opts PostLinkGateOptions) string {
	if strings.TrimSpace(opts.PackagesDir) != "" {
		return opts.PackagesDir
	}
	if opts.ManifestCtx != nil && strings.TrimSpace(opts.ManifestCtx.HalRoot) != "" {
		return opts.ManifestCtx.HalRoot
	}
	if opts.Plan != nil && strings.TrimSpace(opts.Plan.HalRoot) != "" {
		return opts.Plan.HalRoot
	}
	if opts.Plan != nil && strings.TrimSpace(opts.Plan.Chip.HardwarePath) != "" {
		return filepath.Dir(filepath.Dir(filepath.Dir(opts.Plan.Chip.HardwarePath)))
	}
	return ""
}

func isSegmentedBootrom(hw *manifest.HardwareJson) bool {
	return hw != nil && hw.BootromImage != nil && strings.EqualFold(strings.TrimSpace(hw.BootromImage.Layout), build.BootromLayoutSegmented)
}

func parseReservedRAMRegions(hw *manifest.HardwareJson) ([]elfaudit.MemoryRegion, error) {
	if hw == nil || len(hw.ReservedRamRegions) == 0 {
		return nil, nil
	}
	regions := make([]elfaudit.MemoryRegion, 0, len(hw.ReservedRamRegions))
	for _, r := range hw.ReservedRamRegions {
		base, err := build.ParseU64Literal(r.Base)
		if err != nil {
			return nil, fmt.Errorf("parse reserved RAM region %q base %q: %w", r.Name, r.Base, err)
		}
		regions = append(regions, elfaudit.MemoryRegion{
			Name: r.Name,
			Base: base,
			Size: uint64(r.Size),
		})
	}
	return regions, nil
}

func requireBuildArtifact(buildDir string, names ...string) (string, error) {
	if found := findBuildArtifact(buildDir, names...); found != "" {
		return found, nil
	}
	return "", fmt.Errorf("missing expected build artifact (%s) in %s", strings.Join(names, " or "), buildDir)
}

func findBuildArtifact(buildDir string, names ...string) string {
	for _, name := range names {
		p := filepath.Join(buildDir, name)
		if isRegularFile(p) {
			return p
		}
	}
	return ""
}

func newStageAuditConfig(
	buildDir, targetName, stageKey, auditProfile string,
	reservedRAM []elfaudit.MemoryRegion,
	layout *manifest.PartitionLayout,
	hw *manifest.HardwareJson,
	budgetBytes uint64,
	hasSU bool,
) elfaudit.ELFAuditConfig {
	flashBounds, forbidden := stageFlashBoundsAndForbidden(layout, hw, stageKey)
	cfg := elfaudit.ELFAuditConfig{
		Profile:               auditProfile,
		ReservedRegions:       reservedRAM,
		FlashBounds:           flashBounds,
		ForbiddenFlashRegions: forbidden,
		Stage1MaxBytes:        budgetBytes,
		SegmentedBootrom:      stageKey == "stage0" && isSegmentedBootrom(hw),
		AllowRecoveryRuntime:  stageKey == "recovery",
	}
	if mapPath := findBuildArtifact(buildDir, targetName+".map"); mapPath != "" {
		cfg.MapPath = mapPath
		cfg.RequireSSP = true
	}
	if hasSU {
		cfg.StackUsageDirs = stackUsageDirsForTarget(buildDir, targetName)
		cfg.MaxStackBytes = stackBudgetForStage(auditProfile)
		cfg.RequireSSP = true
	}
	return cfg
}

func stackBudgetForStage(auditProfile string) uint64 {
	if auditProfile == elfaudit.ProfileProduction {
		return elfaudit.DefaultMaxStackBytesProduction
	}
	return elfaudit.DefaultMaxStackBytesDev
}

func stackUsageDirsForTarget(buildDir, targetName string) []string {
	cmakeDir := filepath.Join(buildDir, "CMakeFiles")
	var targetSubdirs []string
	switch targetName {
	case "toob_stage0":
		targetSubdirs = []string{
			"toob_stage0.dir", "toob_chip.dir", "toob_crypto.dir",
			"toob_crypto_upstream.dir", "toob_arch.dir",
		}
	case "toob_stage1", "toob_stage1b":
		targetSubdirs = []string{
			"toob_stage1_entry.dir", "toob_stage1.dir", "toob_stage1b.dir",
			"toob_core.dir", "toob_chip.dir", "toob_crypto.dir",
			"toob_crypto_upstream.dir", "toob_heatshrink.dir", "toob_utils.dir", "toob_arch.dir",
		}
	case "toob_recovery":
		targetSubdirs = []string{
			"toob_recovery.dir", "toob_libtoob.dir", "toob_chip.dir",
			"toob_arch.dir", "toob_recovery_crypto.dir", "toob_recovery_crypto_upstream.dir",
		}
	}

	var dirs []string
	for _, sub := range targetSubdirs {
		cand := filepath.Join(cmakeDir, sub)
		if isDir(cand) {
			dirs = append(dirs, cand)
		}
	}
	if len(dirs) > 0 {
		return dirs
	}
	return []string{buildDir}
}

func isRAMExecStage0(hw *manifest.HardwareJson) bool {
	if hw == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(hw.Flash.Stage0ExecMode), "ram") {
		return true
	}
	return isSegmentedBootrom(hw)
}

func slotExecRegion(slot build.PartitionSlot, windowBase, execBase uint64) elfaudit.MemoryRegion {
	if slot.Budget == 0 {
		return elfaudit.MemoryRegion{}
	}
	rel := uint64(slot.Addr)
	if rel >= windowBase {
		rel -= windowBase
	}
	return elfaudit.MemoryRegion{
		Name: slot.Name,
		Base: execBase + rel,
		Size: uint64(slot.Budget),
	}
}

func stageFlashBoundsAndForbidden(
	layout *manifest.PartitionLayout,
	hw *manifest.HardwareJson,
	stageKey string,
) (*elfaudit.MemoryRegion, []elfaudit.MemoryRegion) {
	if layout == nil {
		return nil, nil
	}
	execBase := cmp.Or(layout.XipBaseVal, layout.FlashBase)
	winBase := layout.FlashBase

	namedSlots := []struct {
		key  string
		slot build.PartitionSlot
	}{
		{"stage0", layout.Stage0},
		{"stage1a", layout.Stage1A},
		{"stage1b", layout.Stage1B},
		{"app", layout.App},
		{"staging", layout.Staging},
		{"scratch", layout.Scratch},
		{"wal", layout.Wal},
		{"recovery", layout.Recovery},
		{"netcore", layout.NetCore},
		{"kdm", layout.KDM},
		{"cloudcmd", layout.CloudCmd},
		{"mailbox", layout.Mailbox},
		{"forensic", layout.Forensic},
	}

	var flashBounds *elfaudit.MemoryRegion
	for _, entry := range namedSlots {
		if entry.key == stageKey && entry.slot.Budget > 0 {
			if stageKey == "stage0" && isRAMExecStage0(hw) {
				break
			}
			reg := slotExecRegion(entry.slot, winBase, execBase)
			flashBounds = &reg
			break
		}
	}
	if stageKey == "recovery" && flashBounds == nil && layout.App.Budget > 0 {
		reg := slotExecRegion(layout.App, winBase, execBase)
		flashBounds = &reg
	}

	var forbidden []elfaudit.MemoryRegion
	for _, entry := range namedSlots {
		if entry.slot.Budget == 0 {
			continue
		}
		if entry.key == stageKey {
			continue
		}
		if stageKey == "recovery" && layout.Recovery.Budget == 0 && entry.key == "app" {
			continue
		}
		reg := slotExecRegion(entry.slot, winBase, execBase)
		if flashBounds != nil && reg.Base == flashBounds.Base && reg.Size == flashBounds.Size {
			continue
		}
		forbidden = append(forbidden, reg)
	}
	for _, res := range layout.Reserved {
		if res.Budget == 0 {
			continue
		}
		forbidden = append(forbidden, slotExecRegion(res, winBase, execBase))
	}
	return flashBounds, forbidden
}

func hasStackUsageArtifacts(buildDir string) bool {
	if strings.TrimSpace(buildDir) == "" {
		return false
	}
	found := false
	_ = filepath.WalkDir(buildDir, func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(d.Name()), ".su") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}
