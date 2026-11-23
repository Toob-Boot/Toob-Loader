package cmd

import (
	"cmp"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	build "github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"

	"github.com/toob-boot/toob/internal/elfaudit"
	"github.com/toob-boot/toob/internal/ui"
)

func newELFAuditCmd() *cobra.Command {
	var (
		elfPath        string
		profile        string
		hardwarePath   string
		budget         string
		mapPath        string
		sramBase       string
		sramSize       string
		flashBase      string
		flashSize      string
		stage1MaxBytes string
		reportPath     string
	)

	c := &cobra.Command{
		Use:    "elfaudit [elf-path]",
		Short:  "Audit ELF sections, entrypoints, and memory placement against target limits",
		Hidden: true,
		Args:   cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			targetELF := strings.TrimSpace(elfPath)
			if targetELF == "" && len(args) > 0 {
				targetELF = strings.TrimSpace(args[0])
			}
			if targetELF == "" {
				return errors.New("ELF path is required via --elf or positional argument")
			}

			var auditProfile string
			switch strings.ToLower(strings.TrimSpace(profile)) {
			case elfaudit.ProfileProduction:
				auditProfile = elfaudit.ProfileProduction
			case elfaudit.ProfileDev:
				auditProfile = elfaudit.ProfileDev
			default:
				return fmt.Errorf("invalid --profile %q: must be %q or %q", profile, elfaudit.ProfileDev, elfaudit.ProfileProduction)
			}

			sBase, err := parseAuditRegionU64(sramBase, "sram-base")
			if err != nil {
				return err
			}
			sSize, err := parseAuditRegionU64(sramSize, "sram-size")
			if err != nil {
				return err
			}
			fBase, err := parseAuditRegionU64(flashBase, "flash-base")
			if err != nil {
				return err
			}
			fSize, err := parseAuditRegionU64(flashSize, "flash-size")
			if err != nil {
				return err
			}
			budgetRaw := cmp.Or(strings.TrimSpace(stage1MaxBytes), strings.TrimSpace(budget))
			maxBytes, err := parseAuditRegionU64(budgetRaw, "budget")
			if err != nil {
				return err
			}

			cfg := elfaudit.ELFAuditConfig{
				Profile:              auditProfile,
				Stage1MaxBytes:       maxBytes,
				AllowRecoveryRuntime: strings.Contains(strings.ToLower(filepath.Base(targetELF)), "recovery"),
			}
			if strings.TrimSpace(mapPath) != "" {
				cfg.MapPath = filepath.Clean(mapPath)
			}
			if fSize > 0 {
				cfg.FlashBounds = &elfaudit.MemoryRegion{Name: "flash", Base: fBase, Size: fSize}
			}
			if sSize > 0 {
				cfg.ReservedRegions = append(cfg.ReservedRegions, elfaudit.MemoryRegion{
					Name: "sram-reserved",
					Base: sBase,
					Size: sSize,
				})
			}
			if strings.TrimSpace(hardwarePath) != "" {
				hw, hwErr := build.ParseHardwareJSON(filepath.Clean(hardwarePath))
				if hwErr != nil {
					return fmt.Errorf("parse --hardware %s: %w", sanitizeDisplay(hardwarePath), hwErr)
				}
				for _, r := range hw.ReservedRamRegions {
					rBase, baseErr := build.ParseU64Literal(r.Base)
					if baseErr != nil {
						return fmt.Errorf("parse reserved RAM region %q base %q: %w", r.Name, r.Base, baseErr)
					}
					cfg.ReservedRegions = append(cfg.ReservedRegions, elfaudit.MemoryRegion{
						Name: r.Name,
						Base: rBase,
						Size: uint64(r.Size),
					})
				}
				if hw.BootromImage != nil &&
					strings.EqualFold(strings.TrimSpace(hw.BootromImage.Layout), build.BootromLayoutSegmented) &&
					strings.Contains(strings.ToLower(filepath.Base(targetELF)), "stage0") {
					cfg.SegmentedBootrom = true
				}
			}

			report, err := elfaudit.AuditELF(targetELF, cfg)
			if err != nil {
				return fmt.Errorf("ELF audit execution failed: %w", err)
			}

			if reportPath != "" {
				if expErr := elfaudit.ExportReportJSON(report, reportPath); expErr != nil {
					return fmt.Errorf("write ELF audit report %s: %w", reportPath, expErr)
				}
			}

			if !report.Passed {
				var details []string
				for _, v := range report.Violations {
					details = append(details, fmt.Sprintf("%s (%s)", v.Name, v.Details))
				}
				if len(details) == 0 {
					for _, chk := range report.Checks {
						if !chk.Passed {
							details = append(details, fmt.Sprintf("%s (%s)", chk.Name, chk.Details))
						}
					}
				}
				if len(details) > 0 {
					return fmt.Errorf("ELF security audit failed for %s: %s", sanitizeDisplay(targetELF), sanitizeDisplay(strings.Join(details, "; ")))
				}
				return fmt.Errorf("ELF security audit failed for %s", sanitizeDisplay(targetELF))
			}

			ui.Success("ELF security audit passed (%s, profile=%s)", sanitizeDisplay(targetELF), auditProfile)
			return nil
		},
	}

	c.Flags().StringVar(&elfPath, "elf", "", "Path to compiled ELF binary")
	c.Flags().StringVar(&profile, "profile", elfaudit.ProfileProduction, "Audit profile (dev or production)")
	c.Flags().StringVar(&hardwarePath, "hardware", "", "Path to chip hardware.json for reserved RAM and layout rules")
	c.Flags().StringVar(&budget, "budget", "", "Maximum loadable flash partition footprint budget")
	c.Flags().StringVar(&mapPath, "map", "", "Optional GNU ld linker .map path for symbol ownership verification")
	c.Flags().StringVar(&sramBase, "sram-base", "", "Reserved SRAM base address literal")
	c.Flags().StringVar(&sramSize, "sram-size", "", "Reserved SRAM size literal")
	c.Flags().StringVar(&flashBase, "flash-base", "", "Flash base address literal")
	c.Flags().StringVar(&flashSize, "flash-size", "", "Flash size literal")
	c.Flags().StringVar(&stage1MaxBytes, "stage1-max-bytes", "", "Maximum loadable Stage-1 footprint budget")
	c.Flags().StringVar(&reportPath, "report", "", "Write JSON audit report to path")
	return c
}

func parseAuditRegionU64(raw, field string) (uint64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	trimmed = strings.TrimRight(trimmed, "uUlL")
	val, err := build.ParseU64Literal(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid --%s %q: %w", field, raw, err)
	}
	return val, nil
}
