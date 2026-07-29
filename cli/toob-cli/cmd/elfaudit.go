package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/elfaudit"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ui"
)

var elfauditProfile string
var elfauditHardware string
var elfauditBudget uint64

var elfauditCmd = &cobra.Command{
	Use:   "elfaudit [path/to/target.elf]",
	Short: "Post-link ELF audit: mock poison-pill, memory overlap, budget check",
	Long: `Inspects a linked ELF binary for:
  (a) Mock Poison-Pill  — no *_mock symbols in production profile
  (b) Memory Overlap    — sections vs. reserved_ram_regions from hardware.json
  (c) Budget Footprint  — loadable content vs. stage1_size budget`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		elfPath, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("invalid ELF path: %w", err)
		}

		if _, err := os.Stat(elfPath); os.IsNotExist(err) {
			return fmt.Errorf("ELF binary not found: %s", elfPath)
		}

		config := elfaudit.ELFAuditConfig{
			Profile:        elfauditProfile,
			Stage1MaxBytes: elfauditBudget,
		}

		// Load reserved regions from hardware.json if provided
		if elfauditHardware != "" {
			absHW, err := filepath.Abs(elfauditHardware)
			if err != nil {
				return fmt.Errorf("invalid hardware.json path: %w", err)
			}
			data, err := os.ReadFile(absHW)
			if err != nil {
				return fmt.Errorf("failed to read hardware.json: %w", err)
			}
			var hj manifest.HardwareJson
			if err := json.Unmarshal(data, &hj); err != nil {
				return fmt.Errorf("failed to parse hardware.json: %w", err)
			}
			for _, r := range hj.ReservedRamRegions {
				base, err := strconv.ParseUint(strings.TrimPrefix(r.Base, "0x"), 16, 64)
				if err != nil {
					return fmt.Errorf("invalid base address '%s' for reserved region '%s': %w", r.Base, r.Name, err)
				}
				config.ReservedRegions = append(config.ReservedRegions, elfaudit.MemoryRegion{
					Name: r.Name,
					Base: base,
					Size: uint64(r.Size),
				})
			}
		}

		ui.Header(fmt.Sprintf("ELF Audit: %s [profile=%s]", filepath.Base(elfPath), config.Profile))

		report, err := elfaudit.AuditELF(elfPath, config)
		if err != nil {
			return fmt.Errorf("ELF audit failed: %w", err)
		}

		for _, chk := range report.Checks {
			if chk.Passed {
				ui.Success("%s: %s", chk.Name, chk.Details)
			} else {
				ui.Error("%s: %s", chk.Name, chk.Details)
			}
		}

		// Export JSON report next to the ELF
		reportPath := elfPath + ".audit.json"
		reportData, _ := json.MarshalIndent(report, "", "  ")
		_ = os.WriteFile(reportPath, reportData, 0o644)

		if !report.Passed {
			return fmt.Errorf("FATAL [ELF_AUDIT_FAIL]: Binary failed post-link audit!")
		}

		ui.Success("ELF audit PASSED cleanly. Report: %s", reportPath)
		return nil
	},
}

func init() {
	elfauditCmd.Flags().StringVar(&elfauditProfile, "profile", "production", "Build profile (production|sandbox)")
	elfauditCmd.Flags().StringVar(&elfauditHardware, "hardware", "", "Path to hardware.json for reserved region checks")
	elfauditCmd.Flags().Uint64Var(&elfauditBudget, "budget", 0, "Stage1 size budget in bytes (0 = skip budget check)")
	rootCmd.AddCommand(elfauditCmd)
}

