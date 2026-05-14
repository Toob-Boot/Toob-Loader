package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/abi"
	"github.com/toob-boot/toob/internal/ui"
)

var abiCmd = &cobra.Command{
	Use:   "abi",
	Short: "Advanced ABI analysis and SemVer detection",
	Long: `Provides tools to compare ELF binaries or XML baselines using libabigail 
and automatically derive Semantic Versioning (SemVer) recommendations.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := abi.CheckDependencies(); err != nil {
			return err
		}
		return nil
	},
}

var abiCheckCmd = &cobra.Command{
	Use:   "check [old_baseline] [new_binary]",
	Short: "Compare two binaries and recommend a SemVer bump",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldFile := args[0]
		newFile := args[1]

		ui.Step("Analyzing ABI changes...")
		ui.KeyValue("Baseline", oldFile)
		ui.KeyValue("New", newFile)
		ui.Divider()

		res, err := abi.Compare(oldFile, newFile)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if res.BumpType == abi.BumpPatch {
			ui.Success("ABI is perfectly compatible.")
			ui.Info("Recommended SemVer bump: %s", ui.BoldGreen("PATCH"))
			return nil
		}

		ui.Warn("ABI Changes Detected:")
		fmt.Fprintln(os.Stderr, res.Report)

		switch res.BumpType {
		case abi.BumpMajor:
			ui.Error("Recommended SemVer bump: %s (Breaking Changes)", ui.BoldRed("MAJOR"))
			os.Exit(1)
		case abi.BumpMinor:
			ui.Info("Recommended SemVer bump: %s (Backwards-Compatible)", ui.Bold("MINOR"))
		default:
			ui.Warn("Recommended SemVer bump: %s", ui.BoldRed("UNKNOWN"))
		}

		return nil
	},
}

var abiBaselineCmd = &cobra.Command{
	Use:   "baseline [binary_file]",
	Short: "Generate an XML baseline representation for an ELF binary",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inFile := args[0]
		outFile, _ := cmd.Flags().GetString("out")

		if outFile == "" {
			outFile = inFile + ".abi.xml"
		}

		ui.Step("Generating baseline for %s", inFile)
		if err := abi.GenerateBaseline(inFile, outFile); err != nil {
			return err
		}

		ui.Success("Baseline generated: %s", outFile)
		return nil
	},
}

func init() {
	abiBaselineCmd.Flags().StringP("out", "o", "", "Output XML file path")
	
	abiCmd.AddCommand(abiCheckCmd)
	abiCmd.AddCommand(abiBaselineCmd)
}
