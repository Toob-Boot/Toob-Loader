package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/abi"
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

		fmt.Printf("Analyzing ABI changes...\n")
		fmt.Printf(" Baseline: %s\n", oldFile)
		fmt.Printf(" New:      %s\n\n", newFile)

		res, err := abi.Compare(oldFile, newFile)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if res.BumpType == abi.BumpPatch {
			fmt.Printf("\033[32m✔ ABI is perfectly compatible.\033[0m\n")
			fmt.Printf("Recommended SemVer bump: \033[1;32mPATCH\033[0m\n")
			return nil
		}

		fmt.Printf("\033[33mABI Changes Detected:\033[0m\n")
		fmt.Println(res.Report)

		switch res.BumpType {
		case abi.BumpMajor:
			fmt.Printf("Recommended SemVer bump: \033[1;31mMAJOR\033[0m (Incompatible/Breaking Changes)\n")
			os.Exit(1) // Exit with code 1 so CI pipelines can block this if necessary
		case abi.BumpMinor:
			fmt.Printf("Recommended SemVer bump: \033[1;33mMINOR\033[0m (Backwards-Compatible Additions)\n")
		default:
			fmt.Printf("Recommended SemVer bump: \033[1;31mUNKNOWN\033[0m\n")
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

		fmt.Printf("Generating baseline for %s...\n", inFile)
		if err := abi.GenerateBaseline(inFile, outFile); err != nil {
			return err
		}

		fmt.Printf("\033[32m✔ Baseline successfully generated:\033[0m %s\n", outFile)
		return nil
	},
}

func init() {
	abiBaselineCmd.Flags().StringP("out", "o", "", "Output XML file path")
	
	abiCmd.AddCommand(abiCheckCmd)
	abiCmd.AddCommand(abiBaselineCmd)
}
