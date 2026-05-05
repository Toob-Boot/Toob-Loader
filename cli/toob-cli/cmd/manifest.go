package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
)

var (
	manifestToml     string
	manifestHardware string
	manifestOutDir   string
)

var manifestCmd = &cobra.Command{
	Use:    "manifest",
	Short:  "Compile device.toml into headers and ld scripts",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		
		// Find compiler root to accurately locate the toobloader C code
		compilerRoot, err := paths.FindProjectRoot(cwd)
		if err != nil {
			compilerRoot = cwd // Fallback
		}
		bootloaderDir := filepath.Join(compilerRoot, "toobloader")

		err = manifest.Compile(manifestToml, manifestHardware, manifestOutDir, bootloaderDir)
		if err != nil {
			return fmt.Errorf("manifest compiler failed: %w", err)
		}
		return nil
	},
}

func init() {
	manifestCmd.Flags().StringVar(&manifestToml, "toml", "device.toml", "Path to device.toml")
	manifestCmd.Flags().StringVar(&manifestHardware, "hardware", "", "Path to hardware.json")
	manifestCmd.Flags().StringVar(&manifestOutDir, "outdir", "build/generated", "Output directory for headers and ld scripts")
	manifestCmd.MarkFlagRequired("hardware")

	rootCmd.AddCommand(manifestCmd)
}
