package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/paths"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove all build artifacts (builds/ directory)",
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := paths.FindProjectRoot("")
		if err != nil || root == "" {
			return fmt.Errorf("not in a Toob-Loader project (device.toml not found)")
		}

		buildsDir := filepath.Join(root, "builds")
		if _, err := os.Stat(buildsDir); os.IsNotExist(err) {
			fmt.Println("[toob] Nothing to clean.")
			return nil
		}

		fmt.Printf("[toob] Removing %s ...\n", buildsDir)
		if err := os.RemoveAll(buildsDir); err != nil {
			return fmt.Errorf("failed to clean builds directory: %w", err)
		}

		fmt.Println("[toob] Clean complete.")
		return nil
	},
}
