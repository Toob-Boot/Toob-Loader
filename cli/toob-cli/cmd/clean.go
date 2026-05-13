package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/paths"
)

var flagToolchains bool

func init() {
	cleanCmd.Flags().BoolVar(&flagToolchains, "toolchains", false, "Remove all globally cached cross-compiler toolchains to free up disk space")
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove all build artifacts (builds/ directory)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagToolchains {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			tcDir := filepath.Join(home, ".toob", "toolchains")
			if _, err := os.Stat(tcDir); os.IsNotExist(err) {
				fmt.Println("[toob] No toolchains found. Nothing to clean.")
				return nil
			}
			fmt.Printf("[toob] Removing globally cached toolchains at %s ...\n", tcDir)
			// Safe rename-to-trash pattern for Windows locking safety
			trashDir := filepath.Join(home, ".toob", ".trash", "toolchains-"+time.Now().Format("20060102150405"))
			os.MkdirAll(filepath.Dir(trashDir), 0o755)
			if err := os.Rename(tcDir, trashDir); err != nil {
				return fmt.Errorf("failed to unlock toolchains directory (is a file currently open in an IDE or terminal?): %w", err)
			}

			if err := os.RemoveAll(trashDir); err != nil {
				fmt.Printf("\033[33m[toob] Warning: Could not fully delete all files (some are locked), but toolchains are deactivated.\033[0m\n")
			}
			fmt.Println("\033[32m[toob] Successfully freed disk space.\033[0m")
			return nil
		}

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
