package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/ui"
)

func newCleanCmd() *cobra.Command {
	var (
		all        bool
		toolchains bool
	)

	c := &cobra.Command{
		Use:   "clean",
		Short: "Clean project build outputs and optionally purge cached toolchains & CAS",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			root, err := paths.FindProjectRootStrict(".")
			if err != nil {
				return fmt.Errorf("locate Toob project root: %w", err)
			}

			for _, dirName := range []string{"build", "builds"} {
				target := filepath.Join(root, dirName)
				if _, statErr := os.Stat(target); statErr == nil {
					if rmErr := os.RemoveAll(target); rmErr != nil {
						return fmt.Errorf("remove %s: %w", target, rmErr)
					}
					ui.Info("Removed %s", target)
				}
			}

			if all || toolchains {
				reclaimed, cleanErr := toolchain.CleanToolchainsAndCAS()
				if cleanErr != nil {
					return fmt.Errorf("clean toolchain cache: %w", cleanErr)
				}
				ui.Success("Purged global toolchain cache and CAS (%d bytes reclaimed).", reclaimed)
			}

			ui.Success("Project clean complete.")
			return nil
		},
	}

	c.Flags().BoolVar(&all, "all", false, "Also clean global toolchain caches and CAS storage")
	c.Flags().BoolVar(&toolchains, "toolchains", false, "Clean global cached toolchains and CAS storage")
	return c
}
