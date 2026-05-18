package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Manage the chip registry cache",
}

var flagVerifySignature bool
var flagRegistryDev bool

var registrySyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize the local registry cache with the remote repository",
	RunE: func(cmd *cobra.Command, args []string) error {
		cache := registry.NewCache("")
		if cache.IsInitialized() {
			ui.Step("Updating registry ...")
		} else {
			ui.Step("Cloning registry ...")
		}

		if err := cache.Sync(flagRegistryDev); err != nil {
			return fmt.Errorf("registry sync failed: %w", err)
		}

		if flagVerifySignature {
			ui.Step("Verifying GPG signature of HEAD...")
			if err := cache.VerifyHead(); err != nil {
				return fmt.Errorf("signature verification failed: %w", err)
			}
			ui.Success("Signature OK.")
		}

		commit, _ := cache.HeadCommit()
		ui.Success("Registry synced.  HEAD = %s", ui.Gray(commit))
		return nil
	},
}

func init() {
	registrySyncCmd.Flags().BoolVar(&flagVerifySignature, "verify-signature", false, "Verify GPG signature of the registry HEAD commit")
	registrySyncCmd.Flags().BoolVar(&flagRegistryDev, "dev", false, "Sync the bleeding-edge main branch instead of the latest stable tag")
	registryCmd.AddCommand(registrySyncCmd)
}
