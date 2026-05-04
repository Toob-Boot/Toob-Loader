package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/registry"
)

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Manage the chip registry cache",
}

var registrySyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize the local registry cache with the remote repository",
	RunE: func(cmd *cobra.Command, args []string) error {
		cache := registry.NewCache("")
		if cache.IsInitialized() {
			fmt.Println("[toob] Updating registry ...")
		} else {
			fmt.Println("[toob] Cloning registry ...")
		}

		if err := cache.Sync(); err != nil {
			return fmt.Errorf("registry sync failed: %w", err)
		}

		commit, _ := cache.HeadCommit()
		fmt.Printf("[toob] Registry synced.  HEAD = %s\n", commit)
		return nil
	},
}

func init() {
	registryCmd.AddCommand(registrySyncCmd)
}
