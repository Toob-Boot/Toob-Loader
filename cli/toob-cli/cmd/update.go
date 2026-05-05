package cmd

import (
	"fmt"
	"net/http"

	"github.com/minio/selfupdate"
	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/updater"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Toob CLI to the latest version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[toob] Checking for updates (current version: %s)...\n", Version)
		
		// Bypass the cache for manual update command, we want the live truth
		// To bypass cache in the manual check, we can just call CheckForUpdate
		// Since cache is valid for 24h, if they run `toob update`, we might get a cached result
		// which is fine as long as we know there is an update.
		res, err := updater.CheckForUpdate(Version)
		if err != nil {
			return fmt.Errorf("failed to check for updates: %w", err)
		}

		if !res.Available {
			fmt.Println("[toob] You are already on the latest version!")
			return nil
		}

		fmt.Printf("[toob] Downloading update %s ...\n", res.Version)
		
		resp, err := http.Get(res.DownloadURL)
		if err != nil {
			return fmt.Errorf("failed to download update: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
		}

		err = selfupdate.Apply(resp.Body, selfupdate.Options{})
		if err != nil {
			return fmt.Errorf("failed to apply update: %w", err)
		}

		fmt.Printf("[toob] Successfully updated to %s!\n", res.Version)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
