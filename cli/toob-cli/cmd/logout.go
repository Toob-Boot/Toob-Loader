package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from the Toob Registry",
	Long: `Logs out from the Toob Registry by:
  1. Invalidating your API key on the server
  2. Removing the local credentials file (~/.toob/credentials.json)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()

		if !client.HasToken() {
			ui.Info("Not currently logged in.")
			return nil
		}

		ui.Step("Logging out from Toob Registry...")

		// Invalidate the key on the server first
		_, err := client.Logout(cmd_defaultCtx())
		if err != nil {
			ui.Warn("Could not invalidate key on server: %v", err)
			ui.Info("Removing local credentials anyway...")
		}

		// Always remove local credentials, even if server call failed
		if err := apiclient.DeleteCredentials(); err != nil {
			return fmt.Errorf("failed to remove local credentials: %w", err)
		}

		ui.Success("Logged out successfully.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
