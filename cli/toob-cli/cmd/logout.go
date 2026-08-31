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
	Long: `Signs out of the Toob Registry on this machine.

Removes the stored session from ~/.toob/credentials.json. Any API key created with
'toob tokens' is left in place — use 'toob tokens revoke' to withdraw one of those.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Local only. The server call this used to make went to /api/v1/auth/logout, which the
		// registry does not serve; and a session is a token the identity provider issued, so there is
		// nothing for the registry to invalidate. Removing it here is what ends the session for this
		// machine, which is what "log out" means on a command line.
		//
		// The API key is left alone: it is the credential for machines, and signing out of a terminal
		// must not revoke what CI publishes with. 'toob tokens revoke' is how that one is withdrawn.
		if !apiclient.HasSession() {
			ui.Info("Not currently signed in.")
			return nil
		}

		if err := apiclient.DeleteIdentity(); err != nil {
			return fmt.Errorf("failed to remove the local session: %w", err)
		}

		ui.Success("Signed out.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
