package cmd

import (
	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the currently authenticated user",
	Long:  `Displays the login name, role, and credential status of the currently authenticated Toob Registry user.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()

		if !client.HasToken() {
			ui.Warn("Not logged in. Run 'toob login' to authenticate.")
			return nil
		}

		// Show locally known login if available
		login := apiclient.GetLogin()

		ui.Header("Authentication Status")

		if login != "" {
			ui.KeyValue("Login", ui.Bold("@"+login))
		}
		ui.KeyValue("Token", ui.Green("active"))

		// Verify token by making a lightweight API call
		ui.Step("Verifying token with server...")
		resp, err := client.MyPackages(cmd_defaultCtx())
		if err != nil {
			ui.Warn("Token may be invalid or expired: %v", err)
			ui.Tip("Run 'toob login --force' to re-authenticate.")
			return nil
		}

		ui.Success("Token is valid. You own %d package(s).", resp.Count)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
