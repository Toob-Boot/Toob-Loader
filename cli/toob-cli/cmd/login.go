package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the Toob Registry via GitHub",
	Long: `Authenticates your CLI with the Toob Registry API using GitHub OAuth.

After authentication, your API key is stored in ~/.toob/credentials.json
and automatically used for package publishing and download tracking.

Use --rotate to invalidate your current key and generate a new one.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()

		rotate, _ := cmd.Flags().GetBool("rotate")
		force, _ := cmd.Flags().GetBool("force")

		if client.HasToken() && !force && !rotate {
			ui.Info("Already authenticated. Use --force to re-authenticate or --rotate to get a new key.")
			return nil
		}

		ui.Header("GitHub Authentication")

		// Display the authorization URL for the user
		authURL := client.BaseURL + "/api/v1/auth/github"
		ui.Step("Visit the following URL to authenticate:")
		ui.KeyValue("URL", ui.Bold(authURL))
		ui.Divider()

		ui.Step("Enter the authorization code from GitHub:")
		var code string
		fmt.Scanln(&code)

		if code == "" {
			return fmt.Errorf("no authorization code provided")
		}

		// Branch: rotate existing key vs. fresh login
		if rotate {
			return handleRotate(client, code)
		}
		return handleLogin(client, code)
	},
}

// handleLogin exchanges the OAuth code for an API key via the Login endpoint.
func handleLogin(client *apiclient.Client, code string) error {
	loginResp, err := client.Login(cmd_defaultCtx(), code)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	if loginResp.APIKey != "" {
		if err := apiclient.SaveCredentials(loginResp.APIKey, loginResp.Login); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}
		ui.Success("Authenticated as @%s (Role: %s)", loginResp.Login, loginResp.Role)
		ui.Tip("Your API key has been stored in ~/.toob/credentials.json")
	} else if loginResp.HasAPIKey {
		ui.Success("Authenticated as @%s (Role: %s)", loginResp.Login, loginResp.Role)
		ui.Info("You already have an API key. Use 'toob login --rotate' to generate a new one.")
	}

	return nil
}

// handleRotate exchanges the OAuth code for a rotated API key, invalidating the old one.
func handleRotate(client *apiclient.Client, code string) error {
	ui.Step("Rotating API key...")
	rotateResp, err := client.RotateKey(cmd_defaultCtx(), code)
	if err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}

	if rotateResp.APIKey == "" {
		return fmt.Errorf("server did not return a new API key")
	}

	if err := apiclient.SaveCredentials(rotateResp.APIKey, rotateResp.Login); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	ui.Success("API key rotated for @%s", rotateResp.Login)
	ui.Tip("Your new key has been stored. The old key is now invalid.")
	return nil
}

func init() {
	loginCmd.Flags().Bool("force", false, "Re-authenticate even if already logged in")
	loginCmd.Flags().Bool("rotate", false, "Generate a new API key, invalidating the old one")
	rootCmd.AddCommand(loginCmd)
}
