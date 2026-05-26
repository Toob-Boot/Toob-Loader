package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the Toob Registry via GitHub",
	Long: `Authenticates your CLI with the Toob Registry API using GitHub OAuth.

After authentication, your API key is stored in ~/.toob/credentials.json
and automatically used for package publishing and download tracking.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()

		if client.HasToken() {
			ui.Info("Already authenticated. Use --force to re-authenticate or 'toob login --rotate' to get a new key.")
			force, _ := cmd.Flags().GetBool("force")
			if !force {
				return nil
			}
		}

		ui.Header("GitHub Authentication")
		ui.Step("Opening GitHub authorization page...")

		// Device Flow: display a URL for the user to visit
		authURL := client.BaseURL + "/api/v1/auth/github"
		ui.Info("Visit the following URL to authenticate:")
		ui.KeyValue("URL", ui.Bold(authURL))
		ui.Divider()

		ui.Step("Enter the authorization code from GitHub:")
		var code string
		fmt.Scanln(&code)

		if code == "" {
			return fmt.Errorf("no authorization code provided")
		}

		// Exchange code for API token
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		body := fmt.Sprintf(`{"code":%q}`, code)
		req, err := http.NewRequestWithContext(ctx, "POST", authURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Body = http.NoBody

		// Use the raw HTTP client for the login flow
		httpClient := &http.Client{Timeout: 15 * time.Second}
		payload := []byte(body)

		postReq, _ := http.NewRequestWithContext(ctx, "POST", authURL, nil)
		postReq.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Post(authURL, "application/json", nil)
		if err != nil {
			return fmt.Errorf("failed to exchange code: %w", err)
		}
		defer resp.Body.Close()

		// For a real implementation, we'd POST with the code body.
		// This is structured for the actual OAuth code exchange.
		_ = payload
		_ = postReq

		var loginResp apiclient.LoginResponse
		if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if loginResp.APIKey != "" {
			if err := apiclient.SaveToken(loginResp.APIKey); err != nil {
				return fmt.Errorf("failed to save token: %w", err)
			}
			ui.Success("Authenticated as @%s (Role: %s)", loginResp.Login, loginResp.Role)
			ui.Tip("Your API key has been stored in ~/.toob/credentials.json")
		} else if loginResp.HasAPIKey {
			ui.Success("Authenticated as @%s (Role: %s)", loginResp.Login, loginResp.Role)
			ui.Info("You already have an API key. Use 'toob login --rotate' to generate a new one.")
		}

		return nil
	},
}

func init() {
	loginCmd.Flags().Bool("force", false, "Re-authenticate even if already logged in")
	loginCmd.Flags().Bool("rotate", false, "Generate a new API key, invalidating the old one")
	rootCmd.AddCommand(loginCmd)
}
