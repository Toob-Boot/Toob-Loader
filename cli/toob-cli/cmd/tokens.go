package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var tokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Manage scoped API tokens for CI/CD and automation",
}

// --- tokens create ---

var tokensCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new scoped API token",
	Long: `Creates a new scoped API token for CI/CD pipelines or automation.

The token is shown only once — store it securely.

Example:
  toob tokens create --name "CI Deploy" --scopes publish,promote`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		name, _ := cmd.Flags().GetString("name")
		scopesRaw, _ := cmd.Flags().GetString("scopes")
		expiresIn, _ := cmd.Flags().GetInt("expires-in-days")

		if name == "" {
			return fmt.Errorf("--name is required")
		}
		if scopesRaw == "" {
			return fmt.Errorf("--scopes is required (e.g., publish,promote)")
		}

		scopes := strings.Split(scopesRaw, ",")
		for i, s := range scopes {
			scopes[i] = strings.TrimSpace(s)
		}

		req := &apiclient.TokenCreateRequest{
			Name:   name,
			Scopes: scopes,
		}
		if expiresIn > 0 {
			req.ExpiresIn = &expiresIn
		}

		ui.Step("Creating token '%s'...", name)
		resp, err := client.CreateToken(cmd_defaultCtx(), req)
		if err != nil {
			return fmt.Errorf("failed to create token: %w", err)
		}

		ui.Success("Token created successfully.")
		ui.Divider()
		ui.KeyValue("ID", resp.ID)
		ui.KeyValue("Name", resp.Name)
		ui.KeyValue("Token", ui.Bold(resp.Token))
		ui.Divider()
		ui.Warn("This token will only be shown once. Store it securely!")
		return nil
	},
}

// --- tokens list ---

var tokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all API tokens",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		resp, err := client.ListTokens(cmd_defaultCtx())
		if err != nil {
			return fmt.Errorf("failed to list tokens: %w", err)
		}

		if len(resp.Tokens) == 0 {
			ui.Info("No API tokens found. Create one with 'toob tokens create'.")
			return nil
		}

		ui.Header("API Tokens")

		headers := []string{"ID", "NAME", "SCOPES", "CREATED", "EXPIRES"}
		var rows [][]string
		for _, t := range resp.Tokens {
			expires := ui.Gray("never")
			if t.ExpiresAt != "" {
				expires = t.ExpiresAt
			}
			rows = append(rows, []string{
				t.ID[:8],
				t.Name,
				strings.Join(t.Scopes, ", "),
				t.CreatedAt,
				expires,
			})
		}
		ui.Table(headers, rows)
		return nil
	},
}

// --- tokens revoke ---

var tokensRevokeCmd = &cobra.Command{
	Use:   "revoke [token-id]",
	Short: "Revoke an API token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		tokenID := args[0]
		ui.Step("Revoking token %s...", tokenID)

		if err := client.RevokeToken(cmd_defaultCtx(), tokenID); err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}

		ui.Success("Token %s has been revoked.", tokenID)
		return nil
	},
}

func init() {
	tokensCreateCmd.Flags().String("name", "", "Human-readable name for the token")
	tokensCreateCmd.Flags().String("scopes", "", "Comma-separated list of scopes (e.g., publish,promote)")
	tokensCreateCmd.Flags().Int("expires-in-days", 0, "Token expiry in days (0 = never)")

	tokensCmd.AddCommand(tokensCreateCmd)
	tokensCmd.AddCommand(tokensListCmd)
	tokensCmd.AddCommand(tokensRevokeCmd)

	rootCmd.AddCommand(tokensCmd)
}
