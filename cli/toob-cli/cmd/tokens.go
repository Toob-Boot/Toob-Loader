package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var tokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Manage personal tokens for scripts and CI",
	Long: `A personal token acts as you in one organization, on one namespace, with the scopes it names.
Pass it to the CLI as TOOB_TOKEN. Organization owners set whether members may make them, and may
require approval first; service accounts and trusted workflows are managed in the organization's
settings.

In GitHub Actions a trusted workflow needs no stored secret: 'toob tokens exchange' trades the job's
own OIDC token for a credential that lasts fifteen minutes.`,
}

var tokensCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Make a personal token, shown once",
	Example: `  toob tokens create --name "CI deploy" --namespace acme --scopes publish
  toob tokens create --name release --org acme --namespace acme --scopes publish,publish:promote --expires-in-days 90`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		namespace, _ := cmd.Flags().GetString("namespace")
		scopes, _ := cmd.Flags().GetStringSlice("scopes")
		days, _ := cmd.Flags().GetInt("expires-in-days")

		ctx := cmd_defaultCtx()
		client := apiclient.New()
		organization, err := organizationOf(ctx, cmd, client, nil)
		if err != nil {
			return err
		}

		var created *apiclient.CreatedCredential
		err = withStepUp(ctx, client, func() error {
			var err error
			created, err = client.CreateCredential(ctx, apiclient.CredentialRequest{
				Name: name, TenantID: organization.ID, Namespace: namespace, Scopes: scopes, ExpiresInDays: days,
			})
			return err
		})
		if err != nil {
			return err
		}

		ui.Success("Made %s in %s, valid until %s.", ui.Bold(created.Credential.Name), organization.Name,
			created.Credential.ExpiresAt.Local().Format(time.DateOnly))
		if created.Credential.Status == "pending" {
			ui.Warn("%s requires approval of personal tokens; it works once an administrator approves it.", organization.Name)
		}
		ui.Divider()
		fmt.Println(created.Token)
		ui.Divider()
		ui.Warn("This is the only time the token is shown. Store it as a secret and pass it as %s.", apiclient.TokenEnv)
		return nil
	},
}

var tokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your personal tokens",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd_defaultCtx()
		client := apiclient.New()
		credentials, err := client.Credentials(ctx)
		if err != nil {
			return err
		}
		if len(credentials) == 0 {
			ui.Muted("You have no personal tokens. Make one with 'toob tokens create'.")
			return nil
		}
		organizations, err := client.Organizations(ctx)
		if err != nil {
			return err
		}
		names := map[string]string{}
		for _, organization := range organizations.Tenants {
			names[organization.ID] = organization.Name
		}

		rows := make([][]string, 0, len(credentials))
		for _, credential := range credentials {
			used := ui.Gray("never")
			if credential.LastUsedAt != nil {
				used = credential.LastUsedAt.Local().Format(time.DateOnly)
			}
			rows = append(rows, []string{
				credential.ID, credential.Name, fmt.Sprintf("%s/%s", names[credential.TenantID], credential.Namespace),
				strings.Join(credential.Scopes, ", "), statusOf(credential), used,
			})
		}
		ui.Header("Personal tokens")
		ui.Table([]string{"ID", "NAME", "ORGANIZATION/NAMESPACE", "SCOPES", "STATUS", "LAST USED"}, rows)
		return nil
	},
}

func statusOf(credential apiclient.Credential) string {
	switch {
	case credential.Status == "pending":
		return ui.Yellow("awaiting approval")
	case !credential.ExpiresAt.After(time.Now()):
		return ui.Gray("expired")
	default:
		return "until " + credential.ExpiresAt.Local().Format(time.DateOnly)
	}
}

var tokensRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke one of your personal tokens",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := apiclient.New().RevokeCredential(cmd_defaultCtx(), args[0]); err != nil {
			return err
		}
		ui.Success("Revoked %s; it no longer authenticates.", args[0])
		return nil
	},
}

var tokensExchangeCmd = &cobra.Command{
	Use:   "exchange",
	Short: "In GitHub Actions, get a fifteen-minute credential for a trusted workflow",
	Long: `Trades the job's GitHub OIDC token for a credential of the organization that trusts this
workflow, masks it in the log and sets TOOB_TOKEN for the steps that follow. The job needs
'permissions: id-token: write'.`,
	Example: `  - run: toob tokens exchange
  - run: toob publish`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		env := os.Getenv("GITHUB_ENV")
		if env == "" {
			return apiclient.ErrNotInGitHubActions
		}
		created, err := apiclient.New().ExchangeGitHubToken(cmd_defaultCtx())
		if err != nil {
			return err
		}
		fmt.Printf("::add-mask::%s\n", created.Token)

		file, err := os.OpenFile(env, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("opening GITHUB_ENV: %w", err)
		}
		if _, err := fmt.Fprintf(file, "%s=%s\n", apiclient.TokenEnv, created.Token); err != nil {
			file.Close()
			return fmt.Errorf("writing GITHUB_ENV: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("writing GITHUB_ENV: %w", err)
		}
		ui.Success("%s is set for the following steps, until %s.", apiclient.TokenEnv, created.Credential.ExpiresAt.Format(time.TimeOnly+" MST"))
		return nil
	},
}

func init() {
	tokensCreateCmd.Flags().String("name", "", "What the token is for")
	tokensCreateCmd.Flags().String("namespace", "", "The one namespace the token may act on")
	tokensCreateCmd.Flags().StringSlice("scopes", nil, "read, publish and publish:promote")
	tokensCreateCmd.Flags().Int("expires-in-days", 0, "Lifetime in days, at most 366 (default 30)")
	tokensCreateCmd.Flags().String("org", "", "The organization it acts in, by name or id, instead of the one in use")
	for _, required := range []string{"name", "namespace", "scopes"} {
		cobra.CheckErr(tokensCreateCmd.MarkFlagRequired(required))
	}

	tokensCmd.AddCommand(tokensCreateCmd, tokensListCmd, tokensRevokeCmd, tokensExchangeCmd)
	rootCmd.AddCommand(tokensCmd)
}
