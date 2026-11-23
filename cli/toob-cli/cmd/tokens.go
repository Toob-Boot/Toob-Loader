package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

func newTokensCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "tokens",
		Short: "Manage API access tokens and CI token exchange",
	}

	c.AddCommand(
		newTokensListCmd(),
		newTokensCreateCmd(),
		newTokensRevokeCmd(),
		newTokensExchangeCmd(),
	)
	return c
}

func newTokensListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List personal and service API tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			creds, err := client.Credentials(ctx)
			if err != nil {
				return fmt.Errorf("list tokens: %w", err)
			}

			if len(creds) == 0 {
				ui.Info("No API tokens found.")
				return nil
			}

			now := time.Now()
			for i := range creds {
				cred := &creds[i]
				ui.Info("%-10s %-24s status=%-10s scopes=%s",
					shortID(sanitizeDisplay(cred.ID), 10),
					truncateRunes(cred.Name, 24),
					tokenStatusOf(cred, now),
					sanitizeDisplay(strings.Join(cred.Scopes, ",")))
			}
			return nil
		},
	}
}

func newTokensCreateCmd() *cobra.Command {
	var (
		name          string
		namespace     string
		scopes        []string
		expiresInDays int
	)

	c := &cobra.Command{
		Use:   "create",
		Short: "Create a new scoped API token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name = strings.TrimSpace(name)
			if name == "" {
				return errors.New("--name must not be empty")
			}
			if expiresInDays < 1 || expiresInDays > 366 {
				return fmt.Errorf("--expires-in-days must be between 1 and 366 (got %d)", expiresInDays)
			}
			cleanScopes := normalizeScopes(scopes)
			if len(cleanScopes) == 0 {
				return errors.New("at least one non-empty --scopes value must be specified")
			}

			var tenantID string
			if chosen, err := apiclient.ChosenOrganization(); err == nil && chosen != nil {
				tenantID = chosen.ID
			}

			client := apiclient.New()
			var created *apiclient.CreatedCredential
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var reqErr error
				created, reqErr = client.CreateCredential(ctx, apiclient.CredentialRequest{
					Name:          name,
					TenantID:      tenantID,
					Namespace:     strings.TrimSpace(namespace),
					Scopes:        cleanScopes,
					ExpiresInDays: expiresInDays,
				})
				return reqErr
			}); err != nil {
				return fmt.Errorf("create token: %w", err)
			}

			if created == nil || !isValidToobToken(created.Token) {
				return errors.New("registry returned an invalid token format")
			}

			ui.Success("Created token %s (%s):", sanitizeDisplay(created.Credential.ID), sanitizeDisplay(name))
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), created.Token); err != nil {
				return err
			}
			return nil
		},
	}

	c.Flags().StringVar(&name, "name", "", "Descriptive token label (required)")
	c.Flags().StringVar(&namespace, "namespace", "", "Bind token to a specific @scope namespace")
	c.Flags().StringSliceVar(&scopes, "scopes", []string{"publish"}, "Comma-separated token scopes")
	c.Flags().IntVar(&expiresInDays, "expires-in-days", 90, "Token lifetime in days (1..366)")
	_ = c.MarkFlagRequired("name")
	return c
}

func newTokensRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke an existing API token by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.TrimSpace(args[0])
			if id == "" {
				return errors.New("token id must not be empty")
			}

			client := apiclient.New()
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				return client.RevokeCredential(ctx, id)
			}); err != nil {
				return fmt.Errorf("revoke token: %w", err)
			}

			ui.Success("Revoked token %s", sanitizeDisplay(id))
			return nil
		},
	}
}

func newTokensExchangeCmd() *cobra.Command {
	var (
		githubEnv  bool
		printToken bool
	)

	c := &cobra.Command{
		Use:   "exchange",
		Short: "Exchange a GitHub Actions OIDC JWT for a short-lived Toob token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			exchanged, err := client.ExchangeGitHubToken(ctx)
			if err != nil {
				return fmt.Errorf("exchange CI OIDC token: %w", err)
			}
			if exchanged == nil || !isValidToobToken(exchanged.Token) {
				return errors.New("registry returned an invalid or unsafe token format")
			}

			if githubEnv {
				envPath := strings.TrimSpace(os.Getenv("GITHUB_ENV"))
				if envPath == "" {
					return errors.New("--github-env requested but GITHUB_ENV is unset")
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "::add-mask::%s\n", exchanged.Token); err != nil {
					return err
				}
				if err := appendGithubEnvToken(envPath, exchanged.Token); err != nil {
					return err
				}
				ui.Success("Exported masked TOOB_TOKEN to GITHUB_ENV")
				return nil
			}

			if printToken {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), exchanged.Token); err != nil {
					return err
				}
				return nil
			}

			ui.Success("Exchanged OIDC token successfully (id=%s)", shortID(sanitizeDisplay(exchanged.Credential.ID), 12))
			return nil
		},
	}

	c.Flags().BoolVar(&githubEnv, "github-env", false, "Mask token and append TOOB_TOKEN to GITHUB_ENV")
	c.Flags().BoolVar(&printToken, "print-token", false, "Print exchanged token to stdout")
	return c
}

func appendGithubEnvToken(envPath, token string) error {
	absPath, err := filepath.Abs(filepath.Clean(envPath))
	if err != nil {
		return fmt.Errorf("resolve GITHUB_ENV path: %w", err)
	}
	dir, base := filepath.Split(absPath)
	if base == "" || base == "." || base == ".." {
		return errors.New("invalid GITHUB_ENV filename")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open GITHUB_ENV directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	f, err := root.OpenFile(base, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open GITHUB_ENV: %w", err)
	}
	if _, err := fmt.Fprintf(f, "TOOB_TOKEN=%s\n", token); err != nil {
		_ = f.Close()
		return fmt.Errorf("write GITHUB_ENV: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close GITHUB_ENV: %w", err)
	}
	return nil
}

func normalizeScopes(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func tokenStatusOf(cred *apiclient.Credential, now time.Time) string {
	if strings.EqualFold(cred.Status, "revoked") {
		return "revoked"
	}
	if !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(now) {
		return "expired"
	}
	if strings.EqualFold(cred.Status, "pending") {
		return "pending"
	}
	if cred.Status != "" {
		return sanitizeDisplay(strings.ToLower(cred.Status))
	}
	return "active"
}
