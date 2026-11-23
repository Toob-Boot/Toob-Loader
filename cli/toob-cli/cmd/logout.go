package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

func newLogoutCmd() *cobra.Command {
	var all bool

	c := &cobra.Command{
		Use:   "logout",
		Short: "Revoke the active registry session and clear local credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			_ = all

			if err := client.Logout(ctx); err != nil {
				if !errors.Is(err, apiclient.ErrNoSession) && !errors.Is(err, apiclient.ErrNotSignedIn) {
					return fmt.Errorf("logout failed: %w", err)
				}
			}

			if err := apiclient.ClearOrganization(); err != nil && !errors.Is(err, apiclient.ErrNoSession) && !errors.Is(err, apiclient.ErrNotSignedIn) {
				return fmt.Errorf("clear selected organization: %w", err)
			}

			ui.Success("Signed out and cleared local registry credentials.")
			return nil
		},
	}

	c.Flags().BoolVar(&all, "all", false, "Revoke active session and clear local organization context")
	return c
}
