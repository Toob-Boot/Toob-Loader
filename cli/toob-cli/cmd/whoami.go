package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Display the currently authenticated Toob Registry account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			profile, err := client.Whoami(ctx)
			if err != nil {
				return fmt.Errorf("not signed in or session invalid: %w", err)
			}

			ui.Info("Username: %s", sanitizeDisplay(profile.Username))
			if profile.DisplayName != "" {
				ui.Info("Name:     %s", sanitizeDisplay(profile.DisplayName))
			}
			ui.Info("Subject:  %s", sanitizeDisplay(profile.ID))

			if chosen, chosenErr := apiclient.ChosenOrganization(); chosenErr == nil && chosen != nil && chosen.Name != "" {
				ui.Info("Org:      %s (%s)", sanitizeDisplay(chosen.Name), sanitizeDisplay(chosen.ID))
			}

			if len(profile.Orgs) > 0 {
				names := make([]string, 0, len(profile.Orgs))
				for _, org := range profile.Orgs {
					names = append(names, sanitizeDisplay(org.Name))
				}
				ui.Info("Orgs:     %s", strings.Join(names, ", "))
			}
			return nil
		},
	}
}
