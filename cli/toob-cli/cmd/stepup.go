package cmd

import (
	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

func newStepUpCmd() *cobra.Command {
	var opts authFlowOptions

	c := &cobra.Command{
		Use:   "stepup",
		Short: "Perform Step-Up MFA verification for privileged registry actions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.stepUp = true
			client := apiclient.New()
			profile, err := authenticateInteractive(cmd, client, stepUpCmdTimeout, opts)
			if err != nil {
				return err
			}

			ui.Success("Step-Up authentication verified for %s", sanitizeDisplay(profile.Username))
			return nil
		},
	}

	c.Flags().BoolVar(&opts.device, "device", false, "Use OAuth 2.0 device authorization flow")
	c.Flags().BoolVar(&opts.noBrowser, "no-browser", false, "Do not open a browser window automatically")
	return c
}
