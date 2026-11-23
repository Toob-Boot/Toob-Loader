package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/ui"
)

func newSettingsCmd() *cobra.Command {
	var (
		orgSlug   string
		personal  bool
		noBrowser bool
	)

	c := &cobra.Command{
		Use:   "settings [page]",
		Short: "Open Toob Registry account or organization settings in your browser",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			page := ""
			if len(args) > 0 {
				page = strings.TrimSpace(strings.TrimPrefix(args[0], "/"))
			}

			client := apiclient.New()
			targetOrg := strings.TrimSpace(orgSlug)
			if !personal && targetOrg == "" && page != "tokens" {
				if chosen, err := apiclient.ChosenOrganization(); err == nil && chosen != nil {
					if chosen.Name != "" {
						targetOrg = chosen.Name
					} else {
						targetOrg = chosen.ID
					}
				}
			}

			targetURL, err := buildSettingsURL(client.BaseURL, targetOrg, personal, page)
			if err != nil {
				return err
			}

			ui.Info("Settings URL: %s", targetURL)
			if noBrowser || !ui.IsInteractive() {
				return nil
			}
			return openBrowserSafe(ctx, targetURL)
		},
	}

	c.Flags().StringVar(&orgSlug, "org", "", "Open settings for the specified organization slug or ID")
	c.Flags().BoolVar(&personal, "personal", false, "Open personal account settings regardless of selected organization")
	c.Flags().BoolVar(&noBrowser, "no-browser", false, "Print settings URL instead of launching a browser")
	c.MarkFlagsMutuallyExclusive("personal", "org")
	return c
}

func buildSettingsURL(baseURL, orgSlug string, personal bool, page string) (string, error) {
	origin, err := httputil.CanonicalOrigin(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid registry base URL: %w", err)
	}

	if page == "" {
		if !personal && orgSlug != "" {
			page = "general"
		} else {
			page = "profile"
		}
	}

	var path string
	if !personal && orgSlug != "" && page != "tokens" {
		path = "/orgs/" + url.PathEscape(orgSlug) + "/settings/" + url.PathEscape(page)
	} else {
		path = "/settings/" + url.PathEscape(page)
	}

	fullURL := origin + path
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(fullURL); err != nil {
		return "", fmt.Errorf("unsafe settings URL: %w", err)
	}
	return fullURL, nil
}
