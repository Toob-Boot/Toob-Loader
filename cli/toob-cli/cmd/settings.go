package cmd

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
)

// The settings pages every TOOB app serves (@toob/account, ACCOUNT_PAGES and organizationPath).
var (
	accountSettingsPages = map[string]string{
		"profile":       "",
		"account":       "/account",
		"notifications": "/notifications",
		"preferences":   "/preferences",
		"security":      "/security",
		"sessions":      "/sessions",
		"sign-ins":      "/sign-ins",
		"tokens":        "/tokens",
		"organizations": "/organizations",
		"plan":          "/plan",
	}
	organizationSettingsPages = map[string]string{
		"general": "",
		"people":  "/people",
		"sso":     "/sso",
		"tokens":  "/tokens",
	}
)

var settingsCmd = &cobra.Command{
	Use:   "settings [page]",
	Short: "Open your TOOB account settings in the browser",
	Long: "Opens a page of your account settings: " + strings.Join(pageNames(accountSettingsPages), ", ") + ".\n" +
		"With --org, or the organization chosen by 'toob org use' and one of its pages (" +
		strings.Join(pageNames(organizationSettingsPages), ", ") + "), the organization's settings.",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd_defaultCtx()
		client := apiclient.New()
		config, err := client.FetchAuthConfig(ctx)
		if err != nil {
			return err
		}
		if config.SettingsURL == "" {
			return fmt.Errorf("%s does not publish where account settings open", client.BaseURL)
		}

		page := "profile"
		if len(args) == 1 {
			page = strings.ToLower(args[0])
		}
		path, err := settingsPath(cmd, client, page)
		if err != nil {
			return err
		}
		address := strings.TrimSuffix(config.SettingsURL, "/") + path
		fmt.Fprintln(cmd.OutOrStdout(), address)
		if err := openBrowser(address); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "Open the address above in a browser.")
		}
		return nil
	},
}

// settingsPath is the page's path below the settings: an organization's when one is named or in
// use and the page is one of an organization's.
func settingsPath(cmd *cobra.Command, client *apiclient.Client, page string) (string, error) {
	flag, _ := cmd.Flags().GetString("org")
	if part, ok := organizationSettingsPages[page]; ok {
		organization, err := organizationOf(cmd_defaultCtx(), cmd, client, nil)
		if err != nil {
			return "", err
		}
		return "/organizations/" + url.PathEscape(organization.Name) + part, nil
	}
	if flag != "" {
		return "", fmt.Errorf("an organization's pages are %s", strings.Join(pageNames(organizationSettingsPages), ", "))
	}
	if part, ok := accountSettingsPages[page]; ok {
		return part, nil
	}
	return "", fmt.Errorf("no settings page %q; the pages are %s, and with --org %s", page,
		strings.Join(pageNames(accountSettingsPages), ", "), strings.Join(pageNames(organizationSettingsPages), ", "))
}

func pageNames(pages map[string]string) []string {
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func init() {
	settingsCmd.Flags().String("org", "", "The organization whose settings to open, by name or id, instead of the one in use")
	rootCmd.AddCommand(settingsCmd)
}
