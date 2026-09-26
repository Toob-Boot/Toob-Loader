package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/oidc"
	"github.com/toob-boot/toob/internal/ui"
)

// loginTimeout is how long a person has to finish in the browser before the command gives up. Long
// enough to find a password manager and a second factor; short enough that a forgotten terminal
// stops holding a loopback port open.
const loginTimeout = 5 * time.Minute

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Sign in to the Toob Registry",
	Long: `Signs in through the Toob identity provider.

The registry is asked who issues the tokens it accepts, so nothing about a particular
environment is configured here: pointing the CLI at another registry signs you in to
that registry's identity provider.

A browser opens by default. On a machine without one — a server over SSH, a container —
pass --device and finish the sign-in on a device that has one.

Your session is stored in ~/.toob/credentials.json and refreshed automatically. CI uses a
personal token ('toob tokens create') or, in GitHub Actions, 'toob tokens exchange'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		device, _ := cmd.Flags().GetBool("device")

		client := apiclient.New()
		ctx, cancel := context.WithTimeout(cmd.Context(), loginTimeout)
		defer cancel()

		if apiclient.HasSession() && !force {
			ui.Info("Already signed in. Use --force to sign in again.")
			return nil
		}

		// Where to sign in, asked of the registry being signed in to.
		config, err := client.FetchAuthConfig(ctx)
		if err != nil {
			return err
		}
		provider, err := oidc.Discover(ctx, config.Issuer)
		if err != nil {
			return err
		}

		ui.Header("Sign in to " + config.Issuer)

		var token *oidc.Token
		if device {
			token, err = deviceSignIn(ctx, provider, config)
		} else {
			token, err = browserSignIn(ctx, provider, config)
		}
		if err != nil {
			return err
		}

		if err := apiclient.SaveIdentity(&apiclient.IdentityCredentials{
			Issuer:   config.Issuer,
			ClientID: config.ClientID,
			Token:    token,
		}, ""); err != nil {
			return fmt.Errorf("failed to store the session: %w", err)
		}

		// Ask the registry who it thinks we are. This is the only step that proves the whole chain —
		// that the token was issued for this registry's audience and that it accepts it — and doing it
		// here means a misconfigured deployment is reported at sign-in rather than at the first
		// publish.
		return reportWhoTheRegistrySees(ctx, client)
	},
}

// browserSignIn runs the authorization code flow with PKCE against a loopback redirect.
func browserSignIn(ctx context.Context, provider *oidc.Provider, config *apiclient.AuthConfig) (*oidc.Token, error) {
	login, err := oidc.StartBrowserLogin(provider, config.ClientID, config.Audience, config.Scopes)
	if err != nil {
		return nil, err
	}
	defer login.Close()

	if err := openBrowser(login.AuthorizationURL); err != nil {
		ui.Warn("Could not open a browser: %v", err)
	}
	ui.Info("Open this address if a browser did not:")
	fmt.Println("  " + login.AuthorizationURL)
	ui.Step("Waiting for the sign-in to finish...")

	return login.Wait(ctx)
}

// deviceSignIn runs the device authorization grant, for a machine with no browser of its own.
func deviceSignIn(ctx context.Context, provider *oidc.Provider, config *apiclient.AuthConfig) (*oidc.Token, error) {
	login, err := oidc.StartDeviceLogin(ctx, provider, config.ClientID, config.Audience, config.Scopes)
	if err != nil {
		return nil, err
	}

	if login.VerificationURIComplete != "" {
		ui.Info("On any device with a browser, open:")
		fmt.Println("  " + login.VerificationURIComplete)
		ui.Info("It already carries the code below; check that it matches before approving.")
	} else {
		ui.Info("On any device with a browser, open:")
		fmt.Println("  " + login.VerificationURI)
	}
	fmt.Printf("  Code: %s\n", login.UserCode)
	ui.Step("Waiting for the sign-in to be approved...")

	return login.Wait(ctx)
}

// reportWhoTheRegistrySees confirms the stored session against the registry.
func reportWhoTheRegistrySees(ctx context.Context, client *apiclient.Client) error {
	profile, err := client.Whoami(ctx)
	if err != nil {
		return fmt.Errorf("signed in, but %s did not accept the token: %w", client.BaseURL, err)
	}

	if profile.Username != "" {
		ui.Success("Signed in as %s", profile.Username)
	} else {
		ui.Success("Signed in")
	}
	ui.Tip("Your session is stored in ~/.toob/credentials.json and refreshed automatically.")
	ui.Tip("For CI, make a token with 'toob tokens create' and pass it as %s.", apiclient.TokenEnv)

	return nil
}

// openBrowser opens a URL in the platform's default browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func init() {
	loginCmd.Flags().Bool("force", false, "Sign in again even if a session is already stored")
	loginCmd.Flags().Bool("device", false, "Sign in on another device (for machines without a browser)")
	rootCmd.AddCommand(loginCmd)
}
