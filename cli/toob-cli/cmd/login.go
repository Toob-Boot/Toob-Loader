package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/oidc"
	"github.com/toob-boot/toob/internal/ui"
)

type authFlowOptions struct {
	device     bool
	noBrowser  bool
	stepUp     bool
	stepUpACR  string
	stepMaxAge time.Duration
	tokenStdin bool
	token      string
}

func newLoginCmd() *cobra.Command {
	var opts authFlowOptions

	c := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the Toob Registry",
		Long:  "Sign in to the Toob Registry via interactive browser OIDC (PKCE) or device authorization flow.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			timeout := stepUpCmdTimeout
			if opts.token != "" || opts.tokenStdin {
				timeout = defaultCmdTimeout
			}

			client := apiclient.New()
			profile, err := authenticateInteractive(cmd, client, timeout, opts)
			if err != nil {
				return err
			}

			ui.Success("Signed in as %s", sanitizeDisplay(profile.Username))
			return nil
		},
	}

	c.Flags().BoolVar(&opts.device, "device", false, "Use OAuth 2.0 device authorization flow")
	c.Flags().BoolVar(&opts.noBrowser, "no-browser", false, "Use device flow instead of opening a browser")
	c.Flags().StringVar(&opts.token, "token", "", "Authenticate non-interactively with an existing Toob token")
	c.Flags().BoolVar(&opts.tokenStdin, "token-stdin", false, "Read authentication token from stdin")
	c.MarkFlagsMutuallyExclusive("device", "token", "token-stdin")
	return c
}

func authenticateInteractive(cmd *cobra.Command, client *apiclient.Client, timeout time.Duration, opts authFlowOptions) (*apiclient.Profile, error) {
	if opts.tokenStdin {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return nil, fmt.Errorf("read token from stdin: %w", err)
		}
		opts.token = strings.TrimSpace(string(raw))
	}

	if opts.token != "" {
		cred, profile, err := verifyTokenProfile(cmd, timeout, client.BaseURL, &oidc.Token{AccessToken: opts.token}, "", "")
		if err != nil {
			return nil, err
		}
		if saveErr := apiclient.SaveIdentity(cred, profile.Username); saveErr != nil {
			return nil, fmt.Errorf("save credentials: %w", saveErr)
		}
		client.Token = opts.token
		return profile, nil
	}

	authCfg, disc, err := discoverAuthProvider(cmd, client, timeout)
	if err != nil {
		return nil, err
	}

	var tok *oidc.Token
	useDevice := opts.device || opts.noBrowser || !ui.IsInteractive()
	if useDevice {
		tok, err = runDeviceLoginFlow(cmd, timeout, disc, authCfg)
	} else {
		tok, err = runBrowserLoginFlow(cmd, timeout, disc, authCfg, opts)
	}
	if err != nil {
		return nil, err
	}

	cred, profile, err := verifyTokenProfile(cmd, timeout, client.BaseURL, tok, authCfg.Issuer, authCfg.ClientID)
	if err != nil {
		return nil, err
	}
	if saveErr := apiclient.SaveIdentity(cred, profile.Username); saveErr != nil {
		return nil, fmt.Errorf("save credentials: %w", saveErr)
	}
	client.Token = tok.AccessToken
	return profile, nil
}

func discoverAuthProvider(cmd *cobra.Command, client *apiclient.Client, timeout time.Duration) (*apiclient.AuthConfig, *oidc.Provider, error) {
	ctx, cancel := commandContext(cmd, timeout)
	defer cancel()

	authCfg, err := client.FetchAuthConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch registry auth config: %w", err)
	}
	disc, err := oidc.Discover(ctx, authCfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("discover OIDC endpoints: %w", err)
	}
	return authCfg, disc, nil
}

func runDeviceLoginFlow(cmd *cobra.Command, timeout time.Duration, disc *oidc.Provider, authCfg *apiclient.AuthConfig) (*oidc.Token, error) {
	ctx, cancel := commandContext(cmd, timeout)
	defer cancel()

	dev, err := oidc.StartDeviceLogin(ctx, disc, authCfg.ClientID, authCfg.Audience, authCfg.Scopes)
	if err != nil {
		return nil, fmt.Errorf("start device login: %w", err)
	}
	displayURI := dev.VerificationURI
	if dev.VerificationURIComplete != "" {
		displayURI = dev.VerificationURIComplete
	}
	ui.Step("Open %s and enter code: %s", sanitizeDisplay(displayURI), sanitizeDisplay(dev.UserCode))

	tok, err := dev.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("device login: %w", err)
	}
	return tok, nil
}

func runBrowserLoginFlow(cmd *cobra.Command, timeout time.Duration, disc *oidc.Provider, authCfg *apiclient.AuthConfig, opts authFlowOptions) (*oidc.Token, error) {
	var browser *oidc.BrowserLogin
	var err error
	if opts.stepUp {
		browser, err = oidc.StartBrowserStepUp(disc, authCfg.ClientID, authCfg.Audience, authCfg.Scopes, oidc.StepUp{
			ACRValues: opts.stepUpACR,
			MaxAge:    opts.stepMaxAge,
		})
	} else {
		browser, err = oidc.StartBrowserLogin(disc, authCfg.ClientID, authCfg.Audience, authCfg.Scopes)
	}
	if err != nil {
		return nil, fmt.Errorf("start browser OIDC flow: %w", err)
	}
	defer browser.Close()

	ctx, cancel := commandContext(cmd, timeout)
	defer cancel()

	ui.Step("Opening browser for authentication...")
	if openErr := openBrowserSafe(ctx, browser.AuthorizationURL); openErr != nil {
		ui.Warn("Could not launch browser automatically: %v", openErr)
		ui.Info("Open this URL manually: %s", sanitizeDisplay(browser.AuthorizationURL))
	}
	tok, err := browser.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("browser authentication: %w", err)
	}
	return tok, nil
}

func verifyTokenProfile(cmd *cobra.Command, timeout time.Duration, registryURL string, tok *oidc.Token, issuer, clientID string) (*apiclient.IdentityCredentials, *apiclient.Profile, error) {
	ctx, cancel := commandContext(cmd, timeout)
	defer cancel()
	return verifyTokenWithCtx(ctx, registryURL, tok, issuer, clientID)
}

func verifyTokenWithCtx(ctx context.Context, registryURL string, tok *oidc.Token, issuer, clientID string) (*apiclient.IdentityCredentials, *apiclient.Profile, error) {
	if tok == nil || strings.TrimSpace(tok.AccessToken) == "" {
		return nil, nil, errors.New("authentication succeeded without an access token")
	}

	verifyClient := apiclient.NewForBaseURL(registryURL, defaultCmdTimeout)
	verifyClient.Token = tok.AccessToken

	profile, err := verifyClient.Whoami(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("verify credentials with registry: %w", err)
	}
	if profile == nil || profile.ID == "" || profile.Username == "" {
		return nil, nil, errors.New("registry returned incomplete identity profile")
	}

	cred := &apiclient.IdentityCredentials{
		RegistryURL: registryURL,
		Issuer:      issuer,
		ClientID:    clientID,
		Subject:     profile.ID,
		Token:       tok,
	}
	return cred, profile, nil
}
