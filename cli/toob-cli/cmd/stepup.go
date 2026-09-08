package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/oidc"
	"github.com/toob-boot/toob/internal/ui"
)

// withStepUp runs an operation and, if the registry answers it with a step-up challenge, signs the
// person in again as the challenge asks and runs it once more.
//
// Once, and not until it succeeds: a second challenge after a fresh sign-in is the registry saying
// the session cannot satisfy it — the account holds no authenticator of the required kind, say —
// and that is an answer to show, not a loop to run. A CI token gets no retry at all: the registry
// refuses it with a plain 403, because a machine has no ceremony to perform.
func withStepUp(ctx context.Context, client *apiclient.Client, operation func() error) error {
	err := operation()
	var challenge *apiclient.StepUpRequired
	if !errors.As(err, &challenge) {
		return err
	}

	ui.Info("%s", challenge.Error())
	if err := stepUpSignIn(ctx, client, challenge); err != nil {
		return fmt.Errorf("signing in again: %w", err)
	}

	return operation()
}

// stepUpSignIn performs the browser login the challenge asks for and stores the resulting session.
//
// The provider and client id are re-read from the registry rather than taken from the stored
// session, so a session left behind by another deployment cannot direct this login anywhere else.
func stepUpSignIn(ctx context.Context, client *apiclient.Client, challenge *apiclient.StepUpRequired) error {
	config, err := client.FetchAuthConfig(ctx)
	if err != nil {
		return err
	}
	provider, err := oidc.Discover(ctx, config.Issuer)
	if err != nil {
		return err
	}

	login, err := oidc.StartBrowserStepUp(provider, config.ClientID, config.Audience, config.Scopes, oidc.StepUp{
		ACRValues: challenge.ACRValues,
		MaxAge:    challenge.MaxAge,
	})
	if err != nil {
		return err
	}
	defer login.Close()

	if err := openBrowser(login.AuthorizationURL); err != nil {
		ui.Warn("Could not open a browser: %v", err)
	}
	ui.Info("Open this address if a browser did not:")
	fmt.Println("  " + login.AuthorizationURL)
	ui.Step("Waiting for the sign-in to finish...")

	token, err := login.Wait(ctx)
	if err != nil {
		return err
	}

	return apiclient.SaveIdentity(&apiclient.IdentityCredentials{
		Issuer:   config.Issuer,
		ClientID: config.ClientID,
		Token:    token,
	}, "")
}
