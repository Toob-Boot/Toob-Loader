package apiclient

import (
	"errors"
	"testing"
)

func signIn(t *testing.T, subject string) {
	t.Helper()
	if err := SaveIdentity(&IdentityCredentials{Issuer: "https://id.toob.local", ClientID: "cli", Subject: subject}, subject); err != nil {
		t.Fatalf("signing in as %s failed: %v", subject, err)
	}
}

// The organization in use is the account's: another account starts without one, and the first
// finds its own again.
func TestOrganizationContext_BelongsToTheAccount(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if _, err := ChosenOrganization(); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("a context without anybody signed in: %v", err)
	}

	signIn(t, "usr_anna")
	if err := ChooseOrganization("301", "acme"); err != nil {
		t.Fatalf("choosing failed: %v", err)
	}
	if chosen, err := ChosenOrganization(); err != nil || chosen == nil || chosen.ID != "301" {
		t.Fatalf("anna's context is %+v, %v", chosen, err)
	}

	signIn(t, "usr_ben")
	if chosen, err := ChosenOrganization(); err != nil || chosen != nil {
		t.Errorf("ben sees anna's context: %+v, %v", chosen, err)
	}

	signIn(t, "usr_anna")
	if err := ClearOrganization(); err != nil {
		t.Fatalf("clearing failed: %v", err)
	}
	if chosen, err := ChosenOrganization(); err != nil || chosen != nil {
		t.Errorf("a cleared context is %+v, %v", chosen, err)
	}
}
