package apiclient

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func signIn(t *testing.T, subject string) {
	t.Helper()
	if err := SaveIdentity(&IdentityCredentials{Issuer: "https://id.toob.local", ClientID: "cli", Subject: subject}, subject); err != nil {
		t.Fatalf("signing in as %s failed: %v", subject, err)
	}
}

func TestOrganizationContext_MultiAccountPreservationAndLegacyMigration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOOB_HOME", filepath.Join(home, ".toob"))
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if _, err := ChosenOrganization(); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("a context without anybody signed in: %v", err)
	}

	// Legacy single-object organization.json must still load cleanly.
	legacyOrgFile := filepath.Join(home, ".toob", "organization.json")
	if err := os.MkdirAll(filepath.Dir(legacyOrgFile), 0o700); err != nil {
		t.Fatal(err)
	}
	legacyJSON := `{"issuer":"https://id.toob.local","subject":"usr_anna","id":"301","name":"acme"}`
	if err := os.WriteFile(legacyOrgFile, []byte(legacyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	signIn(t, "usr_anna")
	if chosen, err := ChosenOrganization(); err != nil || chosen == nil || chosen.ID != "301" {
		t.Fatalf("anna's migrated legacy context is %+v, %v", chosen, err)
	}

	// Ben signs in and picks his own org; Anna's selection must NOT be wiped!
	signIn(t, "usr_ben")
	if chosen, err := ChosenOrganization(); err != nil || chosen != nil {
		t.Fatalf("ben unexpectedly sees anna's context: %+v, %v", chosen, err)
	}
	if err := ChooseOrganization("402", "beta-robotics"); err != nil {
		t.Fatalf("ben ChooseOrganization failed: %v", err)
	}

	// Switch back to Anna: her "301" org must still be intact!
	signIn(t, "usr_anna")
	if chosen, err := ChosenOrganization(); err != nil || chosen == nil || chosen.ID != "301" {
		t.Fatalf("anna's org was clobbered by ben: %+v, %v", chosen, err)
	}

	if err := ClearOrganization(); err != nil {
		t.Fatalf("clearing anna's org failed: %v", err)
	}
	if chosen, err := ChosenOrganization(); err != nil || chosen != nil {
		t.Errorf("anna's cleared context is %+v, %v", chosen, err)
	}

	// Ben's org must still survive after Anna clears hers.
	signIn(t, "usr_ben")
	if chosen, err := ChosenOrganization(); err != nil || chosen == nil || chosen.ID != "402" {
		t.Fatalf("ben's org was lost when anna cleared hers: %+v, %v", chosen, err)
	}
}
