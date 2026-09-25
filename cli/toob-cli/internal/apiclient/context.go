package apiclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/toob-boot/toob/internal/paths"
)

// OrganizationContext is the organization 'toob org use' chose, for the account it was chosen in.
// It is where organization commands start when none is named, and grants nothing: identity checks
// the membership on every request.
type OrganizationContext struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	ID      string `json:"id"`
	Name    string `json:"name"`
}

// ErrNotSignedIn is an organization context asked for without a person signed in.
var ErrNotSignedIn = errors.New("nobody is signed in; run 'toob login' first")

func contextPath() (string, error) {
	home, err := paths.ToobHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "organization.json"), nil
}

// signedInAccount is the person the stored session belongs to.
func signedInAccount() (issuer, subject string, err error) {
	identity := loadCredentials().Identity
	if identity == nil || identity.Subject == "" {
		return "", "", ErrNotSignedIn
	}
	return identity.Issuer, identity.Subject, nil
}

// ChosenOrganization is the signed-in account's context, or nil for the account itself. A context
// chosen by another account is not this one's.
func ChosenOrganization() (*OrganizationContext, error) {
	issuer, subject, err := signedInAccount()
	if err != nil {
		return nil, err
	}
	path, err := contextPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the organization context: %w", err)
	}
	var chosen OrganizationContext
	if err := json.Unmarshal(data, &chosen); err != nil {
		return nil, fmt.Errorf("the organization context in %s cannot be read: %w", path, err)
	}
	if chosen.Issuer != issuer || chosen.Subject != subject {
		return nil, nil
	}
	return &chosen, nil
}

// ChooseOrganization makes an organization the signed-in account's context.
func ChooseOrganization(id, name string) error {
	issuer, subject, err := signedInAccount()
	if err != nil {
		return err
	}
	path, err := contextPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(OrganizationContext{Issuer: issuer, Subject: subject, ID: id, Name: name}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Written aside and renamed, as the credentials are, so a parallel command never reads half.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ClearOrganization makes the account itself the context again.
func ClearOrganization() error {
	path, err := contextPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
