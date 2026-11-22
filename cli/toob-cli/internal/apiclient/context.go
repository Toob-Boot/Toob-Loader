package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/toob-boot/toob/internal/filelock"
	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/paths"
)

// OrganizationContext is the active organization chosen via 'toob org use' for one account.
type OrganizationContext struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	ID      string `json:"id"`
	Name    string `json:"name"`
}

type organizationStore struct {
	Contexts []OrganizationContext `json:"contexts"`
}

// ErrNotSignedIn indicates that an organization context operation was attempted without an active session.
var ErrNotSignedIn = errors.New("nobody is signed in; run 'toob login' first")

func contextPath() (string, error) {
	home, err := paths.ToobHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "organization.json"), nil
}

func signedInAccount() (issuer, subject string, err error) {
	identity := loadCredentials().Identity
	if identity == nil || identity.Subject == "" {
		return "", "", ErrNotSignedIn
	}
	return identity.Issuer, identity.Subject, nil
}

func loadOrganizationStore(path string) ([]OrganizationContext, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the organization context: %w", err)
	}
	data, readErr := httputil.ReadBounded(f, 1<<20)
	closeErr := f.Close()
	if readErr != nil {
		return nil, fmt.Errorf("reading the organization context: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("closing the organization context: %w", closeErr)
	}

	var multi organizationStore
	if err := json.Unmarshal(data, &multi); err == nil && multi.Contexts != nil {
		return multi.Contexts, nil
	}

	var legacy OrganizationContext
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("the organization context in %s cannot be read: %w", path, err)
	}
	if legacy.Issuer == "" && legacy.Subject == "" && legacy.ID == "" {
		return nil, nil
	}
	return []OrganizationContext{legacy}, nil
}

func saveOrganizationStore(path string, contexts []OrganizationContext) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if len(contexts) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}

	data, err := json.MarshalIndent(organizationStore{Contexts: contexts}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".toob-org-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func withOrganizationLock(ctx context.Context, fn func(path string) error) error {
	path, err := contextPath()
	if err != nil {
		return err
	}
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	unlock, err := filelock.Lock(lockCtx, path+".lock")
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()

	return fn(path)
}

// ChosenOrganization returns the active organization context for the signed-in account, or nil.
func ChosenOrganization() (*OrganizationContext, error) {
	issuer, subject, err := signedInAccount()
	if err != nil {
		return nil, err
	}
	path, err := contextPath()
	if err != nil {
		return nil, err
	}
	contexts, err := loadOrganizationStore(path)
	if err != nil {
		return nil, err
	}
	for i := range contexts {
		if contexts[i].Issuer == issuer && contexts[i].Subject == subject {
			chosen := contexts[i]
			return &chosen, nil
		}
	}
	return nil, nil
}

// ChooseOrganization persists the active organization for the signed-in account while
// preserving organization choices belonging to other accounts.
func ChooseOrganization(id, name string) error {
	issuer, subject, err := signedInAccount()
	if err != nil {
		return err
	}
	return withOrganizationLock(context.Background(), func(path string) error {
		contexts, loadErr := loadOrganizationStore(path)
		if loadErr != nil {
			return loadErr
		}
		entry := OrganizationContext{Issuer: issuer, Subject: subject, ID: id, Name: name}
		updated := false
		for i := range contexts {
			if contexts[i].Issuer == issuer && contexts[i].Subject == subject {
				contexts[i] = entry
				updated = true
				break
			}
		}
		if !updated {
			contexts = append(contexts, entry)
		}
		return saveOrganizationStore(path, contexts)
	})
}

// ClearOrganization clears the active organization for the currently signed-in account.
func ClearOrganization() error {
	issuer, subject, err := signedInAccount()
	if err != nil {
		return err
	}
	return clearOrganizationForAccount(context.Background(), issuer, subject)
}

func clearOrganizationForAccount(ctx context.Context, issuer, subject string) error {
	if issuer == "" && subject == "" {
		return nil
	}
	return withOrganizationLock(ctx, func(path string) error {
		contexts, loadErr := loadOrganizationStore(path)
		if loadErr != nil {
			if errors.Is(loadErr, os.ErrNotExist) {
				return nil
			}
			return loadErr
		}
		kept := make([]OrganizationContext, 0, len(contexts))
		for _, c := range contexts {
			if c.Issuer == issuer && c.Subject == subject {
				continue
			}
			kept = append(kept, c)
		}
		return saveOrganizationStore(path, kept)
	})
}
