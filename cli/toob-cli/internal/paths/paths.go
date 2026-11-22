// Package paths provides platform-safe path resolution for the Toob CLI.
//
// All Toob-specific filesystem paths flow through this package to guarantee
// cross-platform compatibility (Windows / macOS / Linux).
package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultRegistryURL is the upstream API endpoint for registry operations.
	DefaultRegistryURL = "https://registry.the-toob.com"

	// LegacyGitRegistryURL is the GitHub repository URL retained for migration compatibility.
	LegacyGitRegistryURL = "https://github.com/toob-boot/toob-registry.git"
)

// IsDevMode reports whether TOOB_DEV is enabled ("1" or case-insensitive "true").
func IsDevMode() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TOOB_DEV")))
	return v == "1" || v == "true"
}

// ToobHome returns the Toob home directory (TOOB_HOME override or ~/.toob),
// normalized via filepath.Abs and created with mode 0o700 if missing.
func ToobHome() (string, error) {
	var dir string
	if envHome := strings.TrimSpace(os.Getenv("TOOB_HOME")); envHome != "" {
		absHome, err := filepath.Abs(envHome)
		if err != nil {
			return "", fmt.Errorf("invalid TOOB_HOME path %q: %w", envHome, err)
		}
		dir = absHome
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		absDir, err := filepath.Abs(filepath.Join(home, ".toob"))
		if err != nil {
			return "", fmt.Errorf("cannot normalize home directory: %w", err)
		}
		dir = absDir
	}

	//nolint:gosec // G703: dir is canonicalized TOOB_HOME or ~/.toob directory.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// RegistryDir returns the local cache directory for the package registry.
func RegistryDir() (string, error) {
	if envDir := strings.TrimSpace(os.Getenv("TOOB_REGISTRY_DIR")); envDir != "" {
		absDir, err := filepath.Abs(envDir)
		if err != nil {
			return "", fmt.Errorf("invalid TOOB_REGISTRY_DIR %q: %w", envDir, err)
		}
		return absDir, nil
	}

	if IsDevMode() {
		if cwd, err := os.Getwd(); err == nil {
			curr, absErr := filepath.Abs(cwd)
			if absErr == nil {
				for {
					cand1 := filepath.Join(curr, "toob-infra", "registry", "packages")
					if isRegularOrFile(filepath.Join(cand1, "registry.json")) {
						return cand1, nil
					}
					cand2 := filepath.Join(curr, "registry", "packages")
					if isRegularOrFile(filepath.Join(cand2, "registry.json")) {
						return cand2, nil
					}
					parent := filepath.Dir(curr)
					if parent == curr {
						break
					}
					curr = parent
				}
			}
		}
	}

	home, err := ToobHome()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "registry")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func isRegularOrFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// isProjectRoot returns true if dir contains a non-directory device.toml or toob.lock.
func isProjectRoot(dir string) bool {
	return isRegularOrFile(filepath.Join(dir, "device.toml")) ||
		isRegularOrFile(filepath.Join(dir, "toob.lock"))
}

func resolveStartDir(start string) (string, error) {
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	return filepath.Abs(start)
}

// FindProjectRootStrict locates the nearest Toob project directory by walking
// strictly upward from startDir (or cwd when empty). Unlike FindProjectRoot,
// it never descends into child directories, making it safe for destructive commands.
func FindProjectRootStrict(startDir string) (string, error) {
	current, err := resolveStartDir(startDir)
	if err != nil {
		return "", err
	}

	dir := current
	for {
		if isProjectRoot(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("no Toob project found (no device.toml or toob.lock in %s or any parent directory)", current)
}

// FindProjectRootFromManifest resolves the workspace project root for an explicit
// device.toml path by walking upward from its directory for toob.lock, falling
// back to the manifest's own directory.
func FindProjectRootFromManifest(manifestPath string) (string, error) {
	if strings.TrimSpace(manifestPath) == "" {
		return "", errors.New("manifest path must not be empty")
	}
	absManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return "", fmt.Errorf("invalid manifest path %q: %w", manifestPath, err)
	}
	manifestDir := filepath.Dir(absManifest)

	dir := manifestDir
	for {
		if isRegularOrFile(filepath.Join(dir, "toob.lock")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return manifestDir, nil
}

// FindProjectRoot locates the nearest Toob project directory, walking upward first
// and scanning immediate child directories if none is found upward.
func FindProjectRoot(start string) (string, error) {
	if root, err := FindProjectRootStrict(start); err == nil {
		return root, nil
	}

	current, err := resolveStartDir(start)
	if err != nil {
		return "", err
	}

	entries, err := os.ReadDir(current)
	if err != nil {
		return "", fmt.Errorf("no Toob project found (no device.toml or toob.lock in any parent of %s)", current)
	}

	var candidates []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		childDir := filepath.Join(current, entry.Name())
		if isProjectRoot(childDir) {
			candidates = append(candidates, childDir)
		}
	}

	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("no Toob project found (no device.toml or toob.lock in any parent or child of %s)", current)
	case 1:
		return candidates[0], nil
	default:
		var msg strings.Builder
		fmt.Fprintf(&msg, "multiple Toob projects found in %s:\n", current)
		for _, c := range candidates {
			fmt.Fprintf(&msg, "  - %s\n", filepath.Base(c))
		}
		msg.WriteString("Run the command inside the target project directory or pass --manifest where supported.")
		return "", fmt.Errorf("%s", msg.String())
	}
}

// HALDir returns <project>/toobloader/hal.
func HALDir(projectRoot string) string {
	return filepath.Join(projectRoot, "toobloader", "hal")
}

// LockfilePath returns <project>/toob.lock.
func LockfilePath(projectRoot string) string {
	return filepath.Join(projectRoot, "toob.lock")
}

// GitignorePath returns <project>/.gitignore.
func GitignorePath(projectRoot string) string {
	return filepath.Join(projectRoot, ".gitignore")
}

// CredentialsPath returns <ToobHome>/credentials.json.
func CredentialsPath() (string, error) {
	home, err := ToobHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "credentials.json"), nil
}
