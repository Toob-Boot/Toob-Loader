// Package paths provides platform-safe path resolution for the Toob CLI.
//
// All Toob-specific filesystem paths flow through this package to guarantee
// cross-platform compatibility (Windows / macOS / Linux).
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultRegistryURL is the upstream toob-registry repository.
	DefaultRegistryURL = "https://github.com/toob-boot/toob-registry.git"
)

// ToobHome returns ~/.toob/, creating it if necessary.
func ToobHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".toob")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// RegistryDir returns the local cache directory for the chip registry.
func RegistryDir() (string, error) {
	if envDir := os.Getenv("TOOB_REGISTRY_DIR"); envDir != "" {
		return envDir, nil
	}

	// If we are inside the Toob-Loader monorepo, use the local submodule to avoid cloning.
	if root, err := FindProjectRoot(""); err == nil {
		submodulePath := filepath.Join(root, "toob-registry")
		if _, err := os.Stat(filepath.Join(submodulePath, "registry.json")); err == nil {
			return submodulePath, nil
		}
	}

	home, err := ToobHome()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "registry")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// FindProjectRoot walks upward from start (or cwd if empty) to locate
// a CMakeLists.txt containing "toob-boot".
func FindProjectRoot(start string) (string, error) {
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	current, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}

	for {
		// Check for Core Developer Monorepo
		cmCandidate := filepath.Join(current, "CMakeLists.txt")
		data, err := os.ReadFile(cmCandidate)
		if err == nil && strings.Contains(string(data), "toob-boot") {
			return current, nil
		}

		// Check for End User Project
		if _, err := os.Stat(filepath.Join(current, "device.toml")); err == nil {
			return current, nil
		}
		if _, err := os.Stat(filepath.Join(current, "toob.lock")); err == nil {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return "", fmt.Errorf("no Toob-Loader project root found (no device.toml, toob.lock or CMakeLists.txt containing 'toob-boot' in any parent of %s)", start)
}

// HALDir returns <project>/toobloader/hal/.
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
