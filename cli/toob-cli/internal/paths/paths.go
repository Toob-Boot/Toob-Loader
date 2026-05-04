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

	projectMarker    = "CMakeLists.txt"
	projectSignature = "toob-boot"
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

// RegistryDir returns ~/.toob/registry/.
func RegistryDir() (string, error) {
	home, err := ToobHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "registry"), nil
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
		candidate := filepath.Join(current, projectMarker)
		data, err := os.ReadFile(candidate)
		if err == nil && strings.Contains(string(data), projectSignature) {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return "", fmt.Errorf("no Toob-Loader project root found (no %s containing '%s' in any parent of %s)",
		projectMarker, projectSignature, start)
}

// HALDir returns <project>/bootloader/hal/.
func HALDir(projectRoot string) string {
	return filepath.Join(projectRoot, "bootloader", "hal")
}

// LockfilePath returns <project>/toob.lock.
func LockfilePath(projectRoot string) string {
	return filepath.Join(projectRoot, "toob.lock")
}

// GitignorePath returns <project>/.gitignore.
func GitignorePath(projectRoot string) string {
	return filepath.Join(projectRoot, ".gitignore")
}
