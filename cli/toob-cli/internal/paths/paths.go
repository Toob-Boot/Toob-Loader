// Package paths provides platform-safe path resolution for the Toob CLI.
//
// All Toob-specific filesystem paths flow through this package to guarantee
// cross-platform compatibility (Windows / macOS / Linux).
package paths

import (
	"fmt"
	"os"
	"path/filepath"
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

// isProjectRoot returns true if dir contains a device.toml or toob.lock.
func isProjectRoot(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "device.toml")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "toob.lock")); err == nil {
		return true
	}
	return false
}

// FindProjectRoot locates the nearest Toob project directory.
//
// Search order:
//  1. Walk upward from start (or cwd) looking for device.toml / toob.lock.
//  2. If nothing found upward, scan one level of child directories.
//  3. If exactly one child matches, return it.
//  4. If multiple children match, return an error listing all candidates.
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

	// Phase 1: Walk upward
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

	// Phase 2: Scan immediate children of the starting directory
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
		msg := fmt.Sprintf("multiple Toob projects found in %s:\n", current)
		for _, c := range candidates {
			msg += fmt.Sprintf("  - %s\n", filepath.Base(c))
		}
		msg += "Use --manifest to specify which device.toml to build."
		return "", fmt.Errorf("%s", msg)
	}
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
