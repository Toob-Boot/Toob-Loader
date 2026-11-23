package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/conformance"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

const (
	maxRegistryTarballBytes = 1 << 20 // 1 MiB server limit
	maxRegistryTarballFiles = 128
	maxTarballEntryBytes    = 1 << 20
)

type indexPkgSummary struct {
	Category    string
	Name        string
	Version     string
	Tier        string
	SHA256      string
	Description string
}

func newRegistryCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "registry",
		Short: "Synchronize, inspect, and validate Toob HTTP + Ed25519 registry packages",
	}

	c.AddCommand(
		newRegistrySyncCmd(),
		newRegistryListCmd(),
		newRegistryInfoCmd(),
		newRegistryCheckCmd(),
	)
	return c
}

func newRegistrySyncCmd() *cobra.Command {
	var (
		dev             bool
		verifySignature bool
		revision        string
	)

	c := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize the local package registry cache via HTTPS and Ed25519 index verification",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			devMode := dev || paths.IsDevMode()
			cache, err := registry.OpenForProject(".", devMode)
			if err != nil {
				return fmt.Errorf("open registry: %w", err)
			}

			if err := cache.Sync(devMode, true); err != nil {
				return fmt.Errorf("sync registry index: %w", err)
			}

			if verifySignature {
				if err := cache.VerifyHeadForRevision(revision); err != nil {
					return fmt.Errorf("Ed25519 index signature verification failed: %w", err)
				}
				ui.Success("Verified registry Ed25519 index signature.")
			}

			ui.Success("Registry cache synchronized.")
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Sync against local development registry")
	c.Flags().BoolVar(&verifySignature, "verify-signature", false, "Verify Ed25519 signature over synced index metadata")
	c.Flags().StringVar(&revision, "revision", "", "Expected signed index revision identifier")
	return c
}

func newRegistryListCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "list [category]",
		Short: "List available packages in the synchronized registry index",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cache, err := registry.OpenForProject(".", dev || paths.IsDevMode())
			if err != nil {
				return fmt.Errorf("open registry: %w", err)
			}
			idx, err := cache.LoadIndex()
			if err != nil {
				return fmt.Errorf("load registry index: %w", err)
			}

			cats := allPackageCategories()
			if len(args) == 1 {
				norm, normErr := installer.NormalizeCategory(args[0])
				if normErr != nil {
					return normErr
				}
				cats = []string{norm}
			}

			count := 0
			for _, cat := range cats {
				entries := listIndexCategory(idx, cat)
				for _, entry := range entries {
					count++
					ui.Info("%-12s %-28s %-14s %s", cat, sanitizeDisplay(entry.Name), sanitizeDisplay(entry.Version), formatTierBadge(entry.Tier))
				}
			}
			if count == 0 {
				ui.Info("No packages found in registry index.")
			}
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry")
	return c
}

func newRegistryInfoCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "info <category> <pkg[@version]>",
		Short: "Inspect metadata for a package in the registry index",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			cat, err := installer.NormalizeCategory(args[0])
			if err != nil {
				return err
			}
			name, _, err := installer.ParsePackageRef(args[1])
			if err != nil {
				return err
			}

			cache, err := registry.OpenForProject(".", dev || paths.IsDevMode())
			if err != nil {
				return fmt.Errorf("open registry: %w", err)
			}
			idx, err := cache.LoadIndex()
			if err != nil {
				return fmt.Errorf("load registry index: %w", err)
			}

			entry, ok := findIndexEntry(idx, cat, name)
			if !ok {
				return fmt.Errorf("%s package %q not found in registry index", cat, name)
			}

			ui.Info("Package:  %s/%s", cat, sanitizeDisplay(entry.Name))
			ui.Info("Version:  %s", sanitizeDisplay(entry.Version))
			if entry.Tier != "" {
				ui.Info("Tier:     %s", formatTierBadge(entry.Tier))
			}
			if entry.SHA256 != "" {
				ui.Info("SHA256:   %s", sanitizeDisplay(entry.SHA256))
			}
			if entry.Description != "" {
				ui.Info("Summary:  %s", sanitizeDisplay(entry.Description))
			}
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry")
	return c
}

func newRegistryCheckCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "check [package-dir]",
		Short: "Validate package manifest, tarball size/file gates, and conformance before publishing",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			absDir, err := filepath.Abs(dir)
			if err != nil {
				return fmt.Errorf("resolve package directory %q: %w", dir, err)
			}

			cat, tgzBytes, fileCount, err := buildAndValidatePackageTarball(absDir)
			if err != nil {
				return fmt.Errorf("package gate failed: %w", err)
			}

			report, err := conformance.AuditPackage(absDir)
			if err != nil {
				return fmt.Errorf("conformance audit failed: %w", err)
			}
			if !report.Passed {
				return fmt.Errorf("package %s failed conformance audit with %d failed check(s)", cat, countFailedConformanceChecks(report))
			}

			ui.Success("Registry package check passed (%s: %d files, %d compressed bytes).", cat, fileCount, len(tgzBytes))
			return nil
		},
	}
	return c
}

func listIndexCategory(idx *registry.Index, cat string) []indexPkgSummary {
	if idx == nil {
		return nil
	}
	var out []indexPkgSummary
	switch cat {
	case "chip":
		for k := range idx.Chips {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.Chips[k].Version, Tier: idx.Chips[k].Tier, SHA256: firstNonEmpty(idx.Chips[k].TarballSHA, idx.Chips[k].SHA256), Description: idx.Chips[k].Description})
		}
	case "arch":
		for k := range idx.Archs {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.Archs[k].Version, Tier: idx.Archs[k].Tier, SHA256: firstNonEmpty(idx.Archs[k].TarballSHA, idx.Archs[k].SHA256), Description: idx.Archs[k].Description})
		}
	case "driver":
		for k := range idx.Drivers {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.Drivers[k].Version, Tier: idx.Drivers[k].Tier, SHA256: firstNonEmpty(idx.Drivers[k].TarballSHA, idx.Drivers[k].SHA256), Description: idx.Drivers[k].Description})
		}
	case "crypto":
		for k := range idx.Crypto {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.Crypto[k].Version, Tier: idx.Crypto[k].Tier, SHA256: firstNonEmpty(idx.Crypto[k].TarballSHA, idx.Crypto[k].SHA256), Description: idx.Crypto[k].Description})
		}
	case "soc":
		for k := range idx.SoCs {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.SoCs[k].Version, Tier: idx.SoCs[k].Tier, SHA256: firstNonEmpty(idx.SoCs[k].TarballSHA, idx.SoCs[k].SHA256), Description: idx.SoCs[k].Description})
		}
	case "integration":
		for k := range idx.Integrations {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.Integrations[k].Version, Tier: idx.Integrations[k].Tier, SHA256: firstNonEmpty(idx.Integrations[k].TarballSHA, idx.Integrations[k].SHA256), Description: idx.Integrations[k].Description})
		}
	case "toolchain":
		for k := range idx.Toolchains {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.Toolchains[k].Version, SHA256: idx.Toolchains[k].TarballSHA})
		}
	case "port":
		for k := range idx.Ports {
			out = append(out, indexPkgSummary{Category: cat, Name: k, Version: idx.Ports[k].Version, Tier: idx.Ports[k].Tier, SHA256: firstNonEmpty(idx.Ports[k].TarballSHA, idx.Ports[k].SHA256), Description: idx.Ports[k].Description})
		}
	}
	slices.SortFunc(out, func(a, b indexPkgSummary) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func findIndexEntry(idx *registry.Index, cat, name string) (indexPkgSummary, bool) {
	for _, entry := range listIndexCategory(idx, cat) {
		if entry.Name == name || strings.EqualFold(entry.Name, name) {
			return entry, true
		}
	}
	return indexPkgSummary{}, false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func buildAndValidatePackageTarball(pkgDir string) (string, []byte, int, error) {
	cat, manifestFile, err := detectSinglePackageManifest(pkgDir)
	if err != nil {
		return "", nil, 0, err
	}

	var buf bytes.Buffer
	if tarErr := registry.CreateTarball(pkgDir, &buf); tarErr != nil {
		return "", nil, 0, fmt.Errorf("create package tarball: %w", tarErr)
	}

	tgz := buf.Bytes()
	if len(tgz) > maxRegistryTarballBytes {
		return "", nil, 0, fmt.Errorf("compressed package size %d bytes exceeds %d-byte (1 MiB) registry limit", len(tgz), maxRegistryTarballBytes)
	}

	fileCount, err := validateTarballArchive(tgz, manifestFile)
	if err != nil {
		return "", nil, 0, err
	}
	return cat, tgz, fileCount, nil
}

func detectSinglePackageManifest(pkgDir string) (string, string, error) {
	foundCat := ""
	foundFile := ""

	for _, cat := range allPackageCategories() {
		name := cat + ".toml"
		candidate := filepath.Join(pkgDir, name)
		st, statErr := os.Stat(candidate)
		if statErr == nil && st.Mode().IsRegular() {
			if foundCat != "" {
				return "", "", fmt.Errorf("multiple package manifests found (%s and %s); a package must define exactly one category", foundFile, name)
			}
			foundCat = cat
			foundFile = name
		}
	}

	if foundCat == "" {
		return "", "", fmt.Errorf("no recognized category manifest found in %s (expected one of chip.toml, arch.toml, driver.toml, crypto.toml, soc.toml, integration.toml, toolchain.toml, port.toml)", pkgDir)
	}
	return foundCat, foundFile, nil
}

func validateTarballArchive(tgz []byte, expectedManifest string) (int, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return 0, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(io.LimitReader(gzr, int64(maxRegistryTarballBytes)*4))
	fileCount := 0
	sawManifest := false

	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return 0, fmt.Errorf("corrupt tarball entry: %w", nextErr)
		}

		cleanName := filepath.ToSlash(filepath.Clean(hdr.Name))
		if strings.HasPrefix(cleanName, "/") || strings.HasPrefix(cleanName, "..") || strings.Contains(cleanName, "/../") {
			return 0, fmt.Errorf("tarball contains unsafe path %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			fileCount++
			if fileCount > maxRegistryTarballFiles {
				return 0, fmt.Errorf("tarball contains more than %d files", maxRegistryTarballFiles)
			}
			if hdr.Size > maxTarballEntryBytes {
				return 0, fmt.Errorf("tarball entry %q exceeds %d bytes", hdr.Name, maxTarballEntryBytes)
			}
			if !isAllowedPackageFile(cleanName) {
				return 0, fmt.Errorf("disallowed file extension in package archive: %s", hdr.Name)
			}
			if cleanName == expectedManifest || strings.TrimPrefix(cleanName, "./") == expectedManifest {
				sawManifest = true
			}
		default:
			return 0, fmt.Errorf("disallowed non-regular tar entry %q (type=%d)", hdr.Name, hdr.Typeflag)
		}
	}

	if !sawManifest {
		return 0, fmt.Errorf("package archive does not contain %s at root", expectedManifest)
	}
	return fileCount, nil
}

func isAllowedPackageFile(slashPath string) bool {
	base := filepath.Base(slashPath)
	switch strings.ToLower(filepath.Ext(base)) {
	case ".c", ".h", ".s", ".asm", ".ld", ".cmake", ".toml", ".json", ".md", ".txt", ".py", ".sh", ".yaml", ".yml", ".in", ".def", ".inc":
		return true
	case "":
		switch strings.ToUpper(base) {
		case "LICENSE", "COPYING", "README", "CHANGELOG", "CMAKELISTS.TXT", "MAKEFILE":
			return true
		default:
			return false
		}
	default:
		return false
	}
}
