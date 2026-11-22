package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/resolve"
)

var (
	manifestToml         string
	manifestHardware     string
	manifestChipManifest string
	manifestCoreDir      string
	manifestDriverDirs   []string
	manifestCryptoDirs   []string
	manifestArchDir      string
	manifestSoCDir       string
	manifestOutDir       string
)

func appendExistingDir(dst []string, dir string) []string {
	if dir == "" || slices.Contains(dst, dir) {
		return dst
	}
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return append(dst, dir)
	}
	return dst
}

func runManifestCompile(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("could not determine working directory: %w", err)
	}
	compilerRoot, err := paths.FindProjectRoot(cwd)
	if err != nil {
		return fmt.Errorf("could not find project root: %w", err)
	}

	dt, err := manifest.ParseToml(manifestToml)
	if err != nil {
		return err
	}

	sdk := resolve.LocateSDK(cwd, compilerRoot)
	resolvedCoreDir := manifestCoreDir
	if resolvedCoreDir == "" {
		if _, statErr := os.Stat(filepath.Join(sdk.Core, "hal_contract.json")); statErr == nil {
			resolvedCoreDir = sdk.Core
		}
	}

	resolvedArchDir := manifestArchDir
	resolvedCryptoDirs := slices.Clone(manifestCryptoDirs)
	sourceDirs := []string{sdk.Bootloader}
	sourceDirs = appendExistingDir(sourceDirs, sdk.Recovery)
	sourceDirs = appendExistingDir(sourceDirs, sdk.LibToob)
	if manifestChipManifest != "" {
		chipDir := filepath.Dir(manifestChipManifest)
		sourceDirs = append(sourceDirs, chipDir)
		if resolvedArchDir == "" || manifestSoCDir == "" || len(resolvedCryptoDirs) == 0 {
			if raw, readErr := os.ReadFile(manifestChipManifest); readErr == nil {
				var cm manifest.ChipManifest
				if json.Unmarshal(raw, &cm) == nil {
					halRoot := filepath.Join(chipDir, "..", "..")
					if resolvedArchDir == "" && cm.Arch != "" {
						cand := filepath.Join(halRoot, "arch", filepath.FromSlash(cm.Arch))
						if info, statErr := os.Stat(cand); statErr == nil && info.IsDir() {
							resolvedArchDir = cand
						}
						sourceDirs = appendExistingDir(sourceDirs, cand)
					}
					if manifestSoCDir == "" {
						for _, inc := range cm.Includes {
							if strings.HasPrefix(filepath.ToSlash(inc), "soc/") {
								sourceDirs = appendExistingDir(sourceDirs, filepath.Join(halRoot, "soc"))
								break
							}
						}
					}
					if len(resolvedCryptoDirs) == 0 {
						var cmBackend, cmHash, cmPqc string
						if cm.Crypto != nil {
							cmBackend, cmHash, cmPqc = cm.Crypto.Backend, cm.Crypto.Hash, cm.Crypto.Pqc
						}
						for _, sel := range []struct{ slot, name string }{
							{"backend", firstNonEmpty(dt.Crypto.Backend, cmBackend)},
							{"hash", firstNonEmpty(dt.Crypto.Hash, cmHash)},
							{"pqc", firstNonEmpty(dt.Crypto.Pqc, cmPqc)},
						} {
							if sel.name == "" || strings.EqualFold(sel.name, "none") {
								continue
							}
							for _, cand := range []string{
								filepath.Join(cwd, "toobloader", "hal", "crypto", filepath.FromSlash(sel.name)),
								filepath.Join(cwd, "toobloader", "hal", "crypto", sel.slot, filepath.FromSlash(sel.name)),
								filepath.Join(halRoot, "crypto", sel.slot, filepath.FromSlash(sel.name)),
								filepath.Join(halRoot, "crypto", filepath.FromSlash(sel.name)),
							} {
								if _, statErr := os.Stat(filepath.Join(cand, "crypto_manifest.json")); statErr == nil {
									if !slices.Contains(resolvedCryptoDirs, cand) {
										resolvedCryptoDirs = append(resolvedCryptoDirs, cand)
									}
									break
								}
							}
						}
					}
				}
			}
		}
	}
	if resolvedArchDir != "" && !slices.Contains(sourceDirs, resolvedArchDir) {
		sourceDirs = append(sourceDirs, resolvedArchDir)
	}
	if manifestSoCDir != "" && !slices.Contains(sourceDirs, manifestSoCDir) {
		sourceDirs = append(sourceDirs, manifestSoCDir)
	}
	for _, drv := range manifestDriverDirs {
		if drv != "" && !slices.Contains(sourceDirs, drv) {
			sourceDirs = append(sourceDirs, drv)
		}
	}
	for _, cdir := range resolvedCryptoDirs {
		if cdir != "" && !slices.Contains(sourceDirs, cdir) {
			sourceDirs = append(sourceDirs, cdir)
		}
	}

	ctx, err := manifest.Load(manifest.Inputs{
		Device:           dt,
		HardwarePath:     manifestHardware,
		ChipManifestPath: manifestChipManifest,
		CoreDir:          resolvedCoreDir,
		ArchDir:          resolvedArchDir,
		DriverDirs:       manifestDriverDirs,
		CryptoDirs:       resolvedCryptoDirs,
		SourceDirs:       sourceDirs,
		OutDir:           manifestOutDir,
	})
	if err != nil {
		return fmt.Errorf("manifest compiler failed: %w", err)
	}
	if _, err := manifest.Generate(ctx); err != nil {
		return fmt.Errorf("manifest compiler failed: %w", err)
	}
	return nil
}

var manifestCmd = &cobra.Command{
	Use:    "manifest",
	Short:  "Compile device.toml into headers and ld scripts",
	Hidden: true,
	RunE:   runManifestCompile,
}

var manifestCompileCmd = &cobra.Command{
	Use:   "compile",
	Short: "Compile device.toml into headers and ld scripts",
	RunE:  runManifestCompile,
}

func init() {
	manifestCmd.PersistentFlags().StringVar(&manifestToml, "toml", "device.toml", "Path to device.toml")
	manifestCmd.PersistentFlags().StringVar(&manifestHardware, "hardware", "", "Path to hardware.json")
	manifestCmd.PersistentFlags().StringVar(&manifestChipManifest, "chip-manifest", "", "Path to chip_manifest.json")
	manifestCmd.PersistentFlags().StringVar(&manifestCoreDir, "core-dir", "", "Core SDK directory containing hal_contract.json (auto-detected if omitted)")
	manifestCmd.PersistentFlags().StringSliceVar(&manifestDriverDirs, "driver-dir", nil, "Driver package directory containing a driver_manifest.json (repeatable)")
	manifestCmd.PersistentFlags().StringSliceVar(&manifestCryptoDirs, "crypto-dir", nil, "Crypto package directory containing a crypto_manifest.json (repeatable)")
	manifestCmd.PersistentFlags().StringVar(&manifestArchDir, "arch-dir", "", "Architecture package directory")
	manifestCmd.PersistentFlags().StringVar(&manifestSoCDir, "soc-dir", "", "SoC package directory")
	manifestCmd.PersistentFlags().StringVar(&manifestOutDir, "outdir", "build/generated", "Output directory for headers and ld scripts")
	_ = manifestCmd.MarkPersistentFlagRequired("hardware")

	manifestCmd.AddCommand(manifestCompileCmd)
	rootCmd.AddCommand(manifestCmd)
}
