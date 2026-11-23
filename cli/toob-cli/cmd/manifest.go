package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/buildrunner"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

func newManifestCmd() *cobra.Command {
	var (
		manifestFlag string
		tomlFlag     string
		outDir       string
		profile      string
		halRoot      string
		coreDir      string
		integration  string
		registrySpec string
		locked       bool
		dev          bool
		mock         []string
	)

	c := &cobra.Command{
		Use:   "manifest",
		Short: "Generate declarative CMake, linker, and header files from device.toml",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, 5*defaultCmdTimeout)
			defer cancel()

			chosenManifest := manifestFlag
			if chosenManifest == "" {
				chosenManifest = tomlFlag
			}

			root, manifestPath, err := buildrunner.ResolveWorkspaceAndManifest(chosenManifest)
			if err != nil {
				return fmt.Errorf("resolve workspace and manifest: %w", err)
			}

			dt, err := manifest.ParseToml(manifestPath)
			if err != nil {
				return fmt.Errorf("parse manifest %s: %w", manifestPath, err)
			}

			lockPath := paths.LockfilePath(root)
			lf, lockErr := lockfile.Load(lockPath)
			if lockErr != nil {
				if locked || !os.IsNotExist(lockErr) {
					return fmt.Errorf("load lockfile %s: %w", lockPath, lockErr)
				}
				lf = nil
			}

			devMode := dev || paths.IsDevMode()
			remoteReg, localReg, err := buildrunner.ResolveRegistryOverride(registrySpec, root, devMode)
			if err != nil {
				return err
			}

			var cache *registry.Cache
			if localReg != "" {
				cache, err = registry.OpenForProject(localReg, true)
			} else {
				cache, err = registry.OpenForProject(root, devMode)
			}
			if err != nil {
				return fmt.Errorf("open registry: %w", err)
			}

			idx, err := cache.LoadIndex()
			if err != nil {
				return fmt.Errorf("load registry index: %w", err)
			}

			resolvedCore := coreDir
			if resolvedCore == "" {
				sdkVer, selErr := buildrunner.SelectCoreSDKVersion(dt, lf, idx, locked)
				if selErr != nil {
					return fmt.Errorf("select Core SDK version: %w", selErr)
				}
				dir, _, sdkErr := buildrunner.EnsureCoreSDK(ctx, buildrunner.CoreSDKOptions{
					ProjectRoot: root,
					Version:     sdkVer,
					RegistryURL: remoteReg,
					Index:       idx,
					Lock:        lf,
					DevMode:     devMode,
					Locked:      locked,
				})
				if sdkErr != nil {
					return fmt.Errorf("ensure Core SDK: %w", sdkErr)
				}
				resolvedCore = dir
			}

			if outDir == "" {
				outDir = filepath.Join(root, "build", "generated")
			}

			_, inputs, err := buildrunner.PrepareManifestInputs(
				root,
				dt,
				lf,
				cache,
				idx,
				resolvedCore,
				halRoot,
				profile,
				integration,
				mock,
				cmd.Flags().Changed("mock"),
				locked,
				outDir,
			)
			if err != nil {
				return fmt.Errorf("prepare manifest inputs: %w", err)
			}

			mctx, err := manifest.Load(inputs)
			if err != nil {
				return fmt.Errorf("validate build manifest context: %w", err)
			}

			if _, err := manifest.Generate(mctx); err != nil {
				return fmt.Errorf("generate manifest artifacts: %w", err)
			}

			ui.Success("Generated manifest artifacts in %s", outDir)
			return nil
		},
	}

	c.Flags().StringVarP(&manifestFlag, "manifest", "m", "", "Path to device.toml or toob.toml")
	c.Flags().StringVar(&tomlFlag, "toml", "", "Alias for --manifest")
	c.Flags().StringVarP(&outDir, "out-dir", "o", "", "Output directory for generated files (default: <project>/build/generated)")
	c.Flags().StringVarP(&profile, "profile", "p", "dev", "Build profile (dev or production)")
	c.Flags().StringVar(&halRoot, "hal-root", "", "Override local HAL packages root")
	c.Flags().StringVar(&coreDir, "core-dir", "", "Override Core SDK source directory")
	c.Flags().StringVar(&integration, "integration", "", "Override integration package name[@version]")
	c.Flags().StringVar(&registrySpec, "registry", "", "Override registry URL or local directory")
	c.Flags().BoolVar(&locked, "locked", false, "Require strict lockfile parity")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	c.Flags().StringSliceVar(&mock, "mock", nil, "Hardware mock overrides")
	return c
}
