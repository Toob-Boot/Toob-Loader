package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/buildrunner"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/resolve"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/ui"
)

func newInstallCmd() *cobra.Command {
	var (
		manifestPath  string
		profile       string
		locked        bool
		dev           bool
		registrySpec  string
		toolchainPath string
		noLock        bool
	)

	c := &cobra.Command{
		Use:   "install",
		Short: "Resolve, fetch, and verify all Core SDK, HAL packages, and cross-compiler toolchains",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, 10*defaultCmdTimeout)
			defer cancel()

			root, mPath, err := buildrunner.ResolveWorkspaceAndManifest(manifestPath)
			if err != nil {
				return fmt.Errorf("resolve workspace: %w", err)
			}

			dt, err := manifest.ParseToml(mPath)
			if err != nil {
				return fmt.Errorf("parse manifest %s: %w", mPath, err)
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
			remoteURL, localReg, err := buildrunner.ResolveRegistryOverride(registrySpec, root, devMode)
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

			if !locked && !devMode {
				if syncErr := cache.Sync(false, false); syncErr != nil {
					return fmt.Errorf("sync registry index: %w", syncErr)
				}
			}

			idx, err := cache.LoadIndex()
			if err != nil {
				return fmt.Errorf("load registry index: %w", err)
			}

			sdkVer, err := buildrunner.SelectCoreSDKVersion(dt, lf, idx, locked)
			if err != nil {
				return fmt.Errorf("select Core SDK version: %w", err)
			}
			coreDir, coreSHA, err := buildrunner.EnsureCoreSDK(ctx, buildrunner.CoreSDKOptions{
				ProjectRoot: root,
				Version:     sdkVer,
				RegistryURL: remoteURL,
				Index:       idx,
				Lock:        lf,
				DevMode:     devMode,
				Locked:      locked,
			})
			if err != nil {
				return fmt.Errorf("ensure Core SDK: %w", err)
			}

			plan, err := resolve.Resolve(resolve.Input{
				Root:     root,
				Device:   dt,
				Lock:     lf,
				Index:    idx,
				Registry: cache,
				Profile:  profile,
				CoreDir:  coreDir,
				Locked:   locked,
			})
			if err != nil {
				return fmt.Errorf("resolve dependencies: %w", err)
			}

			if err := verifyPlanPackageDirs(plan); err != nil {
				return err
			}

			var compilerDigest string
			if toolchainPath == "" && plan.Toolchain.Name != "" {
				tcDir, tcErr := toolchain.EnsureToolchain(
					ctx,
					plan.Toolchain.Name,
					plan.Toolchain.Prefix,
					plan.Toolchain.CompilerBinary,
					plan.Toolchain.ExpectedVersion,
					cache.Dir(),
				)
				if tcErr != nil {
					return fmt.Errorf("ensure toolchain %s: %w", plan.Toolchain.Name, tcErr)
				}
				compilerDigest = tcDir
			}

			if !locked && !noLock {
				nextLF, lockGenErr := plan.ToLockfile(cache, lf, remoteURL, "", "", coreSHA, compilerDigest)
				if lockGenErr != nil {
					return fmt.Errorf("build lockfile: %w", lockGenErr)
				}
				if saveErr := nextLF.Save(lockPath); saveErr != nil {
					return fmt.Errorf("save lockfile %s: %w", lockPath, saveErr)
				}
			}

			ui.Success("All project dependencies, Core SDK, and toolchains verified and ready.")
			return nil
		},
	}

	c.Flags().StringVarP(&manifestPath, "manifest", "m", "", "Path to device.toml or toob.toml")
	c.Flags().StringVarP(&profile, "profile", "p", "dev", "Build profile (dev or production)")
	c.Flags().BoolVar(&locked, "locked", false, "Require strict lockfile parity without mutating toob.lock")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	c.Flags().StringVar(&registrySpec, "registry", "", "Override registry URL or local directory")
	c.Flags().StringVar(&toolchainPath, "toolchain-path", "", "Skip automatic toolchain download using host bin directory")
	c.Flags().BoolVar(&noLock, "no-lock", false, "Do not update toob.lock")
	return c
}

func verifyPlanPackageDirs(plan *resolve.Plan) error {
	var pathsToCheck []string
	if plan.Chip.Dir != "" {
		pathsToCheck = append(pathsToCheck, plan.Chip.Dir)
	}
	if plan.Arch.Dir != "" {
		pathsToCheck = append(pathsToCheck, plan.Arch.Dir)
	}
	if plan.SoCDir != "" {
		pathsToCheck = append(pathsToCheck, plan.SoCDir)
	}
	for i := range plan.DriverPackages {
		drv := &plan.DriverPackages[i]
		if drv.Dir != "" {
			pathsToCheck = append(pathsToCheck, drv.Dir)
		}
	}
	pathsToCheck = append(pathsToCheck, plan.RecoveryDriverDirs()...)
	pathsToCheck = append(pathsToCheck, plan.CryptoDirs()...)
	pathsToCheck = append(pathsToCheck, plan.RecoveryCryptoDirs()...)

	for _, dir := range pathsToCheck {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("missing resolved package directory %s: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("resolved package path %s is not a directory", dir)
		}
	}
	return nil
}
