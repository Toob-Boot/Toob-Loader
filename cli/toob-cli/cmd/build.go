package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/buildrunner"
)

func newBuildCmd() *cobra.Command {
	var (
		native        bool
		docker        bool
		locked        bool
		profile       string
		mock          []string
		manifestPath  string
		buildDir      string
		outDir        string
		toolchainPath string
		dev           bool
		containerArch string
		compilerImage string
		registrySpec  string
		integration   string
		stage0        bool
		clean         bool
		verbose       bool
		noCCache      bool
		skipChecks    bool
		noPull        bool
	)

	c := &cobra.Command{
		Use:   "build",
		Short: "Compile and package Toob-Boot firmware from a declarative device manifest",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, 0)
			defer cancel()

			mockChanged := cmd.Flags().Changed("mock")
			noUpdateCheck, _ := cmd.Flags().GetBool("no-update-check")

			if docker {
				mockVal, err := buildrunner.CanonicalizeMockFlagValue(strings.Join(mock, ","), mockChanged)
				if err != nil {
					return err
				}
				return buildrunner.RunDocker(ctx, buildrunner.DockerOptions{
					ManifestPath:  manifestPath,
					BuildDir:      buildDir,
					OutDir:        outDir,
					Profile:       profile,
					ToolchainPath: toolchainPath,
					CompilerImage: compilerImage,
					ContainerArch: containerArch,
					RegistryURL:   registrySpec,
					Integration:   integration,
					MockValue:     mockVal,
					MockChanged:   mockChanged,
					Stage0Only:    stage0,
					Clean:         clean,
					Locked:        locked,
					DevMode:       dev,
					Verbose:       verbose,
					NoCCache:      noCCache,
					NoUpdateCheck: noUpdateCheck,
					SkipChecks:    skipChecks,
					NoPull:        noPull,
					CLIVersion:    Version,
					Stdout:        cmd.OutOrStdout(),
					Stderr:        cmd.ErrOrStderr(),
				})
			}

			_ = native // Native runner is the default when --docker is unset.
			_, err := buildrunner.RunNative(ctx, buildrunner.NativeOptions{
				ManifestPath:  manifestPath,
				BuildDir:      buildDir,
				OutDir:        outDir,
				Profile:       profile,
				ToolchainPath: toolchainPath,
				RegistryURL:   registrySpec,
				Integration:   integration,
				MockOverrides: mock,
				MockSet:       mockChanged,
				Stage0Only:    stage0,
				Clean:         clean,
				Locked:        locked,
				DevMode:       dev,
				Verbose:       verbose,
				NoCCache:      noCCache,
				NoUpdateCheck: noUpdateCheck,
				SkipChecks:    skipChecks,
				CLIVersion:    Version,
				Stdout:        cmd.OutOrStdout(),
				Stderr:        cmd.ErrOrStderr(),
			})
			if err != nil {
				return fmt.Errorf("build failed: %w", err)
			}
			return nil
		},
	}

	c.Flags().BoolVar(&native, "native", false, "Build natively on the host toolchain (default)")
	c.Flags().BoolVar(&docker, "docker", false, "Build inside an isolated Toob compiler container")
	c.Flags().BoolVar(&locked, "locked", false, "Require strict toob.lock parity without network or registry mutation")
	c.Flags().StringVarP(&profile, "profile", "p", "dev", "Build profile (dev or production)")
	c.Flags().StringSliceVar(&mock, "mock", nil, "Hardware mock overrides (all, none, or trait list)")
	if f := c.Flags().Lookup("mock"); f != nil {
		f.NoOptDefVal = "all"
	}
	c.Flags().StringVarP(&manifestPath, "manifest", "m", "", "Path to device.toml or toob.toml")
	c.Flags().StringVar(&buildDir, "build-dir", "", "CMake build output directory")
	c.Flags().StringVarP(&outDir, "out-dir", "o", "", "Firmware artifact output directory")
	c.Flags().StringVar(&toolchainPath, "toolchain-path", "", "Override cross-compiler bin directory")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	c.Flags().StringVar(&containerArch, "container-arch", "", "Target container architecture for --docker builds")
	c.Flags().StringVar(&compilerImage, "compiler-image", "", "Override Docker compiler image reference")
	c.Flags().StringVar(&registrySpec, "registry", "", "Override registry URL or local directory")
	c.Flags().StringVar(&integration, "integration", "", "Override integration package name[@version]")
	c.Flags().BoolVar(&stage0, "stage0", false, "Build and pack Stage-0 bootloader image")
	c.Flags().BoolVar(&clean, "clean", false, "Clean build directory before configuring")
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print verbose CMake/Ninja build output")
	c.Flags().BoolVar(&noCCache, "no-ccache", false, "Disable ccache wrapper")
	c.Flags().BoolVar(&skipChecks, "skip-checks", false, "Skip pre-build HAL conformance and literal lint gates")
	c.Flags().BoolVar(&noPull, "no-pull", false, "Do not pull compiler container image in --docker mode")

	c.MarkFlagsMutuallyExclusive("native", "docker")
	return c
}
