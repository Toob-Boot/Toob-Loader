package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/scaffold"
	"github.com/toob-boot/toob/internal/ui"
)

type initOptions struct {
	chip        string
	integration string
	halRoot     string
	registry    string
	pkg         string
	noGit       bool
	dev         bool
}

func newInitCmd() *cobra.Command {
	var opts initOptions

	c := &cobra.Command{
		Use:   "init [project-name]",
		Short: "Scaffold a new declarative Toob-Boot firmware project",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := ""
			if len(args) == 1 {
				projectName = strings.TrimSpace(args[0])
			}

			targetDir, rollbackDir, chipName, integrationName, err := setupInitProject(projectName, opts)
			if err != nil {
				return err
			}

			if !opts.noGit {
				if gitErr := initGitRepo(cmd, targetDir); gitErr != nil {
					if rollbackDir != "" {
						_ = os.RemoveAll(rollbackDir)
					}
					return gitErr
				}
			}

			ui.Success("Initialized Toob project %s (chip=%s, integration=%s)", targetDir, sanitizeDisplay(chipName), sanitizeDisplay(integrationName))
			return nil
		},
	}

	c.Flags().StringVar(&opts.chip, "chip", "", "Target chip identifier (e.g. stm32f407)")
	c.Flags().StringVar(&opts.integration, "integration", "", "Build integration template (e.g. esp-idf, zephyr, standalone)")
	c.Flags().StringVar(&opts.halRoot, "hal-root", "", "Local HAL packages root override")
	c.Flags().StringVar(&opts.registry, "registry", "", "Registry URL or local directory override")
	c.Flags().StringVar(&opts.pkg, "package", "", "Optional chip/board package reference (@scope/pkg[@ver])")
	c.Flags().BoolVar(&opts.noGit, "no-git", false, "Skip running git init in the new project")
	c.Flags().BoolVar(&opts.dev, "dev", false, "Use local development registry paths")
	return c
}

func setupInitProject(projectName string, opts initOptions) (targetDir, rollbackDir, chipName, integrationName string, err error) {
	if projectName == "" && opts.pkg != "" {
		pkgName, _, parseErr := installer.ParsePackageRef(opts.pkg)
		if parseErr != nil {
			return "", "", "", "", fmt.Errorf("invalid --package %q: %w", opts.pkg, parseErr)
		}
		projectName = safeSlugForPackage(pkgName)
	}
	if projectName == "" {
		projectName = "toob-firmware"
	}

	targetDir, err = filepath.Abs(projectName)
	if err != nil {
		return "", "", "", "", fmt.Errorf("resolve project path %q: %w", projectName, err)
	}

	existed := false
	if _, statErr := os.Stat(targetDir); statErr == nil {
		existed = true
	}

	if mkErr := os.MkdirAll(targetDir, 0o750); mkErr != nil {
		return "", "", "", "", fmt.Errorf("create project directory %s: %w", targetDir, mkErr)
	}
	if !existed {
		rollbackDir = targetDir
	}
	defer func() {
		if err != nil && rollbackDir != "" {
			_ = os.RemoveAll(rollbackDir)
		}
	}()

	devMode := opts.dev || paths.IsDevMode()
	var idx *registry.Index
	var cache *registry.Cache

	if opts.halRoot == "" {
		var openErr error
		if opts.registry != "" {
			cache, openErr = registry.OpenForProject(opts.registry, true)
		} else {
			cache, openErr = registry.OpenForProject(targetDir, devMode)
		}
		if openErr == nil && cache != nil {
			loadedIdx, idxErr := cache.LoadIndex()
			if idxErr == nil {
				idx = loadedIdx
			}
		}
	}

	chipName = strings.TrimSpace(opts.chip)
	if chipName == "" && opts.pkg != "" {
		name, _, parseErr := installer.ParsePackageRef(opts.pkg)
		if parseErr != nil {
			return "", "", "", "", fmt.Errorf("parse package ref %q: %w", opts.pkg, parseErr)
		}
		chipName = name
	}

	integrationName = strings.TrimSpace(opts.integration)
	if integrationName == "" {
		if idx != nil && len(idx.Integrations) > 0 {
			names := make([]string, 0, len(idx.Integrations))
			for k := range idx.Integrations {
				names = append(names, k)
			}
			slices.Sort(names)
			if ui.IsInteractive() {
				selIdx, selErr := ui.Select("Select build integration", names)
				if selErr != nil {
					return "", "", "", "", selErr
				}
				integrationName = names[selIdx]
			} else {
				integrationName = names[0]
			}
		} else {
			integrationName = "standalone"
		}
	}

	var chipInfoPtr *registry.ChipInfo
	if chipName != "" && idx != nil {
		if ci, ok := idx.Chips[chipName]; ok {
			chipCopy := ci
			chipInfoPtr = &chipCopy
		}
	}

	scCtx := scaffold.Context{
		ProjectName: filepath.Base(targetDir),
		ProjectDir:  targetDir,
		ChipName:    chipName,
		ChipInfo:    chipInfoPtr,
		Cache:       cache,
	}

	if integrationName != "" && integrationName != "standalone" {
		gen := &scaffold.IntegrationGenerator{Framework: integrationName}
		if genErr := gen.Generate(scCtx); genErr != nil {
			return "", "", "", "", fmt.Errorf("generate integration scaffold: %w", genErr)
		}
	} else {
		if genErr := scaffold.GenerateDeviceToml(scCtx); genErr != nil {
			return "", "", "", "", fmt.Errorf("generate device.toml: %w", genErr)
		}
	}

	return targetDir, rollbackDir, chipName, integrationName, nil
}

func initGitRepo(cmd *cobra.Command, targetDir string) error {
	if _, lookErr := exec.LookPath("git"); lookErr != nil {
		return nil
	}
	if _, gitStat := os.Stat(filepath.Join(targetDir, ".git")); !os.IsNotExist(gitStat) {
		return nil
	}
	ctx, cancel := commandContext(cmd, defaultCmdTimeout)
	defer cancel()
	return runGitInit(ctx, targetDir)
}

func runGitInit(ctx context.Context, targetDir string) error {
	gitCmd := exec.CommandContext(ctx, "git", "init")
	gitCmd.Dir = targetDir
	if out, gitErr := gitCmd.CombinedOutput(); gitErr != nil {
		return fmt.Errorf("git init in %s failed: %w (%s)", targetDir, gitErr, strings.TrimSpace(string(out)))
	}
	return nil
}

func safeSlugForPackage(pkgName string) string {
	cleaned := strings.TrimPrefix(strings.TrimSpace(pkgName), "@")
	cleaned = strings.ReplaceAll(cleaned, "/", "-")
	cleaned = strings.ReplaceAll(cleaned, "..", "-")
	if cleaned == "" {
		return "toob-firmware"
	}
	return cleaned
}
