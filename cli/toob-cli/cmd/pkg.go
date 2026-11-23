package cmd

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/ui"
)

func allPackageCategories() []string {
	return []string{"arch", "chip", "crypto", "driver", "integration", "port", "soc", "toolchain"}
}

func newPkgCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "pkg",
		Short: "Manage Toob packages across all 8 HAL and toolchain categories",
		Long:  "Install, inspect, vendor (spawn), list, and remove packages across chip, arch, driver, crypto, soc, integration, toolchain, and port categories.",
	}

	c.AddCommand(
		newPkgListCmd(),
		newPkgInfoCmd(),
		newPkgAddCmd(),
		newPkgSpawnCmd(),
		newPkgRemoveCmd(),
	)
	return c
}

func newPkgListCmd() *cobra.Command {
	var (
		category string
		dev      bool
	)

	c := &cobra.Command{
		Use:   "list [category]",
		Short: "List installed packages by category or across all categories",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 && category == "" {
				category = args[0]
			} else if len(args) == 1 && category != "" {
				return errors.New("specify category either positionally or via --category, not both")
			}

			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}

			var categories []string
			if strings.TrimSpace(category) != "" {
				norm, normErr := installer.NormalizeCategory(category)
				if normErr != nil {
					return normErr
				}
				categories = []string{norm}
			} else {
				categories = allPackageCategories()
			}

			return printInstalledCategories(inst, categories)
		},
	}

	c.Flags().StringVarP(&category, "category", "c", "", "Filter by package category (chip, arch, driver, crypto, soc, integration, toolchain, port)")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newPkgInfoCmd() *cobra.Command {
	var (
		category string
		dev      bool
	)

	c := &cobra.Command{
		Use:   "info <category> <pkg[@version]> | info --category <cat> <pkg[@version]>",
		Short: "Show metadata and installed status for a package",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			cat, ref, err := resolveCategoryAndPkg(category, args)
			if err != nil {
				return err
			}
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			details, err := inst.Info(cat, ref)
			if err != nil {
				return err
			}
			printPackageDetails(details)
			return nil
		},
	}

	c.Flags().StringVarP(&category, "category", "c", "", "Package category")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newPkgAddCmd() *cobra.Command {
	var (
		category string
		dev      bool
	)

	c := &cobra.Command{
		Use:   "add <category> <pkg[@version]> | add --category <cat> <pkg[@version]>",
		Short: "Add a registry package dependency to the project",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			cat, ref, err := resolveCategoryAndPkg(category, args)
			if err != nil {
				return err
			}
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.Add(cat, ref); err != nil {
				return err
			}
			ui.Success("Added %s package %s", cat, sanitizeDisplay(ref))
			return nil
		},
	}

	c.Flags().StringVarP(&category, "category", "c", "", "Package category")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newPkgSpawnCmd() *cobra.Command {
	var (
		category string
		dev      bool
	)

	c := &cobra.Command{
		Use:   "spawn <category> <pkg[@version]> | spawn --category <cat> <pkg[@version]>",
		Short: "Vendor (spawn) a package locally into the project workspace for customization",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			cat, ref, err := resolveCategoryAndPkg(category, args)
			if err != nil {
				return err
			}
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.Spawn(cat, ref); err != nil {
				return err
			}
			ui.Success("Spawned %s package %s", cat, sanitizeDisplay(ref))
			return nil
		},
	}

	c.Flags().StringVarP(&category, "category", "c", "", "Package category")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newPkgRemoveCmd() *cobra.Command {
	var (
		category string
		dev      bool
	)

	c := &cobra.Command{
		Use:   "remove <category> <pkg> | remove --category <cat> <pkg>",
		Short: "Remove a package from the project configuration",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			cat, name, err := resolveCategoryAndPkg(category, args)
			if err != nil {
				return err
			}
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.Remove(cat, name); err != nil {
				return err
			}
			ui.Success("Removed %s package %s", cat, sanitizeDisplay(name))
			return nil
		},
	}

	c.Flags().StringVarP(&category, "category", "c", "", "Package category")
	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func resolveCategoryAndPkg(categoryFlag string, args []string) (string, string, error) {
	if strings.TrimSpace(categoryFlag) != "" {
		if len(args) != 1 {
			return "", "", errors.New("expected <pkg[@version]> when --category is specified")
		}
		cat, err := installer.NormalizeCategory(categoryFlag)
		if err != nil {
			return "", "", err
		}
		return cat, args[0], nil
	}

	if len(args) != 2 {
		return "", "", errors.New("expected <category> <pkg[@version]> (or pass --category <cat>)")
	}
	cat, err := installer.NormalizeCategory(args[0])
	if err != nil {
		return "", "", err
	}
	return cat, args[1], nil
}

func printInstalledCategories(inst *installer.Installer, categories []string) error {
	total := 0
	for _, cat := range categories {
		pkgs, err := inst.List(cat)
		if err != nil {
			return fmt.Errorf("list %s packages: %w", cat, err)
		}
		if len(pkgs) == 0 {
			continue
		}
		slices.SortFunc(pkgs, func(a, b installer.InstalledPackage) int {
			return cmp.Compare(a.Name, b.Name)
		})
		for i := range pkgs {
			p := &pkgs[i]
			total++
			ver := p.Version
			if ver == "" {
				ver = "local"
			}
			ui.Info("%-12s %-28s %-14s %s", cat, sanitizeDisplay(p.Name), sanitizeDisplay(ver), sanitizeDisplay(p.Source))
		}
	}
	if total == 0 {
		ui.Info("No packages installed.")
	}
	return nil
}

func printPackageDetails(details *installer.PackageDetails) {
	if details == nil {
		return
	}
	ui.Info("Name:        %s", sanitizeDisplay(details.Name))
	ui.Info("Category:    %s", sanitizeDisplay(details.Category))
	ui.Info("Version:     %s", sanitizeDisplay(details.Version))
	if details.Description != "" {
		ui.Info("Description: %s", sanitizeDisplay(details.Description))
	}
	if details.Author != "" {
		ui.Info("Author:      %s", sanitizeDisplay(details.Author))
	}
	if details.Tier != "" {
		ui.Info("Tier:        %s", formatTierBadge(details.Tier))
	}
	if details.Source != "" {
		ui.Info("Source:      %s", sanitizeDisplay(details.Source))
	}
	if details.SHA256 != "" {
		ui.Info("SHA256:      %s", sanitizeDisplay(details.SHA256))
	}
	if details.SpawnedPath != "" {
		ui.Info("Spawned:     %s", sanitizeDisplay(details.SpawnedPath))
	}
	if details.Verified {
		ui.Info("Verified:    true")
	}
}
