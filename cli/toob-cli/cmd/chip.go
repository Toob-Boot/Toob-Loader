package cmd

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/ui"
)

func newChipCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "chip",
		Short: "Manage chip HAL targets in the current Toob project",
	}

	c.AddCommand(
		newChipListCmd(),
		newChipInfoCmd(),
		newChipAddCmd(),
		newChipSpawnCmd(),
		newChipRemoveCmd(),
	)
	return c
}

func newChipListCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "list",
		Short: "List installed chip packages",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			pkgs, err := inst.List("chip")
			if err != nil {
				return fmt.Errorf("list chip packages: %w", err)
			}
			if len(pkgs) == 0 {
				ui.Info("No chip packages configured.")
				return nil
			}
			slices.SortFunc(pkgs, func(a, b installer.InstalledPackage) int {
				return cmp.Compare(a.Name, b.Name)
			})
			for i := range pkgs {
				p := &pkgs[i]
				ui.Info("%-28s %-14s %s", sanitizeDisplay(p.Name), sanitizeDisplay(p.Version), sanitizeDisplay(p.Source))
			}
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newChipInfoCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "info <chip[@version]>",
		Short: "Show metadata for a chip package",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			details, err := inst.Info("chip", args[0])
			if err != nil {
				return err
			}
			printPackageDetails(details)
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newChipAddCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "add <chip[@version]>",
		Short: "Set or add a chip package in the project manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.AddChip(args[0]); err != nil {
				return err
			}
			ui.Success("Added chip package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newChipSpawnCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "spawn <chip[@version]>",
		Short: "Vendor a chip package locally into the project workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.SpawnChip(args[0]); err != nil {
				return err
			}
			ui.Success("Spawned chip package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newChipRemoveCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "remove <chip>",
		Short: "Remove a vendored chip package from the project",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.RemoveChip(args[0]); err != nil {
				return err
			}
			ui.Success("Removed chip package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}
