package cmd

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/ui"
)

func newDriverCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "driver",
		Short: "Manage HAL driver packages in the current Toob project",
	}

	c.AddCommand(
		newDriverListCmd(),
		newDriverInfoCmd(),
		newDriverAddCmd(),
		newDriverSpawnCmd(),
		newDriverRemoveCmd(),
	)
	return c
}

func newDriverListCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "list",
		Short: "List installed driver packages",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			pkgs, err := inst.List("driver")
			if err != nil {
				return fmt.Errorf("list driver packages: %w", err)
			}
			if len(pkgs) == 0 {
				ui.Info("No driver packages configured.")
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

func newDriverInfoCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "info <driver[@version]>",
		Short: "Show metadata for a driver package",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			details, err := inst.Info("driver", args[0])
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

func newDriverAddCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "add <driver[@version]>",
		Short: "Add a driver package dependency to the project",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.AddDriver(args[0]); err != nil {
				return err
			}
			ui.Success("Added driver package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newDriverSpawnCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "spawn <driver[@version]>",
		Short: "Vendor a driver package locally into the project workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.SpawnDriver(args[0]); err != nil {
				return err
			}
			ui.Success("Spawned driver package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newDriverRemoveCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "remove <driver>",
		Short: "Remove a driver package from the project",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.RemoveDriver(args[0]); err != nil {
				return err
			}
			ui.Success("Removed driver package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}
