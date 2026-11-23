package cmd

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/ui"
)

func newCryptoCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "crypto",
		Short: "Manage Toob cryptographic backend, hash, and PQC packages",
	}

	c.AddCommand(
		newCryptoListCmd(),
		newCryptoInfoCmd(),
		newCryptoUseCmd(),
		newCryptoSpawnCmd(),
		newCryptoRemoveCmd(),
	)
	return c
}

func newCryptoListCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "list",
		Short: "List installed and configured crypto packages",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			pkgs, err := inst.List("crypto")
			if err != nil {
				return fmt.Errorf("list crypto packages: %w", err)
			}
			if len(pkgs) == 0 {
				ui.Info("No crypto packages configured.")
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

func newCryptoInfoCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "info <pkg[@version]>",
		Short: "Show metadata for a crypto package",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			details, err := inst.Info("crypto", args[0])
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

func newCryptoUseCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "use <slot> <pkg[@version]|none>",
		Short: "Bind a crypto package (or none) to a cryptographic slot (backend, hash, pqc)",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.UseCrypto(args[0], args[1]); err != nil {
				return err
			}
			ui.Success("Updated crypto slot %s -> %s", sanitizeDisplay(args[0]), sanitizeDisplay(args[1]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newCryptoSpawnCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "spawn <pkg[@version]>",
		Short: "Vendor a crypto package locally into the project workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.SpawnCrypto(args[0]); err != nil {
				return err
			}
			ui.Success("Spawned crypto package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}

func newCryptoRemoveCmd() *cobra.Command {
	var dev bool

	c := &cobra.Command{
		Use:   "remove <pkg>",
		Short: "Remove a crypto package from the project",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inst, err := openProjectInstaller(dev)
			if err != nil {
				return err
			}
			if err := inst.RemoveCrypto(args[0]); err != nil {
				return err
			}
			ui.Success("Removed crypto package %s", sanitizeDisplay(args[0]))
			return nil
		},
	}

	c.Flags().BoolVar(&dev, "dev", false, "Use local development registry paths")
	return c
}
