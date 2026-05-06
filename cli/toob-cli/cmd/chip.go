package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
)

var chipCmd = &cobra.Command{
	Use:   "chip",
	Short: "Manage chip HAL packages",
}

var chipListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all chips available in the registry",
	RunE: func(cmd *cobra.Command, args []string) error {
		cache := registry.NewCache("")
		idx, err := cache.LoadIndex()
		if err != nil {
			return err
		}
		if len(idx.Chips) == 0 {
			fmt.Println("Registry is empty.")
			return nil
		}
		fmt.Printf("%-20s %-12s %-16s %-10s\n", "Chip", "Vendor", "Arch", "Version")
		fmt.Println(strings.Repeat("-", 58))
		for _, ci := range idx.Chips {
			fmt.Printf("%-20s %-12s %-16s %-10s\n", ci.Name, ci.Vendor, ci.Arch, ci.Version)
		}
		return nil
	},
}

var chipInfoCmd = &cobra.Command{
	Use:   "info [name]",
	Short: "Show detailed information about a chip",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cache := registry.NewCache("")
		ci, err := cache.GetChip(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("  Name:          %s\n", ci.Name)
		fmt.Printf("  Version:       %s\n", ci.Version)
		
		idx, _ := cache.LoadIndex()
		vVer := "unknown"
		aVer := "unknown"
		if idx != nil {
			if vInfo, ok := idx.Vendors[ci.Vendor]; ok {
				vVer = vInfo.Version
			}
			if aInfo, ok := idx.Archs[ci.Arch]; ok {
				aVer = aInfo.Version
			}
		}
		
		fmt.Printf("  Vendor:        %s (v%s)\n", ci.Vendor, vVer)
		fmt.Printf("  Architecture:  %s (v%s)\n", ci.Arch, aVer)
		fmt.Printf("  Compiler Prefix: %s\n", ci.CompilerPrefix)
		fmt.Printf("  Registry Path:   %s\n", ci.Path)
		fmt.Printf("  Description:   %s\n", ci.Description)
		return nil
	},
}

var chipAddCmd = &cobra.Command{
	Use:   "add [name]",
	Short: "Install a chip HAL from the registry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := paths.FindProjectRoot("")
		if err != nil {
			return err
		}
		cache := registry.NewCache("")
		inst := installer.New(root, cache)
		return inst.Add(args[0])
	},
}

var chipSpawnCmd = &cobra.Command{
	Use:   "spawn [name]",
	Short: "Install a chip HAL as locally editable (tracked by git)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := paths.FindProjectRoot("")
		if err != nil {
			return err
		}
		cache := registry.NewCache("")
		inst := installer.New(root, cache)
		return inst.Spawn(args[0])
	},
}

var chipRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Uninstall a chip HAL and its unshared dependencies",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := paths.FindProjectRoot("")
		if err != nil {
			return err
		}
		cache := registry.NewCache("")
		inst := installer.New(root, cache)
		return inst.Remove(args[0])
	},
}

func init() {
	chipCmd.AddCommand(chipListCmd)
	chipCmd.AddCommand(chipInfoCmd)
	chipCmd.AddCommand(chipAddCmd)
	chipCmd.AddCommand(chipSpawnCmd)
	chipCmd.AddCommand(chipRemoveCmd)
}
