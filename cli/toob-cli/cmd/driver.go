package cmd

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

func formatTierBadge(tier string) string {
	switch strings.ToLower(tier) {
	case "official":
		return ui.Green("official")
	case "partner":
		return ui.Cyan("partner")
	case "local":
		return ui.Yellow("local")
	default:
		return ui.Gray("community")
	}
}

var (
	flagDriverTrait string
	flagDriverTier  string
)

var driverCmd = &cobra.Command{
	Use:   "driver",
	Short: "Discover, inspect, and spawn HAL driver packages",
}

var driverListCmd = &cobra.Command{
	Use:   "list [query]",
	Short: "List driver packages in the registry (official, partner, and community)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		query := ""
		if len(args) > 0 {
			query = strings.ToLower(args[0])
		}
		traitFilter := strings.ToLower(strings.TrimSpace(flagDriverTrait))
		tierFilter := strings.ToLower(strings.TrimSpace(flagDriverTier))

		cache := registry.NewCache("")
		idx, err := cache.LoadIndex()
		if err != nil {
			return err
		}
		if len(idx.Drivers) == 0 {
			ui.Muted("No driver packages available in registry.")
			return nil
		}

		ui.Header("Driver Registry")

		headers := []string{"Driver", "Version", "Trait", "Tier", "Description"}
		var rows [][]string
		for _, key := range slices.Sorted(maps.Keys(idx.Drivers)) {
			di := idx.Drivers[key]
			trait := di.Trait
			if trait == "" {
				trait = di.Category
			}
			tier := registry.ClassifyTier(di.Name, di.Author, di.Tier, false)
			if query != "" && !strings.Contains(strings.ToLower(di.Name), query) && !strings.Contains(strings.ToLower(di.Description), query) {
				continue
			}
			if traitFilter != "" && strings.ToLower(trait) != traitFilter && strings.ToLower(di.Category) != traitFilter {
				continue
			}
			if tierFilter != "" && strings.ToLower(tier) != tierFilter {
				continue
			}
			rows = append(rows, []string{
				ui.Bold(di.Name),
				ui.Brand(di.Version),
				ui.Cyan(trait),
				formatTierBadge(tier),
				di.Description,
			})
		}

		if len(rows) == 0 {
			ui.Warn("No driver packages matched your filter.")
			return nil
		}

		ui.Table(headers, rows)
		ui.Muted("%d driver package(s) available.", len(rows))
		return nil
	},
}

var driverInfoCmd = &cobra.Command{
	Use:   "info [name]",
	Short: "Show detailed metadata and trust tier of a driver package",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cache := registry.NewCache("")
		di, err := cache.GetDriver(args[0])
		if err != nil {
			return err
		}

		tier := registry.ClassifyTier(di.Name, di.Author, di.Tier, false)
		trait := di.Trait
		if trait == "" {
			trait = di.Category
		}

		ui.Header(fmt.Sprintf("Driver: %s", di.Name))
		fmt.Fprintln(os.Stderr)
		ui.KeyValue("Version", ui.BoldBrand(di.Version))
		ui.KeyValue("Trust Tier", formatTierBadge(tier))
		ui.KeyValue("Trait", ui.Cyan(trait))
		if di.Category != "" {
			ui.KeyValue("Category", di.Category)
		}
		if di.Author != "" {
			ui.KeyValue("Author", di.Author)
		}
		ui.KeyValue("Registry Path", ui.Gray(di.Path))
		if di.Description != "" {
			ui.KeyValue("Description", di.Description)
		}
		ui.Divider()
		return nil
	},
}

var driverSpawnCmd = &cobra.Command{
	Use:   "spawn [name]",
	Short: "Copy a driver package into toobloader/hal/drivers/ as locally editable",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := paths.FindProjectRoot("")
		if err != nil {
			return err
		}
		cache := registry.NewCache("")
		inst := installer.New(root, cache)
		return inst.SpawnDriver(args[0])
	},
}

func init() {
	driverListCmd.Flags().StringVar(&flagDriverTrait, "trait", "", "Filter drivers by HAL trait (e.g. keystore, flash, wdt, entropy)")
	driverListCmd.Flags().StringVar(&flagDriverTier, "tier", "", "Filter drivers by trust tier (official, partner, community)")

	driverCmd.AddCommand(driverListCmd)
	driverCmd.AddCommand(driverInfoCmd)
	driverCmd.AddCommand(driverSpawnCmd)
}

