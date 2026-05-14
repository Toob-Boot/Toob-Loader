package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

var chipCmd = &cobra.Command{
	Use:   "chip",
	Short: "Manage chip HAL packages",
}

var chipListCmd = &cobra.Command{
	Use:   "list [query]",
	Short: "List all chips available in the registry",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		query := ""
		if len(args) > 0 {
			query = strings.ToLower(args[0])
		}

		cache := registry.NewCache("")

		// Async Matrix Fetch
		matrixChan := make(chan *registry.Matrix, 1)
		go func() {
			m, _ := cache.FetchLiveMatrix()
			matrixChan <- m
		}()

		idx, err := cache.LoadIndex()
		if err != nil {
			return err
		}
		if len(idx.Chips) == 0 {
			ui.Muted("Registry is empty.")
			return nil
		}

		// Wait up to 2 seconds for matrix
		var matrix *registry.Matrix
		select {
		case matrix = <-matrixChan:
		case <-time.After(2 * time.Second):
		}

		headers := []string{"Chip", "Version", "Vendor", "Arch", "Verified CLI"}
		var rows [][]string
		for _, ci := range idx.Chips {
			if query != "" && !strings.Contains(strings.ToLower(ci.Name), query) {
				continue
			}

			verifiedClisStr := "(unverified)"
			if matrix != nil {
				if chipEntry, has := (*matrix)[ci.Name]; has {
					searchVer := strings.TrimPrefix(ci.Version, "v")
					for vKey, verEntry := range chipEntry.Versions {
						if strings.TrimPrefix(vKey, "v") == searchVer {
							var clis []string
							for cliVer, info := range verEntry.VerifiedCliVersions {
								if info.Status == "SUCCESS" {
									clis = append(clis, cliVer)
								}
							}
							if len(clis) > 0 {
								verifiedClisStr = strings.Join(clis, ", ")
							}
							break
						}
					}
				}
			}

			rows = append(rows, []string{ci.Name, ci.Version, ci.Vendor, ci.Arch, verifiedClisStr})
		}

		if len(rows) == 0 {
			ui.Warn("No chips found matching '%s'", query)
			return nil
		}

		ui.Table(headers, rows)
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

		ui.Header(fmt.Sprintf("Chip: %s", ci.Name))

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

		ui.KeyValue("Version", ci.Version)
		ui.KeyValue("Vendor", fmt.Sprintf("%s (v%s)", ci.Vendor, vVer))
		ui.KeyValue("Architecture", fmt.Sprintf("%s (v%s)", ci.Arch, aVer))
		ui.KeyValue("Compiler", ci.CompilerPrefix)
		ui.KeyValue("Registry Path", ci.Path)
		ui.KeyValue("Description", ci.Description)
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
