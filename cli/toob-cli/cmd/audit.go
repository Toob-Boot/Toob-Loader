package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Check local dependencies for security advisories",
	Long: `Scans the project's toob.lock for installed packages and checks each
against the registry for revocation or security advisories.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		projectRoot, err := paths.FindProjectRoot("")
		if err != nil {
			return fmt.Errorf("not in a Toob project: %w", err)
		}

		lockPath := paths.LockfilePath(projectRoot)
		lockData, err := os.ReadFile(lockPath)
		if err != nil {
			ui.Info("No toob.lock found — nothing to audit.")
			return nil
		}

		// Parse the lockfile to extract installed packages
		var lockfile struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(lockData, &lockfile); err != nil {
			return fmt.Errorf("failed to parse %s: %w", filepath.Base(lockPath), err)
		}

		if len(lockfile.Packages) == 0 {
			ui.Info("No packages in toob.lock — nothing to audit.")
			return nil
		}

		ui.Header("Security Audit")
		client := apiclient.New()

		issues := 0
		for _, pkg := range lockfile.Packages {
			resp, err := client.GetPackage(cmd_defaultCtx(), pkg.Name, pkg.Version)
			if err != nil {
				ui.Warn("%s@%s — could not verify: %v", pkg.Name, pkg.Version, err)
				issues++
				continue
			}

			switch resp.Stage {
			case "revoked":
				ui.Error("%s@%s — REVOKED", pkg.Name, pkg.Version)
				issues++
			case "archived":
				ui.Warn("%s@%s — archived (consider upgrading)", pkg.Name, pkg.Version)
			default:
				ui.CheckItem(true, false, fmt.Sprintf("%s@%s", pkg.Name, pkg.Version), resp.Stage)
			}
		}

		ui.Divider()
		if issues > 0 {
			ui.Error("%d issue(s) found. Update affected packages immediately.", issues)
		} else {
			ui.Success("All %d package(s) passed audit.", len(lockfile.Packages))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
