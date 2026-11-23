package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/regcheck"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/toob-boot/toob/internal/updater"
)

// Version is injected at build time via -ldflags.
var Version = "dev"

// Execute initializes CLI terminal UI, builds a fresh root command tree, and executes it.
func Execute() error {
	ui.Init()
	rootCmd := NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		ui.Error("%v", err)
		return err
	}
	return nil
}

// NewRootCmd constructs an isolated Toob CLI command tree with zero package-global state.
func NewRootCmd() *cobra.Command {
	var (
		noUpdateCheck bool
		updateCh      chan *updater.CheckResult
		regCheckCh    <-chan *regcheck.Result
	)

	rootCmd := &cobra.Command{
		Use:           "toob",
		Short:         "Toob-Boot declarative bootloader toolchain & registry CLI",
		Version:       Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if shouldSkipBackgroundChecks(cmd, noUpdateCheck) {
				return
			}

			updateCh = make(chan *updater.CheckResult, 1)
			go func() {
				res, err := updater.CheckForUpdate(Version, false, false)
				if err == nil && res != nil && res.Available {
					updateCh <- res
					return
				}
				close(updateCh)
			}()

			regCheckCh = regcheck.CheckAsync()
		},
		PersistentPostRun: func(_ *cobra.Command, _ []string) {
			if updateCh != nil {
				select {
				case res, ok := <-updateCh:
					if ok && res != nil && res.Available {
						ui.UpdateBanner(Version, sanitizeDisplay(res.Version))
					}
				case <-time.After(150 * time.Millisecond):
				}
			}
			if regCheckCh != nil {
				select {
				case res, ok := <-regCheckCh:
					if ok && res != nil && (res.Outdated || len(res.ChipWarnings) > 0) {
						ui.RegistryBanner(sanitizeDisplay(res.CurrentVersion), sanitizeDisplay(res.LatestVersion), res.ChipWarnings)
					}
				case <-time.After(150 * time.Millisecond):
				}
			}
		},
	}

	rootCmd.PersistentFlags().BoolVar(&noUpdateCheck, "no-update-check", false, "Disable background update and registry security checks")

	rootCmd.AddGroup(
		&cobra.Group{ID: "firmware", Title: "Firmware Build, Signing & Provisioning:"},
		&cobra.Group{ID: "packages", Title: "Registry & HAL Packages:"},
		&cobra.Group{ID: "account", Title: "Account, Auth & Registry Admin:"},
	)

	addGrouped := func(groupID string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = groupID
			rootCmd.AddCommand(c)
		}
	}

	addGrouped("firmware",
		newInitCmd(),
		newBuildCmd(),
		newSignCmd(),
		newProvisionCmd(),
		newManifestCmd(),
		newDoctorCmd(),
		newCleanCmd(),
	)

	addGrouped("packages",
		newPkgCmd(),
		newChipCmd(),
		newDriverCmd(),
		newCryptoCmd(),
		newInstallCmd(),
		newRegistryCmd(),
		newAuditCmd(),
		newConformanceCmd(),
		newLiteralLintCmd(),
		newPublishCmd(),
	)

	addGrouped("account",
		newLoginCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
		newStepUpCmd(),
		newOrgCmd(),
		newTokensCmd(),
		newSettingsCmd(),
		newAdminCmd(),
		newUpdateCmd(),
	)

	rootCmd.AddCommand(
		newBudgetCmd(),
		newELFAuditCmd(),
	)

	return rootCmd
}

func shouldSkipBackgroundChecks(cmd *cobra.Command, flagDisabled bool) bool {
	if flagDisabled || Version == "dev" || paths.IsDevMode() {
		return true
	}
	if os.Getenv("CI") != "" || os.Getenv("TOOB_NO_UPDATE_CHECK") != "" {
		return true
	}
	if !ui.IsInteractive() {
		return true
	}
	if cmd == nil || cmd.Hidden {
		return true
	}
	switch cmd.Name() {
	case "update", "version", "help", "__complete", "budget", "elfaudit":
		return true
	default:
		return false
	}
}
