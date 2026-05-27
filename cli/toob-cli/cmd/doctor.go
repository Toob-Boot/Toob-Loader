package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system environment and dependencies for Toob",
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.Header("Toob Environment Doctor")

		type doctorCheck struct {
			name        string
			command     string
			args        []string
			optional    bool
			solution    string
			autoFixCmd  string
			autoFixArgs []string
			autoFixDesc string
		}

		checks := []doctorCheck{
			{"Git", "git", []string{"--version"}, false, "Install Git from https://git-scm.com/", "", nil, ""},
			{"CMake", "cmake", []string{"--version"}, false, "Install CMake (e.g. via brew, apt, or choco)", "", nil, ""},
			{"Ninja", "ninja", []string{"--version"}, false, "Install Ninja build system", "", nil, ""},
			{"Python", "python", []string{"--version"}, false, "Install Python 3", "", nil, ""},
			{"ZCBOR", "zcbor", []string{"--help"}, false, "Run: pip install zcbor", "python", []string{"-m", "pip", "install", "zcbor", "cbor2<6.0.0"}, "Install zcbor and compatible cbor2 via pip"},
			{"Docker", "docker", []string{"--version"}, true, "Optional for containerized builds", "", nil, ""},
		}

		allPassed := true
		var failedFixable []doctorCheck

		fmt.Fprintln(os.Stderr)
		for _, check := range checks {
			path, err := exec.LookPath(check.command)
			if err != nil {
				if check.optional {
					ui.CheckItem(false, true, check.name, check.solution)
				} else {
					ui.CheckItem(false, false, check.name, check.solution)
					allPassed = false
				}
				if check.autoFixCmd != "" {
					failedFixable = append(failedFixable, check)
				}
				continue
			}

			out, err := exec.Command(path, check.args...).CombinedOutput()
			if err != nil {
				errMsg := strings.TrimSpace(string(out))
				if len(errMsg) > 60 {
					errMsg = errMsg[:57] + "..."
				}
				ui.CheckItem(false, false, check.name, fmt.Sprintf("Found at %s, but failed: %s", path, errMsg))
				allPassed = false
				if check.autoFixCmd != "" {
					failedFixable = append(failedFixable, check)
				}
				continue
			}

			version := strings.Split(strings.TrimSpace(string(out)), "\n")[0]
			if len(version) > 40 {
				version = version[:37] + "..."
			}
			ui.CheckItem(true, false, check.name, version)
		}

		// --- Registry Connectivity Checks (Gap 16) ---
		fmt.Fprintln(os.Stderr)
		ui.Step("Checking registry connectivity...")

		client := apiclient.New()

		// Ping the API
		_, revErr := client.GetRevision(cmd_defaultCtx())
		if revErr != nil {
			ui.CheckItem(false, false, "Registry API", fmt.Sprintf("unreachable: %v", revErr))
			allPassed = false
		} else {
			ui.CheckItem(true, false, "Registry API", client.BaseURL)
		}

		// Auth key check
		if client.HasToken() {
			_, authErr := client.MyPackages(cmd_defaultCtx())
			if authErr != nil {
				ui.CheckItem(false, true, "Auth Token", fmt.Sprintf("invalid or expired: %v", authErr))
			} else {
				login := apiclient.GetLogin()
				detail := "valid"
				if login != "" {
					detail = fmt.Sprintf("valid (@%s)", login)
				}
				ui.CheckItem(true, false, "Auth Token", detail)
			}
		} else {
			ui.CheckItem(false, true, "Auth Token", "not configured (run 'toob login')")
		}

		ui.Divider()
		if allPassed {
			ui.Success("System is ready for Toob development!")
			return nil
		}

		ui.Warn("Missing dependencies detected.")

		if len(failedFixable) > 0 {
			fmt.Fprintln(os.Stderr)
			ui.Info("Toob can attempt to automatically resolve:")
			for _, check := range failedFixable {
				ui.Muted("  %s: %s", check.name, check.autoFixDesc)
			}
			fmt.Fprint(os.Stderr, "\n  Run auto-resolver? [Y/n]: ")

			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))

			if response == "" || response == "y" || response == "yes" {
				fmt.Fprintln(os.Stderr)
				for _, check := range failedFixable {
					ui.Step("Fixing %s...", check.name)
					fixCmd := exec.Command(check.autoFixCmd, check.autoFixArgs...)
					fixCmd.Stdout = os.Stdout
					fixCmd.Stderr = os.Stderr
					if err := fixCmd.Run(); err != nil {
						ui.Error("Failed to fix %s: %v", check.name, err)
					} else {
						ui.Success("Fixed %s", check.name)
					}
				}
				ui.Divider()
				ui.Tip("Run 'toob doctor' again to verify.")
			}
		}

		return nil
	},
}
