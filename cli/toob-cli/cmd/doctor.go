package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system environment and dependencies for Toob",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Toob Environment Doctor")
		fmt.Println("-----------------------")

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

		for _, check := range checks {
			path, err := exec.LookPath(check.command)
			if err != nil {
				if check.optional {
					fmt.Printf("[ ] %s: Not found (Optional)\n    -> %s\n", check.name, check.solution)
				} else {
					fmt.Printf("[X] %s: Not found\n    -> %s\n", check.name, check.solution)
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
				fmt.Printf("[X] %s: Found at %s, but failed to execute\n    -> Error: %s\n", check.name, path, errMsg)
				allPassed = false
				if check.autoFixCmd != "" {
					failedFixable = append(failedFixable, check)
				}
				continue
			}

			version := strings.Split(strings.TrimSpace(string(out)), "\n")[0]
			// Some tools print very long first lines, let's truncate if needed
			if len(version) > 40 {
				version = version[:37] + "..."
			}
			fmt.Printf("[\u2713] %s: OK (%s)\n", check.name, version)
		}

		fmt.Println("-----------------------")
		if allPassed {
			fmt.Println("System is completely ready for Toob development!")
			return nil
		}
		
		fmt.Println("Missing dependencies detected! Please resolve them to ensure a smooth build process.")

		if len(failedFixable) > 0 {
			fmt.Println("\nToob can attempt to automatically resolve the following issues:")
			for _, check := range failedFixable {
				fmt.Printf("  - %s: %s\n", check.name, check.autoFixDesc)
			}
			fmt.Print("\nDo you want to run the auto-resolver? [Y/n]: ")
			
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			
			if response == "" || response == "y" || response == "yes" {
				fmt.Println("\n[toob] Running auto-resolver...")
				for _, check := range failedFixable {
					fmt.Printf("[toob] Fixing %s...\n", check.name)
					cmd := exec.Command(check.autoFixCmd, check.autoFixArgs...)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					if err := cmd.Run(); err != nil {
						fmt.Printf("[toob] Failed to auto-fix %s: %v\n", check.name, err)
					} else {
						fmt.Printf("[toob] Successfully fixed %s!\n", check.name)
					}
				}
				fmt.Println("\n[toob] Auto-resolve complete. Please run 'toob doctor' again to verify.")
			}
		}

		return nil
	},
}
