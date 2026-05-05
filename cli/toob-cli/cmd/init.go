package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/scaffold"
)

var (
	initChip      string
	initNoVSCode  bool
	initFramework string
)

var initCmd = &cobra.Command{
	Use:   "init [project-name]",
	Short: "Initialize a new Toob-Loader IoT project (Zero-Bloat Scaffold)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]
		if initChip == "" {
			return fmt.Errorf("please specify a chip using the --chip flag (e.g., --chip esp32c6)")
		}

		// 1. Create project directory
		projectDir := filepath.Join(".", projectName)
		if _, err := os.Stat(projectDir); err == nil {
			return fmt.Errorf("directory %s already exists", projectDir)
		}
		if err := os.MkdirAll(projectDir, 0o755); err != nil {
			return err
		}

		fmt.Printf("[toob] Initializing Zero-Bloat project '%s' for chip '%s' (Framework: %s)...\n", projectName, initChip, initFramework)

		// 2. Fetch Registry Context
		regDir, err := paths.RegistryDir()
		if err != nil {
			return err
		}
		cache := registry.NewCache(regDir)
		if err := cache.Sync(); err != nil {
			return err
		}
		ci, err := cache.GetChip(initChip)
		if err != nil {
			return fmt.Errorf("chip %s not found in registry", initChip)
		}

		ctx := scaffold.Context{
			ProjectName: projectName,
			ProjectDir:  projectDir,
			ChipName:    initChip,
			ChipInfo:    ci,
			RegistryDir: regDir,
			NoVSCode:    initNoVSCode,
		}

		// 3. Delegate to specific Generator
		var generator scaffold.Generator
		switch strings.ToLower(initFramework) {
		case "baremetal":
			generator = &scaffold.BaremetalGenerator{}
		case "zephyr":
			generator = &scaffold.ZephyrGenerator{}
		default:
			return fmt.Errorf("unsupported framework '%s'. Supported: baremetal, zephyr", initFramework)
		}

		if err := generator.Generate(ctx); err != nil {
			return fmt.Errorf("scaffolding failed: %w", err)
		}

		// 4. Run installer.Add (True IKEA Mode)
		// Change directory to the project directory before running installer
		cwd, _ := os.Getwd()
		os.Chdir(projectDir)
		defer os.Chdir(cwd)

		inst := installer.New(".", cache)
		if err := inst.Add(initChip); err != nil {
			return fmt.Errorf("failed to add chip '%s': %w", initChip, err)
		}

		fmt.Println("\n[toob] Project initialized successfully!")
		
		if strings.ToLower(initFramework) == "zephyr" {
			fmt.Printf("Run `cd %s` then `west build` to compile the Zephyr application.\n", projectName)
		} else {
			fmt.Printf("Run `cd %s` then `toob build` to compile the Bootloader.\n", projectName)
		}
		return nil
	},
}

func init() {
	initCmd.Flags().StringVarP(&initChip, "chip", "c", "", "Target chip for the project (e.g., esp32c6)")
	initCmd.Flags().BoolVar(&initNoVSCode, "no-vscode", false, "Disable generation of VS Code IntelliSense configurations")
	initCmd.Flags().StringVar(&initFramework, "framework", "baremetal", "Target RTOS framework (baremetal, zephyr)")
}
