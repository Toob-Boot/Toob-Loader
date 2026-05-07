package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/scaffold"
)

var (
	initChip         string
	initNoVSCode     bool
	initFramework    string
	initDevContainer bool
	initSdkUrl       string
	initSdkRevision  string
)

var initCmd = &cobra.Command{
	Use:   "init [project-name]",
	Short: "Initialize a new Toob-Loader IoT project (Zero-Bloat Scaffold)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]
		
		validNamePattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
		if !validNamePattern.MatchString(projectName) {
			return fmt.Errorf("invalid project name '%s'. Only alphanumeric characters, dashes, and underscores are allowed", projectName)
		}

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

		// Rollback on failure
		var initErr error
		defer func() {
			if initErr != nil {
				fmt.Printf("[toob] ERROR: Scaffolding failed: %v\n", initErr)
				fmt.Printf("[toob] Rolling back... removing directory %s\n", projectDir)
				os.RemoveAll(projectDir)
			}
		}()

		fmt.Printf("[toob] Initializing Zero-Bloat project '%s' for chip '%s' (Framework: %s)...\n", projectName, initChip, initFramework)

		// 2. Fetch Registry Context
		regDir, err := paths.RegistryDir()
		if err != nil {
			initErr = err
			return err
		}
		cache := registry.NewCache("")
		if err := cache.Sync(); err != nil {
			initErr = err
			return err
		}
		ci, err := cache.GetChip(initChip)
		if err != nil {
			initErr = fmt.Errorf("chip %s not found in registry", initChip)
			return initErr
		}

		ctx := scaffold.Context{
			ProjectName:     projectName,
			ProjectDir:      projectDir,
			ChipName:        initChip,
			ChipInfo:        ci,
			RegistryDir:     regDir,
			NoVSCode:        initNoVSCode,
			UseDevContainer: initDevContainer,
			SdkUrl:          initSdkUrl,
			SdkRevision:     initSdkRevision,
		}

		// 3. Delegate to specific Generator
		var generator scaffold.Generator
		switch strings.ToLower(initFramework) {
		case "baremetal":
			generator = &scaffold.BaremetalGenerator{}
		case "zephyr":
			generator = &scaffold.ZephyrGenerator{}
		case "espidf":
			generator = &scaffold.EspIdfGenerator{}
		default:
			initErr = fmt.Errorf("unsupported framework '%s'. Supported: baremetal, zephyr, espidf", initFramework)
			return initErr
		}

		if err := generator.Generate(ctx); err != nil {
			initErr = fmt.Errorf("scaffolding failed: %w", err)
			return initErr
		}

		// 4. Run installer.Add (True IKEA Mode)
		// Change directory to the project directory before running installer
		cwd, _ := os.Getwd()
		os.Chdir(projectDir)
		defer os.Chdir(cwd)

		inst := installer.New(".", cache)
		if err := inst.Add(initChip); err != nil {
			initErr = fmt.Errorf("failed to add chip '%s': %w", initChip, err)
			return initErr
		}

		// 5. Initialize Git Repository
		gitCmd := exec.Command("git", "init")
		gitCmd.Stdout = os.Stdout
		gitCmd.Stderr = os.Stderr
		if err := gitCmd.Run(); err != nil {
			fmt.Printf("[toob] WARN: Failed to initialize git repository: %v\n", err)
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
	initCmd.Flags().StringVar(&initFramework, "framework", "baremetal", "Target RTOS framework (baremetal, zephyr, espidf)")
	initCmd.Flags().BoolVar(&initDevContainer, "devcontainer", false, "Generate VS Code DevContainer configuration for isolated builds")
	initCmd.Flags().StringVar(&initSdkUrl, "sdk-url", "https://github.com/Toob-Boot/Toob-Loader.git", "URL to fetch the Toob-Loader SDK from")
	initCmd.Flags().StringVar(&initSdkRevision, "sdk-version", "main", "Git branch or tag to use for the Toob-Loader SDK")
}
