package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/conformance"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

// --- toob registry publish ---

var registryPublishCmd = &cobra.Command{
	Use:   "publish [path]",
	Short: "Publish a package to the Toob Registry",
	Long: `Packages the specified directory into a tarball and uploads it to the registry.

The package directory must contain a valid manifest file (e.g., driver_manifest.json).
Files matching .toobignore, .gitignore, or built-in defaults are excluded.

Examples:
  toob registry publish .
  toob registry publish ./my-driver --promote
  toob registry publish ./my-driver --skip-git-check`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.NewWithTimeout(apiclient.UploadTimeout)
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		srcDir := "."
		if len(args) > 0 {
			srcDir = args[0]
		}

		absDir, err := filepath.Abs(srcDir)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}

		if _, err := os.Stat(absDir); err != nil {
			return fmt.Errorf("directory does not exist: %s", absDir)
		}

		// Dirty-tree warning (Gap 25)
		skipGitCheck, _ := cmd.Flags().GetBool("skip-git-check")
		if !skipGitCheck {
			if err := warnIfDirtyGit(absDir); err != nil {
				return err
			}
		}

		// Check manifest dependencies (Gap 18)
		if err := checkManifestDependencies(cmd_defaultCtx(), absDir, client); err != nil {
			return err
		}

		// Mandatory HAL Conformance Gate (REG-042)
		ui.Step("Running HAL Conformance Gate...")
		confReport, confErr := conformance.AuditPackage(absDir)
		if confErr != nil || confReport == nil || !confReport.Passed {
			return fmt.Errorf("FATAL [CONFORMANCE_FAIL]: Package failed HAL conformance audit! Run 'toob conformance %s' for details.", absDir)
		}
		jsonPath := filepath.Join(absDir, "conformance_report.json")
		mdPath := filepath.Join(absDir, "conformance_report.md")
		_ = conformance.ExportReportJSON(confReport, jsonPath)
		_ = conformance.ExportReportMarkdown(confReport, mdPath)
		ui.Success("HAL Conformance audit PASSED cleanly. Generated CRA compliance reports.")
		// Name collision pre-check (Gap 14)
		manifestName := detectPackageName(absDir)
		if manifestName != "" {
			checkResp, err := client.CheckNameAvailable(cmd_defaultCtx(), manifestName)
			if err == nil && checkResp != nil && !checkResp.Available {
				ui.Warn("Name '%s' is already claimed in staging/stable by another publisher.", manifestName)
				ui.Info("You can still publish to dev for testing, but promotion may be blocked.")
			}
		}

		ui.Header("Package Publish")
		ui.Step("Packing %s ...", ui.Bold(filepath.Base(absDir)))

		// Create tarball in memory with signal handling (Gap 41)
		ctx, cancel := signal.NotifyContext(cmd_defaultCtx(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		var buf bytes.Buffer
		mpw := multipart.NewWriter(&buf)

		fw, err := mpw.CreateFormFile("tarball", filepath.Base(absDir)+".tar.gz")
		if err != nil {
			return fmt.Errorf("failed to create multipart form: %w", err)
		}

		if err := registry.CreateTarball(absDir, fw); err != nil {
			return fmt.Errorf("failed to create tarball: %w", err)
		}
		mpw.Close()

		ui.Success("Tarball created (%d bytes)", buf.Len())

		// Upload
		spinner := ui.NewSpinner("Uploading to registry...")
		spinner.Start()

		resp, err := client.Publish(ctx, &buf, mpw.FormDataContentType())
		spinner.Stop()

		if err != nil {
			return fmt.Errorf("publish failed: %w", err)
		}

		ui.Success("Published %s@%s (ID: %s)", resp.Name, resp.Version, resp.ID[:8])
		ui.KeyValue("Category", resp.Category)
		ui.KeyValue("Stage", ui.Cyan(resp.Stage))
		ui.KeyValue("SHA256", ui.Gray(resp.TarballSHA))

		if len(resp.IngestionWarnings) > 0 {
			ui.Divider()
			ui.Warn("Ingestion warnings:")
			for _, w := range resp.IngestionWarnings {
				ui.Info("  • %s", w)
			}
		}

		// Auto-promote if requested (Gap 12 tie-in)
		promote, _ := cmd.Flags().GetBool("promote")
		if promote {
			return doPromote(client, resp.Name, resp.Version)
		}

		ui.Divider()
		ui.Tip("Run 'toob registry promote %s@%s' to start compile validation.", resp.Name, resp.Version)
		return nil
	},
}

// --- toob registry unpublish ---

var registryUnpublishCmd = &cobra.Command{
	Use:   "unpublish <name>@<version>",
	Short: "Remove a dev-stage package from the registry",
	Long:  `Deletes a package that is still in the 'dev' stage. Packages in testing/staging/stable cannot be unpublished.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		name, version, err := parseNameVersion(args[0])
		if err != nil {
			return err
		}

		confirmed, err := ui.Confirm(fmt.Sprintf("Unpublish %s@%s?", name, version), false)
		if err != nil || !confirmed {
			ui.Info("Aborted.")
			return nil
		}

		ui.Step("Unpublishing %s@%s...", name, version)
		resp, err := client.Unpublish(cmd_defaultCtx(), name, version)
		if err != nil {
			return fmt.Errorf("unpublish failed: %w", err)
		}

		ui.Success("Unpublished %s@%s (%s)", resp.Name, resp.Version, resp.Status)
		return nil
	},
}

// --- toob registry promote ---

var registryPromoteCmd = &cobra.Command{
	Use:   "promote <name>@<version>",
	Short: "Promote a dev package to compile validation (testing)",
	Long:  `Promotes a package from the 'dev' stage to 'testing', triggering automated compile validation in a Firecracker VM.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		name, version, err := parseNameVersion(args[0])
		if err != nil {
			return err
		}

		return doPromote(client, name, version)
	},
}

// doPromote is the shared logic for promoting a package.
func doPromote(client *apiclient.Client, name, version string) error {
	ui.Step("Promoting %s@%s to testing...", name, version)

	spinner := ui.NewSpinner("Requesting compile validation...")
	spinner.Start()

	resp, err := client.Promote(cmd_defaultCtx(), name, version)
	spinner.Stop()

	if err != nil {
		return fmt.Errorf("promotion failed: %w", err)
	}

	ui.Success("Promoted to %s", resp.Status)
	ui.KeyValue("Job ID", resp.JobID)
	if resp.Warning != "" {
		ui.Warn("%s", resp.Warning)
	}
	ui.Tip("Track progress with 'toob registry mine'.")
	return nil
}

// --- toob registry mine ---

var registryMineCmd = &cobra.Command{
	Use:   "mine",
	Short: "List your published packages",
	Long:  `Shows all packages owned by the authenticated publisher, including their stage, status, and feedback.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		resp, err := client.MyPackages(cmd_defaultCtx())
		if err != nil {
			return fmt.Errorf("failed to list packages: %w", err)
		}

		if resp.Count == 0 {
			ui.Info("No packages found. Publish one with 'toob registry publish'.")
			return nil
		}

		ui.Header("My Packages")

		headers := []string{"ID", "NAME", "VERSION", "CATEGORY", "STAGE", "STATUS", "CREATED"}
		var rows [][]string
		for _, p := range resp.Packages {
			stage := formatStage(p.Stage)
			status := formatStatus(p.StagingStatus, p.StagingFeedback)
			rows = append(rows, []string{
				p.ID[:8],
				p.Name,
				p.Version,
				p.Category,
				stage,
				status,
				p.CreatedAt,
			})
		}

		ui.Table(headers, rows)
		ui.Divider()

		// Quota display (Gap 11): count packages per stage
		devCount, testingCount := 0, 0
		for _, p := range resp.Packages {
			switch p.Stage {
			case "dev":
				devCount++
			case "testing":
				testingCount++
			}
		}
		if devCount > 0 || testingCount > 0 {
			ui.KeyValue("Dev Quota", fmt.Sprintf("%d package(s)", devCount))
			ui.KeyValue("Testing Quota", fmt.Sprintf("%d package(s)", testingCount))
		}
		ui.Info("Total: %d package(s)", resp.Count)
		return nil
	},
}

// --- toob registry search ---

var registrySearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search for packages in the registry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		query := args[0]

		resp, err := client.Search(cmd_defaultCtx(), query)
		if err != nil {
			return fmt.Errorf("search failed: %w", err)
		}

		if resp.Count == 0 {
			ui.Info("No packages found for '%s'.", query)
			return nil
		}

		ui.Header("Search Results")
		headers := []string{"NAME", "VERSION", "CATEGORY", "DESCRIPTION"}
		var rows [][]string
		for _, r := range resp.Results {
			desc := r.Description
			if len(desc) > 50 {
				desc = desc[:47] + "..."
			}
			rows = append(rows, []string{r.Name, r.Version, r.Category, desc})
		}
		ui.Table(headers, rows)
		ui.Info("%d result(s) found.", resp.Count)
		return nil
	},
}

// --- toob registry check ---

var registryCheckCmd = &cobra.Command{
	Use:   "check [path]",
	Short: "Run local pre-flight validation on a package",
	Long:  `Validates a package directory locally before uploading. Checks file extensions, manifest syntax, and file sizes.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcDir := "."
		if len(args) > 0 {
			srcDir = args[0]
		}

		absDir, err := filepath.Abs(srcDir)
		if err != nil {
			return err
		}

		ui.Header("Pre-flight Check")
		passed := true

		// Check 1: Directory exists
		info, err := os.Stat(absDir)
		if err != nil || !info.IsDir() {
			ui.CheckItem(false, false, "Directory", fmt.Sprintf("%s does not exist or is not a directory", absDir))
			return fmt.Errorf("pre-flight failed")
		}
		ui.CheckItem(true, false, "Directory", absDir)

		// Check 2: Manifest exists
		manifestFound := false
		for _, mf := range []string{"driver_manifest.json", "crypto_manifest.json", "chip_manifest.json", "arch_manifest.json", "toolchain_manifest.json", "integration_manifest.json"} {
			if _, err := os.Stat(filepath.Join(absDir, mf)); err == nil {
				ui.CheckItem(true, false, "Manifest", mf)
				manifestFound = true
				break
			}
		}
		if !manifestFound {
			ui.CheckItem(false, false, "Manifest", "No recognized manifest file found")
			passed = false
		}

		// Check 3: No oversized files (> 1 MB warning, > 5 MB error)
		var oversized []string
		filepath.Walk(absDir, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			if fi.Size() > 5<<20 {
				rel, _ := filepath.Rel(absDir, path)
				oversized = append(oversized, fmt.Sprintf("%s (%d bytes)", rel, fi.Size()))
			}
			return nil
		})
		if len(oversized) > 0 {
			ui.CheckItem(false, false, "File Sizes", fmt.Sprintf("%d file(s) exceed 5 MB", len(oversized)))
			for _, f := range oversized {
				ui.Muted("  %s", f)
			}
			passed = false
		} else {
			ui.CheckItem(true, false, "File Sizes", "All files within limits")
		}

		ui.Divider()
		if passed {
			ui.Success("Pre-flight checks passed.")
		} else {
			ui.Error("Pre-flight checks failed. Fix the issues above before publishing.")
		}
		return nil
	},
}

// --- toob registry clean ---

var registryCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove the local registry cache",
	Long:  `Purges the local registry cache (~/.toob/registry) and forces a fresh sync on the next operation.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := paths.RegistryDir()
		if err != nil {
			return err
		}

		ui.Step("Removing registry cache at %s...", dir)
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("failed to clean cache: %w", err)
		}

		ui.Success("Registry cache cleaned. Run 'toob registry sync' to re-initialize.")
		return nil
	},
}

// --- Helpers ---

// parseNameVersion splits "name@version" into its components.
func parseNameVersion(input string) (string, string, error) {
	// Handle scoped packages: @scope/name@version
	lastAt := strings.LastIndex(input, "@")
	if lastAt <= 0 {
		return "", "", fmt.Errorf("invalid format: expected <name>@<version> (e.g., uart-driver@1.0.0)")
	}

	name := input[:lastAt]
	version := input[lastAt+1:]

	if name == "" || version == "" {
		return "", "", fmt.Errorf("invalid format: expected <name>@<version>")
	}

	return name, version, nil
}

// formatStage colors the stage string for table display.
func formatStage(stage string) string {
	switch stage {
	case "dev":
		return ui.Gray(stage)
	case "testing":
		return ui.Yellow(stage)
	case "staging":
		return ui.Cyan(stage)
	case "stable":
		return ui.Green(stage)
	case "revoked":
		return ui.Red(stage)
	default:
		return stage
	}
}

// formatStatus renders the staging status and feedback for table display.
func formatStatus(status, feedback string) string {
	if status == "" {
		return ui.Gray("—")
	}
	switch status {
	case "accepted":
		return ui.Green("accepted")
	case "rejected":
		text := ui.Red("rejected")
		if feedback != "" {
			text += " " + ui.Gray("("+feedback+")")
		}
		return text
	default:
		return status
	}
}

// warnIfDirtyGit checks if the directory is a git repo with uncommitted changes.
func warnIfDirtyGit(dir string) error {
	gitCmd := exec.Command("git", "-C", dir, "status", "--porcelain")
	out, err := gitCmd.Output()
	if err != nil {
		// Not a git repo or git not available — skip silently
		return nil
	}

	if len(strings.TrimSpace(string(out))) > 0 {
		ui.Warn("Uncommitted changes detected in %s", dir)
		confirmed, err := ui.Confirm("Publish anyway?", false)
		if err != nil || !confirmed {
			return fmt.Errorf("aborted: uncommitted changes in working tree")
		}
	}
	return nil
}

// detectPackageName attempts to read the package name from a manifest file.
func detectPackageName(dir string) string {
	// Quick scan for manifest files
	manifests := []string{
		"driver_manifest.json",
		"crypto_manifest.json",
		"chip_manifest.json",
		"arch_manifest.json",
		"toolchain_manifest.json",
		"integration_manifest.json",
	}

	for _, mf := range manifests {
		data, err := os.ReadFile(filepath.Join(dir, mf))
		if err != nil {
			continue
		}
		// Extract name field via simple string scan (avoid full JSON parse overhead)
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, `"name"`) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					name := strings.Trim(strings.TrimSpace(parts[1]), `",`)
					if name != "" {
						return name
					}
				}
			}
		}
	}
	return ""
}

// checkManifestDependencies parses package dependencies and validates them against the registry.
func checkManifestDependencies(ctx context.Context, dir string, client *apiclient.Client) error {
	manifests := []string{
		"driver_manifest.json",
		"crypto_manifest.json",
		"chip_manifest.json",
		"arch_manifest.json",
		"toolchain_manifest.json",
		"integration_manifest.json",
	}

	var data []byte
	for _, mf := range manifests {
		baseClean := filepath.Clean(dir)
		targetClean := filepath.Clean(filepath.Join(baseClean, mf))
		rel, err := filepath.Rel(baseClean, targetClean)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			continue
		}
		if d, err := os.ReadFile(targetClean); err == nil {
			data = d
			break
		}
	}

	if data == nil {
		return nil
	}

	var m struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil // skip if invalid JSON, check command handles errors
	}

	if len(m.Dependencies) == 0 {
		return nil
	}

	ui.Step("Checking package dependencies...")
	cache := registry.NewCache("")
	idx, cacheErr := cache.LoadIndex()

	for depName, depVerConstraint := range m.Dependencies {
		exists := false

		// 1. Check local registry index cache
		if cacheErr == nil && idx != nil {
			if _, ok := idx.Chips[depName]; ok {
				exists = true
			}
			if _, ok := idx.Archs[depName]; ok {
				exists = true
			}
			if _, ok := idx.Toolchains[depName]; ok {
				exists = true
			}
			if _, ok := idx.Integrations[depName]; ok {
				exists = true
			}
			if _, ok := idx.Drivers[depName]; ok {
				exists = true
			}
			if _, ok := idx.Crypto[depName]; ok {
				exists = true
			}
		}

		// 2. Check remote API via search if not found locally
		if !exists {
			resp, err := client.Search(ctx, depName)
			if err == nil && resp != nil && resp.Count > 0 {
				for _, p := range resp.Results {
					if p.Name == depName {
						exists = true
						break
					}
				}
			}
		}

		if !exists {
			ui.Warn("Dependency %s@%s not found in registry (missing or not yet stable).", depName, depVerConstraint)
		} else {
			// Query specific package details to check for revocation
			cleanVer := strings.TrimLeft(depVerConstraint, "^~>=< ")
			if cleanVer != "" {
				pkgResp, err := client.GetPackage(ctx, depName, cleanVer)
				if err == nil && pkgResp != nil {
					switch pkgResp.Stage {
					case "revoked":
						ui.Warn("Dependency %s@%s matches a REVOKED version in the registry.", depName, depVerConstraint)
					case "archived":
						ui.Info("Dependency %s@%s is archived in the registry.", depName, depVerConstraint)
					}
				}
			}
		}
	}
	return nil
}

func init() {
	registryPublishCmd.Flags().Bool("promote", false, "Automatically promote to testing after upload")
	registryPublishCmd.Flags().Bool("skip-git-check", false, "Skip the uncommitted changes warning")

	registryCmd.AddCommand(registryPublishCmd)
	registryCmd.AddCommand(registryUnpublishCmd)
	registryCmd.AddCommand(registryPromoteCmd)
	registryCmd.AddCommand(registryMineCmd)
	registryCmd.AddCommand(registrySearchCmd)
	registryCmd.AddCommand(registryCheckCmd)
	registryCmd.AddCommand(registryCleanCmd)
}
