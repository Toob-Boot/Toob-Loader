package cbor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/toob-boot/toob/internal/ui"
	"golang.org/x/sync/errgroup"
)

// Generate runs the zcbor parser generation for cloud-command and telemetry CDDLs.
func Generate(outputDir, compilerRoot, projectRoot, compilerTag string) error {
	telemCddl := filepath.Join(compilerRoot, "cli", "cbor", "toob_telemetry.cddl")

	ui.Step("Generating ZCBOR CodeGen C artifacts in: %s", outputDir)

	zcborPath, err := exec.LookPath("zcbor")
	useDocker := false
	if err != nil {
		ui.Muted("Local zcbor not found.")
		zcborPath, err = exec.LookPath("docker")
		if err != nil {
			return fmt.Errorf("FATAL ERROR: Valid Python zcbor CLI not found, and Docker is not installed for fallback!\nPlease install Python and 'pip install zcbor', or install Docker.")
		}

		// Non-TTY check: if not a TTY, fail-fast without interactive prompt
		stat, statErr := os.Stdin.Stat()
		isTTY := statErr == nil && (stat.Mode()&os.ModeCharDevice) != 0
		if !isTTY || os.Getenv("CI") != "" {
			return fmt.Errorf("FATAL ERROR: Valid Python zcbor CLI not found, and fallback prompts are disabled in non-TTY/CI environment")
		}

		fmt.Print("  ? Do you want to use the Docker Hybrid Fallback for this step? [Y/n]: ")
		var response string
		fmt.Scanln(&response)
		if response != "" && strings.ToLower(strings.TrimSpace(response)) != "y" {
			return fmt.Errorf("FATAL ERROR: Valid Python zcbor CLI not found, and Docker fallback declined.")
		}
		useDocker = true
	} else {
		ui.Step("zcbor CLI found locally. Generating strict parsers...")
	}

	cloudCmdCddl := filepath.Join(compilerRoot, "cli", "cbor", "toob_cloud_cmd.cddl")

	commands := [][]string{
		{"code", "-c", telemCddl, "--decode", "-t", "toob_telemetry", "--output-c", filepath.Join(outputDir, "toob_telemetry_decode.c"), "--output-h", filepath.Join(outputDir, "toob_telemetry_decode.h")},
		{"code", "-c", telemCddl, "--encode", "-t", "toob_telemetry", "--output-c", filepath.Join(outputDir, "toob_telemetry_encode.c"), "--output-h", filepath.Join(outputDir, "toob_telemetry_encode.h")},
		{"code", "-c", cloudCmdCddl, "--decode", "-t", "toob_cloud_cmd", "--output-c", filepath.Join(outputDir, "boot_cloud_cmd_decode.c"), "--output-h", filepath.Join(outputDir, "boot_cloud_cmd_decode.h")},
	}

	var g errgroup.Group
	for _, args := range commands {
		args := args // Capture for goroutine closure safety
		g.Go(func() error {
			var cmd *exec.Cmd
			if useDocker {
				// Copy args to avoid race condition when rewriting paths
				dockerArgs := make([]string, len(args))
				copy(dockerArgs, args)
				for i, arg := range dockerArgs {
					if filepath.IsAbs(arg) {
						rel, _ := filepath.Rel(projectRoot, arg)
						dockerArgs[i] = filepath.ToSlash(filepath.Join("/workspace", rel))
					}
				}
				prefixArgs := []string{"run", "--rm", "-v", fmt.Sprintf("%s:/workspace", projectRoot), "-w", "/workspace", "mannomannx/toob-compiler:" + compilerTag, "zcbor"}
				prefixArgs = append(prefixArgs, dockerArgs...)
				cmd = exec.Command(zcborPath, prefixArgs...)
			} else {
				cmd = exec.Command(zcborPath, args...)
			}
			cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
			var errBuf strings.Builder
			cmd.Stderr = &errBuf
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("zcbor command failed for target: %v, output: %s", err, errBuf.String())
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	ui.Success("CBOR CodeGen complete.")
	return nil
}
