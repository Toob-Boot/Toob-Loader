package suit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Generate runs the zcbor parser generation for SUIT and telemetry CDDLs.
func Generate(outputDir, compilerRoot, projectRoot, cliVersion string) error {
	suitCddl := filepath.Join(compilerRoot, "cli", "suit", "toob_suit.cddl")
	telemCddl := filepath.Join(compilerRoot, "cli", "suit", "toob_telemetry.cddl")

	fmt.Println("[SUIT CodeGen] Generating C artifacts in:", outputDir)

	zcborPath, err := exec.LookPath("zcbor")
	useDocker := false
	if err != nil {
		fmt.Println("[SUIT CodeGen] Local zcbor not found.")
		zcborPath, err = exec.LookPath("docker")
		if err != nil {
			return fmt.Errorf("FATAL ERROR: Valid Python zcbor CLI not found, and Docker is not installed for fallback!\nPlease install Python and 'pip install zcbor', or install Docker.")
		}
		fmt.Print("[SUIT CodeGen] Do you want to use the Docker Hybrid Fallback for this step? [Y/n]: ")
		var response string
		fmt.Scanln(&response)
		if response != "" && strings.ToLower(strings.TrimSpace(response)) != "y" {
			return fmt.Errorf("FATAL ERROR: Valid Python zcbor CLI not found, and Docker fallback declined.")
		}
		useDocker = true
	} else {
		fmt.Println("[SUIT CodeGen] zcbor CLI found locally. Generating strict parsers...")
	}

	commands := [][]string{
		{"code", "-c", suitCddl, "--decode", "-t", "toob_suit", "--output-c", filepath.Join(outputDir, "boot_suit.c"), "--output-h", filepath.Join(outputDir, "boot_suit.h")},
		{"code", "-c", telemCddl, "--decode", "-t", "toob_telemetry", "--output-c", filepath.Join(outputDir, "toob_telemetry_decode.c"), "--output-h", filepath.Join(outputDir, "toob_telemetry_decode.h")},
		{"code", "-c", telemCddl, "--encode", "-t", "toob_telemetry", "--output-c", filepath.Join(outputDir, "toob_telemetry_encode.c"), "--output-h", filepath.Join(outputDir, "toob_telemetry_encode.h")},
	}

	for _, args := range commands {
		var cmd *exec.Cmd
		if useDocker {
			// Translate paths to /workspace inside docker
			for i, arg := range args {
				if filepath.IsAbs(arg) {
					rel, _ := filepath.Rel(projectRoot, arg)
					args[i] = filepath.ToSlash(filepath.Join("/workspace", rel))
				}
			}
			dockerArgs := []string{"run", "--rm", "-v", fmt.Sprintf("%s:/workspace", projectRoot), "-w", "/workspace", "repowatt/toob-compiler:v" + cliVersion, "zcbor"}
			dockerArgs = append(dockerArgs, args...)
			cmd = exec.Command(zcborPath, dockerArgs...)
		} else {
			cmd = exec.Command(zcborPath, args...)
		}
		cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("zcbor command failed: %v", err)
		}
	}

	fmt.Println("[SUIT CodeGen] Complete.")
	return nil
}
