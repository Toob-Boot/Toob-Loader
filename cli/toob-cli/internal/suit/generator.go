package suit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Generate runs the zcbor parser generation for SUIT and telemetry CDDLs.
func Generate(outputDir, compilerRoot string) error {
	suitCddl := filepath.Join(compilerRoot, "cli", "suit", "toob_suit.cddl")
	telemCddl := filepath.Join(compilerRoot, "cli", "suit", "toob_telemetry.cddl")

	fmt.Println("[SUIT CodeGen] Generating C artifacts in:", outputDir)

	zcborPath, err := exec.LookPath("zcbor")
	if err != nil {
		suitH := filepath.Join(outputDir, "boot_suit.h")
		if data, err := os.ReadFile(suitH); err == nil {
			if !strings.Contains(string(data), "BOOT_SUIT_MOCK_H") {
				fmt.Println("[SUIT CodeGen] zcbor not found, but real outputs exist. Preserving them! (Idempotence Guard)")
				return nil
			}
		}
		return fmt.Errorf("[SUIT CodeGen] FATAL ERROR: Valid Python zcbor CLI not found!\nPlease ensure zcbor is installed ('pip install zcbor') and available in your PATH")
	}

	fmt.Println("[SUIT CodeGen] zcbor CLI found. Generating strict parsers...")

	commands := [][]string{
		{"code", "-c", suitCddl, "--decode", "-t", "toob_suit", "--output-c", filepath.Join(outputDir, "boot_suit.c"), "--output-h", filepath.Join(outputDir, "boot_suit.h")},
		{"code", "-c", telemCddl, "--decode", "-t", "toob_telemetry", "--output-c", filepath.Join(outputDir, "toob_telemetry_decode.c"), "--output-h", filepath.Join(outputDir, "toob_telemetry_decode.h")},
		{"code", "-c", telemCddl, "--encode", "-t", "toob_telemetry", "--output-c", filepath.Join(outputDir, "toob_telemetry_encode.c"), "--output-h", filepath.Join(outputDir, "toob_telemetry_encode.h")},
	}

	for _, args := range commands {
		cmd := exec.Command(zcborPath, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("zcbor command failed: %v", err)
		}
	}

	fmt.Println("[SUIT CodeGen] Complete.")
	return nil
}
