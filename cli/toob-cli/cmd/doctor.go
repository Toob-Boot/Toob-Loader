package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/ui"
)

const doctorProbeTimeout = 5 * time.Second

type doctorToolProbe struct {
	label    string
	bins     []string
	args     []string
	required bool
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check host toolchain, build tools, Python, and container runtime availability",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			probes := []doctorToolProbe{
				{label: "CMake", bins: []string{"cmake"}, args: []string{"--version"}, required: true},
				{label: "Ninja", bins: []string{"ninja"}, args: []string{"--version"}, required: true},
				{label: "Git", bins: []string{"git"}, args: []string{"--version"}, required: true},
				{label: "Python", bins: []string{"python3", "python"}, args: []string{"--version"}, required: false},
				{label: "Docker", bins: []string{"docker"}, args: []string{"--version"}, required: false},
			}

			failedRequired := 0
			for _, probe := range probes {
				foundPath, versionLine := runDoctorProbe(cmd, probe)
				switch {
				case foundPath != "":
					ui.Success("%-10s OK   %s (%s)", probe.label, foundPath, sanitizeDisplay(versionLine))
				case probe.required:
					failedRequired++
					ui.Error("%-10s MISS required build tool not found in PATH", probe.label)
				default:
					ui.Warn("%-10s OPT  not found (optional)", probe.label)
				}
			}

			crossCompilers := []string{"arm-none-eabi-gcc", "riscv32-unknown-elf-gcc", "xtensa-esp32-elf-gcc", "gcc", "clang"}
			compilerFound := false
			for _, cc := range crossCompilers {
				p, ver := probeExecutable(cmd, cc, "--version")
				if p != "" {
					compilerFound = true
					ui.Success("%-10s OK   %s (%s)", "Compiler", p, sanitizeDisplay(ver))
				}
			}
			if !compilerFound {
				ui.Warn("No C compiler found on PATH (cached/containerized toolchains may still work)")
			}

			if failedRequired > 0 {
				return fmt.Errorf("doctor check failed: %d required host tool(s) missing", failedRequired)
			}

			ui.Success("Host environment check passed.")
			return nil
		},
	}
}

func runDoctorProbe(cmd *cobra.Command, probe doctorToolProbe) (string, string) {
	for _, bin := range probe.bins {
		p, ver := probeExecutable(cmd, bin, probe.args...)
		if p != "" {
			return p, ver
		}
	}
	return "", ""
}

func probeExecutable(cmd *cobra.Command, bin string, args ...string) (string, string) {
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return "", ""
	}
	if isWindowsStoreStub(resolved) {
		return "", ""
	}

	ctx, cancel := commandContext(cmd, doctorProbeTimeout)
	defer cancel()

	proc := exec.CommandContext(ctx, resolved, args...)
	out, err := proc.CombinedOutput()
	if err != nil {
		return "", ""
	}
	line := strings.TrimSpace(string(out))
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	return resolved, strings.TrimSpace(line)
}

func isWindowsStoreStub(binPath string) bool {
	clean := filepath.Clean(binPath)
	info, err := os.Lstat(clean)
	if err != nil {
		return true
	}
	if info.Size() == 0 && strings.Contains(strings.ToLower(clean), "windowsapps") {
		return true
	}
	return false
}
