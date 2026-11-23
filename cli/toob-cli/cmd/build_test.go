package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/buildrunner"
	"github.com/toob-boot/toob/internal/ports"
)

func TestBuildCommandFlagsAndMutualExclusivity(t *testing.T) {
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"build", "--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("build --help failed: %v", err)
	}

	helpText := out.String()
	for _, flag := range []string{
		"--locked", "--native", "--docker", "--profile", "--mock",
		"--manifest", "--build-dir", "--toolchain-path", "--dev",
		"--container-arch", "--compiler-image",
	} {
		if !strings.Contains(helpText, flag) {
			t.Errorf("build --help missing expected flag %q", flag)
		}
	}

	rootConflict := NewRootCmd()
	rootConflict.SetArgs([]string{"build", "--native", "--docker"})
	if err := rootConflict.Execute(); err == nil {
		t.Fatalf("expected error when both --native and --docker are specified")
	}
}

func TestBuildRunnerMockCanonicalizationAndDockerArgs(t *testing.T) {
	canonical, err := buildrunner.CanonicalizeMockFlagValue("uart,efuse", true)
	if err != nil {
		t.Fatalf("CanonicalizeMockFlagValue failed: %v", err)
	}
	if canonical != "uart,efuse" && !strings.Contains(canonical, "efuse") {
		t.Fatalf("unexpected canonical mock value: %q", canonical)
	}

	unchanged, err := buildrunner.CanonicalizeMockFlagValue("", false)
	if err != nil || unchanged != "" {
		t.Fatalf("expected empty unchanged mock value, got %q (%v)", unchanged, err)
	}

	ws := t.TempDir()
	sub := filepath.Join(ws, "build", "out")
	rel, err := buildrunner.ContainerPath(ws, sub)
	if err != nil {
		t.Fatalf("ContainerPath failed: %v", err)
	}
	if rel != "/workspace/build/out" {
		t.Fatalf("unexpected ContainerPath: got %q want /workspace/build/out", rel)
	}

	if _, escErr := buildrunner.ContainerPath(ws, filepath.Join(ws, "..", "escape")); escErr == nil {
		t.Fatalf("expected ContainerPath to reject workspace escape")
	}

	args, err := buildrunner.BuildDockerRunArgs(ports.DockerBuildInput{
		Image:       "ghcr.io/toob-boot/toob-compiler:test",
		Workspace:   ws,
		RegistryDir: filepath.Join(ws, "reg"),
		WorkDir:     ws,
		Command:     "toob",
		CommandArgs: []string{"build", "--native", "--profile", "dev"},
	})
	if err != nil {
		t.Fatalf("BuildDockerRunArgs failed: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "ghcr.io/toob-boot/toob-compiler:test") {
		t.Fatalf("docker run args missing compiler image: %v", args)
	}
}

func TestCMakeFingerprintDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	in := buildrunner.CMakeFingerprintInputs{
		ProjectRoot: dir,
		Profile:     "dev",
		ChipName:    "testchip",
	}
	fp1, err := buildrunner.ComputeCMakeFingerprint(in)
	if err != nil {
		t.Fatalf("ComputeCMakeFingerprint failed: %v", err)
	}
	if fp1 == "" {
		t.Fatalf("expected non-empty fingerprint")
	}

	if writeErr := os.WriteFile(filepath.Join(dir, "CMakeCache.txt"), []byte("// mock cmake cache\n"), 0o600); writeErr != nil {
		t.Fatalf("write CMakeCache.txt: %v", writeErr)
	}
	if fpErr := buildrunner.WriteCMakeFingerprint(dir, fp1); fpErr != nil {
		t.Fatalf("WriteCMakeFingerprint failed: %v", fpErr)
	}
	if buildrunner.FingerprintNeedsConfigure(dir, fp1) {
		t.Fatalf("expected matching fingerprint to skip reconfigure")
	}

	in.Profile = "production"
	fp2, err := buildrunner.ComputeCMakeFingerprint(in)
	if err != nil {
		t.Fatalf("ComputeCMakeFingerprint (production) failed: %v", err)
	}
	if fp1 == fp2 {
		t.Fatalf("expected profile change to invalidate CMake fingerprint")
	}
	if !buildrunner.FingerprintNeedsConfigure(dir, fp2) {
		t.Fatalf("expected mismatched fingerprint to require reconfigure")
	}
}
