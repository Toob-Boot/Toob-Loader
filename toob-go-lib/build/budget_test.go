package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("failed to create dir for %s: %v", name, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return p
}

func TestCheckBudget(t *testing.T) {
	tmpDir := t.TempDir()
	tomlPath := writeTempFile(t, tmpDir, "device.toml", `
name = "test-device"
version = "1.0.0"

[device]
chip = "esp32c6"

[partitions]
stage0_size = 16384
stage1_size = 65536
app_size = 262144
recovery_size = 131072
netcore_size = 65536
`)
	bin := func(name string, size int) string {
		return writeTempFile(t, tmpDir, name, string(make([]byte, size)))
	}

	t.Run("fits", func(t *testing.T) {
		cases := []struct {
			stage  string
			size   int
			budget uint32
		}{
			{"stage0", 8192, 16384},
			{"stage1", 65536 - 84, 65536}, // exact fit with 84-byte signed envelope
			{"Stage1B", 1, 65536},         // alias, case-insensitive
			{"app", 200000, 262144},
			{"staging", 200000, 262144},
			{"recovery_os", 100000, 131072},
			{"netcore", 32768, 65536},
		}
		for _, c := range cases {
			rep, err := CheckBudget(tomlPath, bin(c.stage+".bin", c.size), c.stage)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", c.stage, err)
			}
			if rep.Stage != c.stage || rep.Size != uint32(c.size) || rep.Budget != c.budget {
				t.Errorf("%s: unexpected report %+v", c.stage, rep)
			}
		}
	})

	t.Run("failures", func(t *testing.T) {
		emptyToml := writeTempFile(t, tmpDir, "empty.toml", "name = \"x\"\n[device]\nchip = \"esp32c6\"\n[partitions]\nstage0_size = 0\n")
		small := bin("small.bin", 8192)
		cases := []struct {
			name, toml, bin, stage, want string
		}{
			{"exceeded", tomlPath, bin("big.bin", 20000), "stage0", "BUDGET_EXCEEDED"},
			{"stage1 envelope exceeded", tomlPath, bin("s1_overflow.bin", 65536-80), "stage1", "BUDGET_EXCEEDED"},
			{"empty binary", tomlPath, bin("zero.bin", 0), "stage0", "empty"},
			{"unknown stage", tomlPath, small, "stage9", "invalid stage"},
			{"missing binary", tomlPath, filepath.Join(tmpDir, "none.bin"), "stage0", "Could not read binary"},
			{"missing toml", filepath.Join(tmpDir, "none.toml"), small, "stage0", "Could not read/parse"},
			{"stage0 unset", emptyToml, small, "stage0", "BUDGET_001"},
			{"stage1 unset", emptyToml, small, "stage1", "BUDGET_002"},
			{"recovery unset", emptyToml, small, "recovery", "BUDGET_003"},
			{"app unset", emptyToml, small, "app", "BUDGET_004"},
		}
		for _, c := range cases {
			rep, err := CheckBudget(c.toml, c.bin, c.stage)
			if err == nil || rep != nil {
				t.Fatalf("%s: expected error, got report %+v", c.name, rep)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: expected %q in error, got %v", c.name, c.want, err)
			}
		}
	})
}
