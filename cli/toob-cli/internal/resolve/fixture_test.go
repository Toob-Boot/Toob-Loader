package resolve

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
)

const (
	testChip      = "esp32c6"
	testToolchain = "riscv32-esp-elf"
)

// fakeSource answers every lookup with <base>/<kind>/<name> unless the
// lookup is listed in fail ("<kind>:<name>"). Tests create the files they need.
type fakeSource struct {
	base  string
	fail  map[string]bool
	socOK bool
	calls []string
}

func (f *fakeSource) lookup(kind, name string) (string, error) {
	f.calls = append(f.calls, kind+":"+name)
	if f.fail[kind+":"+name] {
		return "", errors.New("fake: unavailable")
	}
	return filepath.Join(f.base, kind, name), nil
}

func (f *fakeSource) ChipSourcePath(name string) (string, error) { return f.lookup("chips", name) }
func (f *fakeSource) ArchSourcePath(name string) (string, error) { return f.lookup("arch", name) }
func (f *fakeSource) DriverSourcePath(name string) (string, error) {
	return f.lookup("drivers", name)
}
func (f *fakeSource) CryptoSourcePath(name string) (string, error) {
	return f.lookup("crypto", name)
}
func (f *fakeSource) ToolchainConfigPath(name string) (string, error) {
	return f.lookup("toolchains", name)
}

func (f *fakeSource) SoCSourcePath(name string) (string, error) {
	if !f.socOK {
		return "", errors.New("fake: no soc package")
	}
	return f.lookup("soc", name)
}

func (f *fakeSource) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// fixture is a complete, valid build input. Tests mutate single aspects.
type fixture struct {
	t     *testing.T
	root  string
	reg   *fakeSource
	spec  ports.ChipManifest
	dev   *manifestpkg.DeviceToml
	lock  *lockfile.Lockfile
	index *registry.Index
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	wrapper := "wrap/w.c"
	fx := &fixture{
		t:    t,
		root: t.TempDir(),
		reg:  &fakeSource{base: t.TempDir(), fail: map[string]bool{}},
		spec: ports.ChipManifest{
			Arch:           "riscv",
			CompilerPrefix: testToolchain + "-",
			Version:        "2.0.0",
			MinCoreSDK:     "v1.0.0",
			Sources: &ports.ChipSources{Drivers: []string{
				"drivers/uart/esp_uart_v1/console.c",
				"drivers/uart/esp_uart_v1/extra.c",
				"drivers/flash/esp_flash/flash.c",
			}},
			Includes: []string{"soc/esp/include", "include"},
			Crypto:   &ports.ChipCrypto{Backend: "monocypher", Hash: "sha256_sw"},
			Recovery: &ports.ChipRecovery{
				Console:  "uart/esp_uart_v1",
				Flash:    "flash/esp_flash",
				Crypto:   &ports.RecoveryCrypto{Backend: "none"},
				Sources:  []string{"recovery/main.c"},
				Includes: []string{"recovery/inc"},
			},
		},
		dev:  &manifestpkg.DeviceToml{},
		lock: &lockfile.Lockfile{Toolchains: map[string]lockfile.ToolchainEntry{}},
		index: &registry.Index{
			Chips:      map[string]registry.ChipInfo{},
			Toolchains: map[string]registry.ToolchainInfo{testToolchain: {Version: "1.2.3"}},
			Ecosystem: &registry.EcosystemVersions{
				CoreSDK: []string{"core/v1.0.0", "core/v1.2.0", "not-semver"},
			},
			Crypto: map[string]registry.CryptoInfo{
				"monocypher": {
					MinCoreSdk:      "v1.0.0",
					UpstreamSources: []string{"src/a.c", "src/b.c"},
					Includes:        []string{"inc"},
					Cflags:          []string{"-DX=1"},
					Wrapper:         &wrapper,
				},
				"sha256_sw": {UpstreamSources: []string{"sha.c"}},
			},
		},
	}
	fx.dev.Device.Chip = testChip
	fx.writeChip(fx.registryChipDir(), fx.spec)
	fx.touch(filepath.Join(fx.reg.base, "toolchains", testToolchain, "toolchain.cmake"))
	return fx
}

func (fx *fixture) registryChipDir() string {
	return filepath.Join(fx.reg.base, "chips", testChip)
}

func (fx *fixture) localChipDir() string {
	return filepath.Join(fx.root, localHalDir, "chips", testChip)
}

func (fx *fixture) touch(file string) {
	fx.t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		fx.t.Fatal(err)
	}
}

func (fx *fixture) writeJSON(file string, v any) {
	fx.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		fx.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o644); err != nil {
		fx.t.Fatal(err)
	}
}

func (fx *fixture) writeRaw(file, content string) error {
	fx.t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return os.WriteFile(file, []byte(content), 0o644)
}

// writeChip writes hardware.json and the manifest of spec into dir.
func (fx *fixture) writeChip(dir string, spec ports.ChipManifest) {
	fx.t.Helper()
	data, err := json.Marshal(spec)
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.touch(filepath.Join(dir, hardwareFile))
	if err := os.WriteFile(filepath.Join(dir, chipManifestFile), data, 0o644); err != nil {
		fx.t.Fatal(err)
	}
}

// setSpec mutates the registry chip manifest and rewrites it.
func (fx *fixture) setSpec(mutate func(*ports.ChipManifest)) {
	fx.t.Helper()
	mutate(&fx.spec)
	fx.writeChip(fx.registryChipDir(), fx.spec)
}

func (fx *fixture) setCrypto(name string, mutate func(*registry.CryptoInfo)) {
	info := fx.index.Crypto[name]
	mutate(&info)
	fx.index.Crypto[name] = info
}

func (fx *fixture) input() Input {
	return Input{Root: fx.root, Device: fx.dev, Lock: fx.lock, Index: fx.index, Registry: fx.reg}
}

func (fx *fixture) resolve() (*Plan, error) { return Resolve(fx.input()) }

// chip resolves the chip and fails the test if that is not possible.
func (fx *fixture) chip() *Chip {
	fx.t.Helper()
	chip, err := resolveChip(fx.input())
	if err != nil {
		fx.t.Fatalf("resolveChip: %v", err)
	}
	return chip
}

func requireErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
