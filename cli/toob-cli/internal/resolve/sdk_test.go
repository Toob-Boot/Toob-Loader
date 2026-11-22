package resolve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
)

func TestResolveCoreSDK(t *testing.T) {
	tests := []struct {
		name       string
		device     string
		pinned     string
		minSDK     string
		noRegistry bool
		want       string
		wantOrigin string
		wantErr    string
	}{
		{name: "device version", device: "core/v1.1.0", want: "core/v1.1.0", wantOrigin: originDevice},
		{name: "lockfile wins", device: "core/v1.0.0", pinned: "core/v1.1.0", want: "core/v1.1.0", wantOrigin: originLockfile},
		{name: "unset resolves latest", want: "core/v1.2.0", wantOrigin: originAuto},
		{name: "latest keyword", device: "latest", want: "core/v1.2.0", wantOrigin: originAuto},
		{name: "toob-boot keyword", device: "toob-boot", want: "core/v1.2.0", wantOrigin: originAuto},
		{name: "latest also overrides pin keyword", pinned: "latest", want: "core/v1.2.0", wantOrigin: originAuto},
		{name: "no registry falls back to chip minimum", noRegistry: true, minSDK: "v1.0.0", want: "v1.0.0", wantOrigin: originFallback},
		{name: "no registry and no minimum falls back to main", noRegistry: true, want: "main", wantOrigin: originFallback},
		{name: "main passes any minimum", device: "main", minSDK: "v9.0.0", want: "main", wantOrigin: originDevice},
		{name: "dev passes any minimum", device: "dev", minSDK: "v9.0.0", want: "dev", wantOrigin: originDevice},
		{name: "below minimum", device: "core/v1.2.0", minSDK: "v1.3.0", wantErr: "requires Core SDK >= v1.3.0"},
		{name: "equal to minimum", device: "core/v1.3.0", minSDK: "v1.3.0", want: "core/v1.3.0", wantOrigin: originDevice},
		{name: "unparsable version", device: "core/garbage", minSDK: "v1.0.0", wantErr: "cannot check"},
		{name: "unparsable minimum", device: "core/v1.2.0", minSDK: "garbage", wantErr: "invalid min_core_sdk"},
		{name: "unsafe version", device: "core/../x", wantErr: "Core SDK version"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			in := fx.input()
			if tc.noRegistry {
				in.Index = &registry.Index{}
			}
			in.Device.Build.CoreSDK = tc.device
			in.Lock.Environment.CoreSDK = tc.pinned
			chip := &Chip{Name: testChip, Spec: &ports.ChipManifest{MinCoreSDK: tc.minSDK}}

			got, err := resolveCoreSDK(in, chip)
			if tc.wantErr != "" {
				requireErr(t, err, tc.wantErr)
				return
			}
			requireNoErr(t, err)
			if got.Version != tc.want || got.Origin != tc.wantOrigin {
				t.Fatalf("got %+v, want version %q origin %q", got, tc.want, tc.wantOrigin)
			}
		})
	}
}

func TestCoreSDKLabel(t *testing.T) {
	if got := (CoreSDK{Version: "v1", Origin: originAuto}).Label(); got != "v1 (auto-resolved)" {
		t.Fatalf("unexpected label %q", got)
	}
}

func TestLatestCoreSDK(t *testing.T) {
	versions := func(tags ...string) *registry.Index {
		return &registry.Index{Ecosystem: &registry.EcosystemVersions{CoreSDK: tags}}
	}
	tests := []struct {
		name    string
		idx     *registry.Index
		want    string
		wantErr string
	}{
		{name: "nil index", idx: nil, wantErr: "no core SDK versions"},
		{name: "no ecosystem", idx: &registry.Index{}, wantErr: "no core SDK versions"},
		{name: "empty list", idx: versions(), wantErr: "no core SDK versions"},
		{name: "only invalid tags", idx: versions("main", "nightly"), wantErr: "no valid semantic versions"},
		{name: "numeric not lexical", idx: versions("core/v1.9.0", "core/v1.10.0", "core/v1.2.0"), want: "core/v1.10.0"},
		{name: "invalid tags are skipped", idx: versions("main", "core/v0.1.0"), want: "core/v0.1.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := latestCoreSDK(tc.idx)
			if tc.wantErr != "" {
				requireErr(t, err, tc.wantErr)
				return
			}
			requireNoErr(t, err)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseCoreSDKVersion(t *testing.T) {
	for _, tag := range []string{"core/v1.2.3", "v1.2.3", "1.2.3"} {
		v, err := parseCoreSDKVersion(tag)
		requireNoErr(t, err)
		if v.String() != "1.2.3" {
			t.Errorf("parseCoreSDKVersion(%q) = %s", tag, v)
		}
	}
	if _, err := parseCoreSDKVersion("main"); err == nil {
		t.Error("branch name parsed as version")
	}
}

func TestLocateSDK(t *testing.T) {
	t.Run("non-dev mode ignores workspace toobloader/core override", func(t *testing.T) {
		t.Setenv("TOOB_DEV", "")
		root, compilerRoot := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "toobloader", "core"), 0o755); err != nil {
			t.Fatal(err)
		}

		got := LocateSDK(root, compilerRoot)
		want := SDKPaths{
			Bootloader: filepath.Join(compilerRoot, "toobloader"),
			Core:       filepath.Join(compilerRoot, "toobloader", "core"),
			Stage0:     filepath.Join(compilerRoot, "toobloader", "stage0"),
			SDK:        filepath.Join(compilerRoot, "sdk"),
			Recovery:   filepath.Join(compilerRoot, "recovery"),
			LibToob:    filepath.Join(compilerRoot, "sdk", "libtoob"),
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("dev mode allows workspace Core SDK override when toobloader/core exists", func(t *testing.T) {
		t.Setenv("TOOB_DEV", "1")
		root, compilerRoot := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "toobloader", "core"), 0o755); err != nil {
			t.Fatal(err)
		}

		got := LocateSDK(root, compilerRoot)
		want := SDKPaths{
			Bootloader: filepath.Join(root, "toobloader"),
			Core:       filepath.Join(root, "toobloader", "core"),
			Stage0:     filepath.Join(compilerRoot, "toobloader", "stage0"),
			SDK:        filepath.Join(compilerRoot, "sdk"),
			Recovery:   filepath.Join(compilerRoot, "recovery"),
			LibToob:    filepath.Join(compilerRoot, "sdk", "libtoob"),
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("spawned chip with only toobloader/hal never shadows SDK Bootloader", func(t *testing.T) {
		t.Setenv("TOOB_DEV", "1")
		root, compilerRoot := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "toobloader", "hal", "chips", "esp32c6"), 0o755); err != nil {
			t.Fatal(err)
		}

		got := LocateSDK(root, compilerRoot)
		if got.Bootloader != filepath.Join(compilerRoot, "toobloader") {
			t.Fatalf("spawned hal shadowed SDK Bootloader: got %q", got.Bootloader)
		}
	})
}

func TestMinCompilerEnforcement(t *testing.T) {
	fx := newFixture(t)
	fx.setSpec(func(s *ports.ChipManifest) { s.MinCompiler = "14.0.0" })
	if _, err := resolveToolchain(fx.input(), fx.chip()); err == nil {
		t.Fatal("expected toolchain 1.2.3 below min_compiler 14.0.0 to fail")
	}

	fx.index.Toolchains[testToolchain] = registry.ToolchainInfo{
		Version:         "esp-14.2.0_20251107",
		UpstreamVersion: "14.2.0_20251107",
	}
	if _, err := resolveToolchain(fx.input(), fx.chip()); err != nil {
		t.Fatalf("expected toolchain 14.2.0 >= 14.0.0 to pass: %v", err)
	}
}

func TestResolveToolchain(t *testing.T) {
	t.Run("index version", func(t *testing.T) {
		fx := newFixture(t)
		tc, err := resolveToolchain(fx.input(), fx.chip())
		requireNoErr(t, err)
		if tc.Name != testToolchain || tc.Prefix != testToolchain+"-" || tc.ExpectedVersion != "1.2.3" {
			t.Fatalf("unexpected toolchain %+v", tc)
		}
		if want := filepath.Join(fx.reg.base, "toolchains", testToolchain, "toolchain.cmake"); tc.File != want {
			t.Fatalf("File = %q, want %q", tc.File, want)
		}
	})

	t.Run("lockfile pin overrides index", func(t *testing.T) {
		fx := newFixture(t)
		fx.lock.Toolchains[testToolchain] = lockfile.ToolchainEntry{Version: "1.0.0"}
		tc, err := resolveToolchain(fx.input(), fx.chip())
		requireNoErr(t, err)
		if tc.ExpectedVersion != "1.0.0" {
			t.Fatalf("ExpectedVersion = %q, want the pinned 1.0.0", tc.ExpectedVersion)
		}
	})

	t.Run("empty pin is ignored", func(t *testing.T) {
		fx := newFixture(t)
		fx.lock.Toolchains[testToolchain] = lockfile.ToolchainEntry{}
		tc, err := resolveToolchain(fx.input(), fx.chip())
		requireNoErr(t, err)
		if tc.ExpectedVersion != "1.2.3" {
			t.Fatalf("ExpectedVersion = %q, want 1.2.3", tc.ExpectedVersion)
		}
	})

	t.Run("registry failure", func(t *testing.T) {
		fx := newFixture(t)
		fx.reg.fail["toolchains:"+testToolchain] = true
		_, err := resolveToolchain(fx.input(), fx.chip())
		requireErr(t, err, "failed to resolve toolchain config")
	})

	t.Run("missing toolchain.cmake", func(t *testing.T) {
		fx := newFixture(t)
		if err := os.Remove(filepath.Join(fx.reg.base, "toolchains", testToolchain, "toolchain.cmake")); err != nil {
			t.Fatal(err)
		}
		_, err := resolveToolchain(fx.input(), fx.chip())
		requireErr(t, err, "registry toolchain missing")
	})

	t.Run("invalid name", func(t *testing.T) {
		fx := newFixture(t)
		chip := fx.chip()
		chip.Prefix = "-"
		_, err := resolveToolchain(fx.input(), chip)
		requireErr(t, err, "invalid toolchain name")
	})
}

func TestResolveCompiler(t *testing.T) {
	fx := newFixture(t)
	got, err := resolveCompiler(fx.input())
	requireNoErr(t, err)
	if got != "latest" {
		t.Fatalf("unset compiler = %q, want latest", got)
	}

	fx.dev.Build.Compiler = "1.2.3"
	got, err = resolveCompiler(fx.input())
	requireNoErr(t, err)
	if got != "1.2.3" {
		t.Fatalf("compiler = %q, want 1.2.3", got)
	}

	fx.dev.Build.Compiler = "1.2;rm"
	_, err = resolveCompiler(fx.input())
	requireErr(t, err, "compiler version")
}
