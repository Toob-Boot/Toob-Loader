package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/oidc"
	"github.com/toob-boot/toob/internal/ui"
)

func TestE2E_RootGroupsAndHiddenCommands(t *testing.T) {
	root := NewRootCmd()

	if !root.SilenceErrors || !root.SilenceUsage {
		t.Fatalf("root command must enable SilenceErrors and SilenceUsage")
	}

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("root --help failed: %v", err)
	}

	helpText := out.String()
	for _, groupTitle := range []string{
		"Firmware Build, Signing & Provisioning:",
		"Registry & HAL Packages:",
		"Account, Auth & Registry Admin:",
	} {
		if !strings.Contains(helpText, groupTitle) {
			t.Errorf("help output missing group title %q", groupTitle)
		}
	}

	// Internal plumbing commands must be marked Hidden: true.
	for _, hiddenPath := range [][]string{{"budget"}, {"elfaudit"}, {"admin", "mock-webhook"}} {
		sub, _, findErr := root.Find(hiddenPath)
		if findErr != nil || sub == nil {
			t.Fatalf("missing subcommand %v: %v", hiddenPath, findErr)
		}
		if !sub.Hidden {
			t.Errorf("command %v must be Hidden: true", hiddenPath)
		}
	}

	// Ensure budget & elfaudit do NOT appear in top-level user help text.
	if strings.Contains(helpText, "elfaudit") {
		t.Errorf("hidden command 'elfaudit' must not appear in root help output")
	}
}

func TestE2E_ZeroGlobalLeakageRepeatedRootInvocations(t *testing.T) {
	// Invoke root commands with conflicting flags sequentially on fresh NewRootCmd() instances.
	tmp := t.TempDir()
	dummy := filepath.Join(tmp, "dummy.bin")
	if err := os.WriteFile(dummy, []byte("abc"), 0o600); err != nil {
		t.Fatalf("write dummy: %v", err)
	}

	r1 := NewRootCmd()
	r1.SetArgs([]string{"sign", "manifest", "--in", dummy, "--mock", "--key-hex", "deadbeef"})
	if err := r1.Execute(); err == nil {
		t.Fatalf("expected mutual exclusivity error on r1")
	}

	// Second invocation without --mock must NOT inherit --mock from r1.
	r2 := NewRootCmd()
	r2.SetArgs([]string{"sign", "manifest", "--in", dummy, "--key-hex", "0000"})
	err2 := r2.Execute()
	if err2 == nil {
		t.Fatalf("expected invalid key hex error on r2")
	}
	if strings.Contains(err2.Error(), "mutually exclusive") {
		t.Fatalf("flag state leaked from r1 into r2: %v", err2)
	}
}

func TestE2E_InitPkgChipDriverCryptoLockfileV2(t *testing.T) {
	tmp := t.TempDir()
	toobHome := filepath.Join(tmp, "home")
	regDir := filepath.Join(tmp, "registry")
	projDir := filepath.Join(tmp, "my-device")

	setupTestRegistryFixture(t, regDir)
	t.Setenv("TOOB_HOME", toobHome)
	t.Setenv("TOOB_DEV", "1")
	t.Setenv("TOOB_REGISTRY_DIR", regDir)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	// 1. Run `toob init` from outside projDir; verify os.Getwd() is never mutated.
	initCmd := NewRootCmd()
	initCmd.SetArgs([]string{"init", projDir, "--chip", "testchip", "--integration", "standalone", "--registry", regDir, "--no-git", "--dev"})
	if execErr := initCmd.Execute(); execErr != nil {
		t.Fatalf("toob init failed: %v", execErr)
	}
	afterInitDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd after init: %v", err)
	}
	if afterInitDir != origDir {
		t.Fatalf("init mutated working directory from %q to %q", origDir, afterInitDir)
	}
	if _, statErr := os.Stat(filepath.Join(projDir, "device.toml")); statErr != nil {
		t.Fatalf("expected device.toml in initialized project: %v", statErr)
	}

	// Switch test CWD safely into projDir via t.Chdir for project-scoped commands.
	t.Chdir(projDir)

	// 2. Test chip/pkg/driver/crypto symmetrical commands over internal/installer.
	cmds := [][]string{
		{"chip", "add", "testchip@1.0.0", "--dev"},
		{"pkg", "add", "--category", "driver", "testdrv@1.0.0", "--dev"},
		{"driver", "spawn", "testdrv@1.0.0", "--dev"},
		{"crypto", "use", "backend", "testcrypto@1.0.0", "--dev"},
		{"pkg", "list", "--dev"},
		{"pkg", "info", "driver", "testdrv", "--dev"},
	}
	for _, argv := range cmds {
		c := NewRootCmd()
		c.SetArgs(argv)
		if execErr := c.Execute(); execErr != nil {
			t.Fatalf("command %v failed: %v", argv, execErr)
		}
	}

	// 3. Verify Lockfile v2 schema persisted cleanly.
	lf, err := lockfile.Load(filepath.Join(projDir, "toob.lock"))
	if err != nil {
		t.Fatalf("load toob.lock: %v", err)
	}
	if lf.FormatVersion != lockfile.FormatVersionV2 {
		t.Fatalf("expected Lockfile format_version=%d, got %d", lockfile.FormatVersionV2, lf.FormatVersion)
	}
	if valErr := lf.Validate(); valErr != nil {
		t.Fatalf("toob.lock validation failed: %v", valErr)
	}
	if !lf.HasChip("testchip") {
		t.Fatalf("expected testchip to be pinned in toob.lock")
	}
	if drvPkg := lf.FindPackage("driver", "testdrv", "1.0.0"); drvPkg == nil || drvPkg.Source != "spawned" {
		t.Fatalf("expected spawned testdrv@1.0.0 in toob.lock, got %+v", drvPkg)
	}
}

func TestE2E_AuditTOMLV2FailClosedOnRevokedAndHTTP410(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/package/revoked-drv/1.0.0":
			_, _ = w.Write([]byte(`{"name":"revoked-drv","version":"1.0.0","category":"driver","stage":"revoked"}`))
		case "/api/v1/package/yanked-crypto/2.0.0":
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":"gone"}`))
		case "/api/v1/package/good-chip/1.0.0":
			_, _ = w.Write([]byte(`{"name":"good-chip","version":"1.0.0","category":"chip","stage":"stable"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("TOOB_HOME", filepath.Join(tmp, "home"))
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)

	badLock := filepath.Join(tmp, "toob.lock")
	lf := lockfile.NewV2()
	lf.Packages = []lockfile.LockedPackage{
		{Category: "chip", Name: "good-chip", Version: "1.0.0", Source: "registry", SHA256: strings.Repeat("a", 64)},
		{Category: "driver", Name: "revoked-drv", Version: "1.0.0", Source: "registry", SHA256: strings.Repeat("b", 64)},
		{Category: "crypto", Name: "yanked-crypto", Version: "2.0.0", Source: "registry", SHA256: strings.Repeat("c", 64)},
	}
	if err := lf.Save(badLock); err != nil {
		t.Fatalf("save bad lockfile: %v", err)
	}

	auditFail := NewRootCmd()
	auditFail.SetArgs([]string{"audit", "--lockfile", badLock})
	err := auditFail.Execute()
	if err == nil {
		t.Fatalf("expected non-zero failure when lockfile contains revoked and 410 packages")
	}
	if !strings.Contains(err.Error(), "2 issue(s)") {
		t.Fatalf("expected 2 issues reported, got: %v", err)
	}

	cleanLock := filepath.Join(tmp, "clean.lock")
	cleanLF := lockfile.NewV2()
	cleanLF.Packages = []lockfile.LockedPackage{
		{Category: "chip", Name: "good-chip", Version: "1.0.0", Source: "registry", SHA256: strings.Repeat("a", 64)},
	}
	if err := cleanLF.Save(cleanLock); err != nil {
		t.Fatalf("save clean lockfile: %v", err)
	}

	auditPass := NewRootCmd()
	auditPass.SetArgs([]string{"audit", "--lockfile", cleanLock})
	if err := auditPass.Execute(); err != nil {
		t.Fatalf("expected clean audit to pass, got: %v", err)
	}
}

func TestE2E_TokensExchangeRejectsNewlineInjection(t *testing.T) {
	var returnedToken string
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/config":
			_ = json.NewEncoder(w).Encode(apiclient.AuthConfig{
				Issuer:      srvURL,
				Audience:    "toob-registry",
				ClientID:    "toob-cli",
				Scopes:      []string{"openid"},
				AccountsURL: srvURL,
				SettingsURL: srvURL + "/settings",
			})
		case "/gh-oidc":
			_, _ = w.Write([]byte(`{"value":"fake.jwt.payload"}`))
		case "/api/v1/credentials/exchange":
			_ = json.NewEncoder(w).Encode(apiclient.CreatedCredential{
				Token: returnedToken,
				Credential: apiclient.Credential{
					ID: "cred_1234567890",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srvURL = srv.URL
	defer srv.Close()

	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "github.env")
	t.Setenv("TOOB_HOME", filepath.Join(tmp, "home"))
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/gh-oidc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gh-req-token")
	t.Setenv("GITHUB_ENV", envFile)

	// 1. Malicious token attempting newline/ENV injection MUST fail and leave GITHUB_ENV untouched.
	returnedToken = "toob_pat_abc123\nLD_PRELOAD=/tmp/pwn.so"
	badCmd := NewRootCmd()
	badCmd.SetArgs([]string{"tokens", "exchange", "--github-env"})
	if err := badCmd.Execute(); err == nil {
		t.Fatalf("expected newline-injected token to be rejected")
	}
	if _, statErr := os.Stat(envFile); !os.IsNotExist(statErr) {
		raw, _ := os.ReadFile(envFile)
		if len(raw) > 0 {
			t.Fatalf("GITHUB_ENV must not be written when token validation fails, got: %q", string(raw))
		}
	}

	// 2. Valid token passes regex check and writes GITHUB_ENV safely.
	returnedToken = "toob_fed_CleanToken_01"
	var stdout bytes.Buffer
	goodCmd := NewRootCmd()
	goodCmd.SetOut(&stdout)
	goodCmd.SetArgs([]string{"tokens", "exchange", "--github-env"})
	if err := goodCmd.Execute(); err != nil {
		t.Fatalf("expected valid token exchange to pass: %v", err)
	}
	if !strings.Contains(stdout.String(), "::add-mask::toob_fed_CleanToken_01") {
		t.Fatalf("expected add-mask workflow command, got: %q", stdout.String())
	}
	envBytes, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read GITHUB_ENV: %v", err)
	}
	if !strings.Contains(string(envBytes), "TOOB_TOKEN=toob_fed_CleanToken_01\n") {
		t.Fatalf("unexpected GITHUB_ENV contents: %q", string(envBytes))
	}

	// 3. `tokens create` validates inputs BEFORE Step-Up.
	createBad := NewRootCmd()
	createBad.SetArgs([]string{"tokens", "create", "--name", "ci", "--expires-in-days", "400"})
	if err := createBad.Execute(); err == nil || !strings.Contains(err.Error(), "1 and 366") {
		t.Fatalf("expected pre-Step-Up validation failure on --expires-in-days, got: %v", err)
	}
}

func TestE2E_DoctorWhoamiRegistryCheckErrorExits(t *testing.T) {
	// 1. Doctor returns non-zero when required build tools are absent.
	emptyPathDir := t.TempDir()
	t.Setenv("PATH", emptyPathDir)
	docCmd := NewRootCmd()
	docCmd.SetArgs([]string{"doctor"})
	if err := docCmd.Execute(); err == nil {
		t.Fatalf("expected doctor to return error when required build tools are missing")
	}

	// 2. Whoami returns non-zero against 401 Unauthorized.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer authSrv.Close()

	homeDir := t.TempDir()
	t.Setenv("TOOB_HOME", homeDir)
	t.Setenv("TOOB_REGISTRY_URL", authSrv.URL)
	t.Setenv("TOOB_TOKEN", "toob_pat_invalid")

	whoCmd := NewRootCmd()
	whoCmd.SetArgs([]string{"whoami"})
	if err := whoCmd.Execute(); err == nil {
		t.Fatalf("expected whoami to fail on 401 unauthorized")
	}

	// 3. `registry check` returns non-zero on invalid package directory & disallowed extensions.
	badPkgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badPkgDir, "driver.toml"), []byte("name = \"bad\"\nversion = \"1.0.0\"\n"), 0o600); err != nil {
		t.Fatalf("write driver.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(badPkgDir, "payload.exe"), []byte("MZ"), 0o600); err != nil {
		t.Fatalf("write payload.exe: %v", err)
	}
	chkCmd := NewRootCmd()
	chkCmd.SetArgs([]string{"registry", "check", badPkgDir})
	if err := chkCmd.Execute(); err == nil {
		t.Fatalf("expected registry check to fail on disallowed .exe file extension")
	}
}

func TestE2E_AdminSubcommandsAndMockWebhookDTO(t *testing.T) {
	var seenPaths []string
	var lastRevokeReq apiclient.AdminRevokeRequest
	var lastHookReq apiclient.AdminMockWebhookRequest

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)

		switch r.URL.Path {
		case "/api/v1/auth/config":
			_ = json.NewEncoder(w).Encode(apiclient.AuthConfig{
				Issuer:      srvURL,
				Audience:    "toob-registry",
				ClientID:    "toob-cli",
				Scopes:      []string{"openid"},
				AccountsURL: srvURL + "/accounts",
				SettingsURL: srvURL + "/settings",
			})
		case "/api/v1/admin/status":
			_ = json.NewEncoder(w).Encode(apiclient.AdminStatusResponse{})
		case "/api/v1/admin/staging":
			_ = json.NewEncoder(w).Encode(apiclient.AdminStagingResponse{
				Packages: []apiclient.AdminStagingPackage{
					{ID: "pkg-1", Name: "spi-drv", Version: "1.0.0", Category: "driver", StagingStatus: "pending"},
				},
			})
		case "/api/v1/admin/accept", "/api/v1/admin/reject", "/api/v1/admin/archive", "/api/v1/admin/cache-purge":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/admin/release":
			_ = json.NewEncoder(w).Encode(apiclient.AdminReleaseResponse{Status: "released", RevisionID: 7, Count: 12})
		case "/api/v1/admin/revoke":
			_ = json.Unmarshal(body, &lastRevokeReq)
			_ = json.NewEncoder(w).Encode(apiclient.AdminRevokeResponse{Status: "revoked", AdvisoryID: 99, AffectedRevisions: 2})
		case "/api/v1/admin/mock-webhook":
			_ = json.Unmarshal(body, &lastHookReq)
			_, _ = w.Write([]byte(`{"status":"queued","job_id":4242}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srvURL = srv.URL
	defer srv.Close()

	t.Setenv("TOOB_HOME", t.TempDir())
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)
	if saveErr := apiclient.SaveIdentity(&apiclient.IdentityCredentials{
		RegistryURL: srv.URL,
		Issuer:      srv.URL,
		ClientID:    "toob-cli",
		Subject:     "admin-sub-1",
		Token: &oidc.Token{
			AccessToken: "oidc-admin-session-token",
			ExpiresAt:   time.Now().Add(time.Hour),
		},
	}, "admin-user"); saveErr != nil {
		t.Fatalf("SaveIdentity: %v", saveErr)
	}

	invocations := [][]string{
		{"admin", "status"},
		{"admin", "staging"},
		{"admin", "accept", "spi-drv", "1.0.0"},
		{"admin", "reject", "spi-drv", "1.0.0", "missing-hal"},
		{"admin", "release"},
		{"admin", "revoke", "spi-drv", "1.0.0", "--severity", "critical", "--title", "CVE-2026-0001"},
		{"admin", "archive", "spi-drv", "0.9.0"},
		{"admin", "cache-purge"},
		{"admin", "mock-webhook", "--action", "synchronize", "--pr", "17", "--repo", "toob-boot/toob-registry", "--sha", "abc123", "--user-id", "55"},
	}

	for _, argv := range invocations {
		c := NewRootCmd()
		c.SetArgs(argv)
		if err := c.Execute(); err != nil {
			t.Fatalf("admin command %v failed: %v", argv, err)
		}
	}

	if lastRevokeReq.Name != "spi-drv" || lastRevokeReq.Severity != "critical" || lastRevokeReq.Title != "CVE-2026-0001" {
		t.Fatalf("unexpected AdminRevokeRequest DTO: %+v", lastRevokeReq)
	}
	if lastHookReq.PRNumber != 17 || lastHookReq.Action != "synchronize" || lastHookReq.GitHubUserID != 55 {
		t.Fatalf("unexpected AdminMockWebhookRequest DTO: %+v", lastHookReq)
	}
	if len(seenPaths) != len(invocations) {
		t.Fatalf("expected %d admin HTTP requests, saw %d (%v)", len(invocations), len(seenPaths), seenPaths)
	}
}

func TestE2E_SettingsProvisionAndELFAuditGuards(t *testing.T) {
	// Settings URL builder routing & safety guards.
	u1, err := buildSettingsURL("https://registry.the-toob.com", "acme", false, "")
	if err != nil || u1 != "https://registry.the-toob.com/orgs/acme/settings/general" {
		t.Fatalf("unexpected org default settings URL: %q (%v)", u1, err)
	}
	u2, err := buildSettingsURL("https://registry.the-toob.com", "acme", true, "")
	if err != nil || u2 != "https://registry.the-toob.com/settings/profile" {
		t.Fatalf("unexpected --personal settings URL: %q (%v)", u2, err)
	}
	u3, err := buildSettingsURL("https://registry.the-toob.com", "", false, "tokens")
	if err != nil || u3 != "https://registry.the-toob.com/settings/tokens" {
		t.Fatalf("unexpected tokens settings URL: %q (%v)", u3, err)
	}
	if _, unsafeErr := buildSettingsURL("http://evil.example.com", "", false, "profile"); unsafeErr == nil {
		t.Fatalf("expected unsafe non-HTTPS settings URL to fail")
	}

	// Provision read-id requires --key or --mock, and rejects both together.
	provMissing := NewRootCmd()
	provMissing.SetArgs([]string{"provision", "read-id", "--port", "COM99"})
	if err := provMissing.Execute(); err == nil {
		t.Fatalf("expected provision read-id without --key or --mock to fail")
	}

	provConflict := NewRootCmd()
	provConflict.SetArgs([]string{"provision", "read-id", "--port", "COM99", "--mock", "--key", "00"})
	if err := provConflict.Execute(); err == nil {
		t.Fatalf("expected provision read-id with both --mock and --key to fail")
	}

	// ELFAudit rejects invalid profiles like "sandbox" fail-closed.
	elfCmd := NewRootCmd()
	elfCmd.SetArgs([]string{"elfaudit", "--elf", "nonexistent.elf", "--profile", "sandbox"})
	if err := elfCmd.Execute(); err == nil || !strings.Contains(err.Error(), "must be") {
		t.Fatalf("expected fail-closed invalid --profile error from elfaudit, got: %v", err)
	}
}

func setupTestRegistryFixture(t *testing.T, regDir string) {
	t.Helper()
	ui.SetColorEnabled(false)

	dirs := []string{
		filepath.Join(regDir, "chips", "testchip"),
		filepath.Join(regDir, "archs", "cortex-m4"),
		filepath.Join(regDir, "drivers", "testdrv"),
		filepath.Join(regDir, "crypto", "testcrypto"),
		filepath.Join(regDir, "crypto", "testhash"),
		filepath.Join(regDir, "integrations", "standalone"),
		filepath.Join(regDir, "toolchains", "arm-none-eabi"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	idxJSON := `{
		"format_version": 2,
		"registry_version": "2.0.0",
		"chips": {
			"testchip": {
				"name": "testchip",
				"arch": "cortex-m4",
				"compiler_prefix": "arm-none-eabi-",
				"path": "chips/testchip",
				"version": "1.0.0",
				"tier": "official",
				"description": "Synthetic test chip",
				"crypto": {"backend": "testcrypto", "hash": "testhash"}
			}
		},
		"archs": {
			"cortex-m4": {
				"name": "cortex-m4",
				"path": "archs/cortex-m4",
				"version": "1.0.0",
				"tier": "official",
				"description": "Cortex-M4 arch"
			}
		},
		"drivers": {
			"testdrv": {
				"name": "testdrv",
				"trait": "flash",
				"path": "drivers/testdrv",
				"version": "1.0.0",
				"tier": "official",
				"description": "Synthetic flash driver"
			}
		},
		"crypto": {
			"testcrypto": {
				"name": "testcrypto",
				"path": "crypto/testcrypto",
				"version": "1.0.0",
				"tier": "official",
				"category": ["backend"],
				"description": "Ed25519 backend"
			},
			"testhash": {
				"name": "testhash",
				"path": "crypto/testhash",
				"version": "1.0.0",
				"tier": "official",
				"category": ["hash"],
				"description": "SHA-256 hash"
			}
		},
		"integrations": {
			"standalone": {
				"name": "standalone",
				"path": "integrations/standalone",
				"version": "1.0.0",
				"tier": "official",
				"description": "Standalone integration"
			}
		},
		"toolchains": {
			"arm-none-eabi": {
				"path": "toolchains/arm-none-eabi",
				"version": "14.2.0"
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(regDir, "registry.json"), []byte(idxJSON), 0o600); err != nil {
		t.Fatalf("write registry.json: %v", err)
	}

	files := map[string]string{
		filepath.Join(regDir, "chips", "testchip", "chip.toml"):                 "name = \"testchip\"\nversion = \"1.0.0\"\narch = \"cortex-m4\"\n",
		filepath.Join(regDir, "chips", "testchip", "chip_manifest.json"):        `{"name":"testchip","version":"1.0.0","arch":"cortex-m4","compiler_prefix":"arm-none-eabi-"}`,
		filepath.Join(regDir, "chips", "testchip", "hardware.json"):             `{"chip_family":"stm32f4","constants":{"X":"1U"},"flash":{"size":1048576,"write_alignment":4,"app_alignment":16384,"base":"0x08000000","regions":[{"type":"writable","name":"bank0","base":134217728,"size":1048576,"sector_size":16384}]},"memory":{"iram_base":"0x20000000U","iram_size":"0x20000U","sram_base":"0x20000000U","sram_size":"0x20000U"}}`,
		filepath.Join(regDir, "archs", "cortex-m4", "arch.toml"):                "name = \"cortex-m4\"\nversion = \"1.0.0\"\n",
		filepath.Join(regDir, "drivers", "testdrv", "driver.toml"):              "name = \"testdrv\"\nversion = \"1.0.0\"\ntrait = \"flash\"\n",
		filepath.Join(regDir, "drivers", "testdrv", "driver_manifest.json"):     `{"name":"testdrv","version":"1.0.0","trait":"flash"}`,
		filepath.Join(regDir, "drivers", "testdrv", "driver.c"):                 "/* test driver */\n",
		filepath.Join(regDir, "crypto", "testcrypto", "crypto.toml"):            "name = \"testcrypto\"\nversion = \"1.0.0\"\ncategory = [\"backend\"]\n",
		filepath.Join(regDir, "crypto", "testhash", "crypto.toml"):              "name = \"testhash\"\nversion = \"1.0.0\"\ncategory = [\"hash\"]\n",
		filepath.Join(regDir, "integrations", "standalone", "integration.toml"): "name = \"standalone\"\nversion = \"1.0.0\"\n",
		filepath.Join(regDir, "toolchains", "arm-none-eabi", "toolchain.toml"):  "name = \"arm-none-eabi\"\nversion = \"14.2.0\"\n",
	}
	for p, content := range files {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", p, err)
		}
	}
}
