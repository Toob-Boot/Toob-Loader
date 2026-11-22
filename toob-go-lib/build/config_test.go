package build

import (
	"strings"
	"testing"
)

func TestResolveTransport(t *testing.T) {
	caps := func(model string, slots int, scratch bool) *SlotCapabilities {
		return &SlotCapabilities{ExecModel: model, SlotCount: slots, HasScratch: scratch, MaxEraseCycles: 100000}
	}
	cases := []struct {
		name        string
		caps        *SlotCapabilities // nil = chip declares no capabilities
		provider    string
		backup      string
		scratchSize uint32
		want        Transport
		wantBackup  BackupMode
		wantErr     string
	}{
		{name: "auto pointer", caps: caps("xip_remap", 2, false), want: TransportPointer},
		{name: "auto pointer bank_swap", caps: caps("bank_swap", 2, false), want: TransportPointer},
		{name: "auto oneway", caps: caps("fixed", 2, false), want: TransportOneway, wantBackup: BackupFull},
		{name: "auto swapscratch", caps: caps("fixed", 1, true), want: TransportSwapScratch},
		{name: "auto swapmove", caps: caps("fixed", 1, false), want: TransportSwapMove},
		{name: "explicit case-insensitive", caps: caps("fixed", 1, false), provider: " SwapMove ", want: TransportSwapMove},
		{name: "explicit swapoffset", caps: caps("fixed", 1, false), provider: "swapoffset", want: TransportSwapOffset},
		{name: "unknown provider", caps: caps("xip_remap", 2, false), provider: "bogus", wantErr: "unknown transport provider"},
		{name: "unknown provider without caps", provider: "bogus", wantErr: "unknown transport provider"},
		{name: "unset without caps", wantErr: "must be set explicitly"},
		{name: "explicit without caps", provider: "swapscratch", scratchSize: 4096, want: TransportSwapScratch},
		{name: "pointer without caps fails", provider: "pointer", wantErr: "slot_capabilities"},
		{name: "pointer not remappable", caps: caps("fixed", 2, false), provider: "pointer", wantErr: "remappable"},
		{name: "pointer single slot", caps: caps("xip_remap", 1, false), provider: "pointer", wantErr: "slot_count >= 2"},
		{name: "oneway full single slot", caps: caps("fixed", 1, false), provider: "oneway", wantErr: "full backup"},
		{
			name: "oneway full with scratch", caps: caps("fixed", 1, false), provider: "oneway", scratchSize: 4096,
			want: TransportOneway, wantBackup: BackupFull,
		},
		{
			name: "oneway none single slot fails", caps: caps("fixed", 1, false), provider: "oneway", backup: "NONE",
			wantErr: "slot_count >= 2",
		},
		{
			name: "oneway none two slots", caps: caps("fixed", 2, false), provider: "oneway", backup: "NONE",
			want: TransportOneway, wantBackup: BackupNone,
		},
		{
			name: "oneway reverse delta single slot fails", caps: caps("fixed", 1, false), provider: "oneway", backup: "reverse_delta",
			wantErr: "slot_count >= 2",
		},
		{
			name: "oneway reverse delta", caps: caps("fixed", 2, false), provider: "oneway", backup: "reverse_delta",
			want: TransportOneway, wantBackup: BackupReverseDelta,
		},
		{name: "oneway unknown backup", caps: caps("fixed", 2, false), provider: "oneway", backup: "weird", wantErr: "unknown backup mode"},
		{name: "backup on non-oneway", caps: caps("xip_remap", 2, false), provider: "pointer", backup: "full", wantErr: "applies only to the oneway"},
		{name: "backup on auto pointer", caps: caps("xip_remap", 2, false), backup: "none", wantErr: "applies only to the oneway"},
		{name: "swapscratch without scratch", caps: caps("fixed", 2, false), provider: "swapscratch", wantErr: "requires a scratch"},
		{
			name: "swapscratch with scratch size", caps: caps("fixed", 2, false), provider: "swapscratch", scratchSize: 8192,
			want: TransportSwapScratch,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := testContext(t)
			log := &recordingLogger{}
			ctx.Log = log
			ctx.Chip.SlotCapabilities = c.caps
			ctx.Device.BootConfig.TransportProvider = c.provider
			ctx.Device.BootConfig.BackupMode = c.backup
			ctx.Device.Partitions.ScratchSize = c.scratchSize

			got, backup, err := resolveTransport(ctx)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want || backup != c.wantBackup {
				t.Errorf("expected %s/%q, got %s/%q", c.want, c.wantBackup, got, backup)
			}
			if c.caps == nil && len(log.warns) == 0 {
				t.Error("expected a warning when capabilities are unknown")
			}
			if c.provider == "" && len(log.infos) == 0 {
				t.Error("expected the auto-selection to be logged")
			}
		})
	}
}

func TestTransportHelpers(t *testing.T) {
	if TransportSwapOffset.cMacro() != "TOOB_TRANSPORT_SWAPOFFSET" || BackupReverseDelta.cMacro() != "TOOB_ONEWAY_BACKUP_REVERSE_DELTA" {
		t.Error("unexpected C macro names")
	}
	scratch := map[Transport]map[BackupMode]bool{
		TransportSwapScratch: {BackupUnset: true},
		TransportOneway:      {BackupFull: true, BackupNone: false, BackupReverseDelta: false},
		TransportPointer:     {BackupUnset: false},
		TransportSwapMove:    {BackupUnset: false},
		TransportSwapOffset:  {BackupUnset: false},
	}
	for tr, modes := range scratch {
		for b, want := range modes {
			if got := needsDedicatedScratch(tr, b, 1); got != want {
				t.Errorf("needsDedicatedScratch(%s, %q, 1) = %v, want %v", tr, b, got, want)
			}
		}
	}
}

func TestResolveConfigDefaults(t *testing.T) {
	ctx := testContext(t)
	ctx.Device.Partitions.WalSectors = 0
	ctx.Device.BootConfig.WdtTimeoutMs = 0
	ctx.Hardware.Flash.XipBase = ""
	ctx.Chip.SlotCapabilities.ExecModel = "fixed" // auto-selects oneway

	cfg, err := resolveConfig(ctx)
	if err != nil {
		t.Fatalf("resolveConfig failed: %v", err)
	}
	want := ResolvedConfig{
		Transport:               TransportOneway,
		BackupMode:              BackupFull,
		SlotCount:               2,
		WalSectors:              defaultWalSectors,
		WdtTimeoutMs:            defaultWdtTimeoutMs,
		StagingSlotID:           defaultStagingSlotID,
		FeatureCloudCommands:    true,
		FeatureUartProvisioning: true,
		FeatureMultiImage:       true,
		FeatureDelta:            true,
		FeatureCompression:      true,
		FlashBase:               0,
		FlashBaseAddr:           defaultFlashBaseAddr,
		XipBase:                 defaultXipBase,
		XipBaseVal:              0,
		ExecModel:               "fixed",
		Arch:                    "riscv32",
		Stage0ExecMode:          "xip",
		ImageHeaderOffset:       0x14,
	}
	if *cfg != want {
		t.Errorf("expected %+v, got %+v", want, *cfg)
	}
	if ctx.Device.BootConfig.TransportProvider != "" || ctx.Device.BootConfig.BackupMode != "" {
		t.Error("resolveConfig must not mutate the device configuration")
	}

	// CRIT-42 / LOW-15: staging_slot_id must be in [1..254]; 0 and >254 are rejected.
	zeroSlot := uint32(0)
	ctx.Device.Partitions.StagingSlotID = &zeroSlot
	if _, rErr := resolveConfig(ctx); rErr == nil {
		t.Fatal("expected staging_slot_id=0 to fail")
	}
	oneSlot := uint32(1)
	ctx.Device.Partitions.StagingSlotID = &oneSlot
	ctx.Hardware.Flash.Base = 0x08000000
	ctx.Hardware.Flash.Regions = []FlashRegion{
		{Type: "writable", Base: 0x08000000, SectorSize: 4096, Count: 1024},
	}
	cfgOne, err := resolveConfig(ctx)
	if err != nil {
		t.Fatalf("resolveConfig with staging_slot_id=1 and flash.base=0x08000000 failed: %v", err)
	}
	if cfgOne.StagingSlotID != 1 || cfgOne.FlashBase != 0x08000000 || cfgOne.FlashBaseAddr != "0x08000000" {
		t.Errorf("unexpected cfgOne: %+v", *cfgOne)
	}
}

func TestResolveConfigErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Context)
		wantErr string
	}{
		{"wal below minimum", func(c *Context) { c.Device.Partitions.WalSectors = 2 }, "below the minimum"},
		{"flash base separator", func(c *Context) { c.Hardware.Flash.BaseAddr = "0x1_0" }, "flash.base_addr"},
		{"xip base octal", func(c *Context) { c.Hardware.Flash.XipBase = "0420" }, "flash.xip_base"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := testContext(t)
			c.mutate(ctx)
			if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestValidateContext(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Context)
		wantErr string // empty = must pass
	}{
		{"baseline", func(*Context) {}, ""},
		{"chip name normalization", func(c *Context) { c.Device.Device.Chip = "TEST-CHIP"; c.Chip.Name = "testchip" }, ""},
		{"empty device chip", func(c *Context) { c.Device.Device.Chip = "" }, "must define [device] chip"},
		{"zero product id", func(c *Context) { c.Device.Identity.ProductID = 0 }, "product_id"},
		{"reserved product id", func(c *Context) { c.Device.Identity.ProductID = 0xFFFF }, "0xFFFF is reserved"},
		{"zero vendor id", func(c *Context) { c.Device.Identity.VendorID = 0 }, "vendor_id"},
		{"reserved vendor id", func(c *Context) { c.Device.Identity.VendorID = 0xFFFF }, "0xFFFF is reserved"},
		{"device chip mismatch", func(c *Context) { c.Device.Device.Chip = "stm32f4" }, "does not match hardware.json"},
		{"chip manifest mismatch", func(c *Context) { c.Chip.Name = "other" }, "chip_manifest.json name"},
		{"chip manifest without name", func(c *Context) { c.Chip.Name = "" }, ""},
		{"flash size", func(c *Context) { c.Hardware.Flash.Size = 0 }, "flash.size"},
		{"write alignment", func(c *Context) { c.Hardware.Flash.WriteAlignment = 0 }, "flash.write_alignment"},
		{"no regions", func(c *Context) { c.Hardware.Flash.Regions = nil }, "flash.regions"},
		{"writable without geometry", func(c *Context) { c.Hardware.Flash.Regions[1].Count = 0 }, "FLASH_004"},
		{"reserved without size", func(c *Context) { c.Hardware.Flash.Regions[0].Size = 0 }, "must specify 'size'"},
		{"unknown region type", func(c *Context) { c.Hardware.Flash.Regions[0].Type = "otp" }, "unknown type 'otp'"},
		{"arena size", func(c *Context) { c.Hardware.CryptoCapabilities.ArenaSize = 0 }, "arena_size"},
		{"iram missing", func(c *Context) { c.Hardware.Memory.IramSize = "" }, "iram_size are mandatory"},
		{"iram invalid", func(c *Context) { c.Hardware.Memory.IramBase = "0x" }, "memory.iram_base"},
		{"reserved ram base", func(c *Context) { c.Hardware.ReservedRamRegions[0].Base = "nope" }, "reserved_ram_regions[confirm_nonce]"},
		{"partitions", func(c *Context) { c.Device.Partitions.AppSize = 0 }, "mandatory in [partitions]"},
		{"reset value outside code mask", func(c *Context) {
			c.Hardware.ResetCauses.Codes[0].Value = 0x30
			c.Hardware.ResetCauses.Codes[0].Mask = 0x10
		}, "bits outside its mask"},
		{"reset name", func(c *Context) { c.Hardware.ResetCauses.Codes[0].Name = "" }, "must be a valid C identifier"},
		{"reset name not an identifier", func(c *Context) { c.Hardware.ResetCauses.Codes[0].Name = "bad name" }, "must be a valid C identifier"},
		{"reset duplicate name", func(c *Context) {
			c.Hardware.ResetCauses.Codes = append(c.Hardware.ResetCauses.Codes,
				ResetCauseCode{Name: strings.ToLower(c.Hardware.ResetCauses.Codes[0].Name), Value: 200})
		}, "defined more than once"},
		{"reset duplicate value", func(c *Context) {
			c.Hardware.ResetCauses.Codes = append(c.Hardware.ResetCauses.Codes,
				ResetCauseCode{Name: "extra_cause", Value: c.Hardware.ResetCauses.Codes[0].Value})
		}, "share the hardware code"},
		{"max retries", func(c *Context) { c.Device.BootConfig.MaxRetries = 0 }, "max_retries"},
		{"chip name unsafe", func(c *Context) { c.Device.Device.Chip = "../evil" }, "invalid chip name"},
		{"REG-003 violated", func(c *Context) {
			c.Device.Partitions.EnableDeltas = true
			c.Chip.SlotCapabilities.ExecModel = "fixed"
		}, "REG-003"},
		{"REG-003 scratch", func(c *Context) {
			c.Device.Partitions.EnableDeltas = true
			c.Chip.SlotCapabilities.ExecModel = "fixed"
			c.Chip.SlotCapabilities.HasScratch = true
		}, ""},
		{"REG-003 remappable", func(c *Context) { c.Device.Partitions.EnableDeltas = true }, ""},
		{"REG-007", func(c *Context) { c.Device.Recovery.Crypto.Backend = "None" }, "REG-007"},
		{"REG-007 justified", func(c *Context) {
			c.Device.Recovery.Crypto.Backend = "none"
			c.Device.Recovery.Crypto.Justification = "covered by boot_proof HMAC"
		}, ""},
		{"REG-009 compiler", func(c *Context) { c.Chip.MinCompiler = "LATEST" }, "min_compiler"},
		{"REG-009 sdk without caps", func(c *Context) {
			c.Chip.SlotCapabilities = nil
			c.Chip.MinCoreSDK = "latest"
		}, "min_core_sdk"},
		{"no chip manifest", func(c *Context) { c.Chip = nil }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := testContext(t)
			c.mutate(ctx)
			err := validateContext(ctx)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}
