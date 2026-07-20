package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/toob-boot/toob/internal/ui"
)

func Compile(tomlPath, hardwarePath, outDir, bootloaderDir, halChipDir string, extraDirs []string) error {
	dt, hj, err := LoadConfig(tomlPath, hardwarePath)
	if err != nil {
		return err
	}

	// Read and parse chip_manifest.json if present in halChipDir (ST-016 / Validation)
	var cm ChipManifest
	cmPath := filepath.Join(halChipDir, "chip_manifest.json")
	hasCapabilities := false
	if data, err := os.ReadFile(cmPath); err == nil {
		if err := json.Unmarshal(data, &cm); err == nil && cm.SlotCapabilities != nil {
			hasCapabilities = true
		}
	}

	// Auto-selection or validation of transport provider based on capabilities
	if hasCapabilities && cm.SlotCapabilities != nil {
		caps := cm.SlotCapabilities
		provider := strings.ToLower(dt.BootConfig.TransportProvider)

		if provider == "" {
			// Auto-selection algorithm
			if caps.SlotCount >= 2 && (caps.ExecModel == "xip_remap" || caps.ExecModel == "bank_swap" || caps.ExecModel == "relocatable") {
				dt.BootConfig.TransportProvider = "pointer"
			} else if caps.SlotCount >= 2 {
				dt.BootConfig.TransportProvider = "oneway"
			} else if caps.HasScratch {
				dt.BootConfig.TransportProvider = "swapscratch"
			} else {
				dt.BootConfig.TransportProvider = "swapmove"
			}
			ui.Success("Auto-selected transport provider '%s' based on chip capabilities", dt.BootConfig.TransportProvider)
		} else {
			// Validation algorithm
			switch provider {
			case "pointer":
				if caps.SlotCount < 2 {
					return fmt.Errorf("FATAL: transport provider 'pointer' requires slot_count >= 2, but chip has %d", caps.SlotCount)
				}
				if caps.ExecModel != "xip_remap" && caps.ExecModel != "bank_swap" && caps.ExecModel != "relocatable" {
					return fmt.Errorf("FATAL: transport provider 'pointer' requires a remappable, bank-swappable, or relocatable execution model, but chip has '%s'", caps.ExecModel)
				}
			case "oneway":
				if caps.SlotCount < 2 && dt.Partitions.ScratchSize == 0 {
					return fmt.Errorf("FATAL: transport provider 'oneway' requires slot_count >= 2 or a configured scratch partition for backup, but chip has %d slots and scratch size is 0", caps.SlotCount)
				}
			case "swapscratch":
				if !caps.HasScratch && dt.Partitions.ScratchSize == 0 {
					return fmt.Errorf("FATAL: transport provider 'swapscratch' requires a scratch partition, but scratch size is 0")
				}
			case "swapmove":
				// swapmove works on any chip
			default:
				return fmt.Errorf("FATAL: unknown transport provider '%s'", dt.BootConfig.TransportProvider)
			}
		}
	} else {
		// Fallback auto-selection if capabilities are not defined in registry
		if dt.BootConfig.TransportProvider == "" {
			dt.BootConfig.TransportProvider = "swapscratch"
			ui.Warn("No chip capabilities declared; falling back to default 'swapscratch' transport provider")
		}
	}

	// Delta coherence check (REG-003):
	// enable_deltas requires either:
	//   a) has_scratch == true (scratch-based delta strategy), or
	//   b) exec_model is xip_remap/bank_swap/relocatable (scratch-less delta via pointer transport)
	if dt.Partitions.EnableDeltas && hasCapabilities && cm.SlotCapabilities != nil {
		caps := cm.SlotCapabilities
		scratchLessCapable := caps.ExecModel == "xip_remap" ||
			caps.ExecModel == "bank_swap" ||
			caps.ExecModel == "relocatable"
		if !caps.HasScratch && !scratchLessCapable {
			return fmt.Errorf(
				"FATAL [REG-003]: enable_deltas = true requires either "+
					"has_scratch = true or a scratch-less execution model "+
					"(xip_remap, bank_swap, relocatable), but chip '%s' has "+
					"has_scratch = %v and exec_model = '%s'",
				hj.ChipFamily, caps.HasScratch, caps.ExecModel)
		}
	}

	tomlChip := strings.ToLower(strings.ReplaceAll(dt.Device.Chip, "-", ""))
	hwChip := strings.ToLower(strings.ReplaceAll(hj.ChipFamily, "-", ""))
	if tomlChip != hwChip {
		return fmt.Errorf("FATAL: device.toml chip (%s) does not match hardware.json chip_family (%s)", tomlChip, hwChip)
	}

	if hj.Flash.Size == 0 {
		return fmt.Errorf("FATAL: flash.size is mandatory in hardware.json")
	}

	if len(hj.Flash.Regions) == 0 {
		return fmt.Errorf("FATAL: flash.regions array is mandatory in hardware.json")
	}

	for _, r := range hj.Flash.Regions {
		if r.Type == "writable" || r.Type == "" {
			if r.SectorSize == 0 || r.Count == 0 {
				return fmt.Errorf("FATAL [FLASH_004]: Writable flash region '%s' must specify both 'sector_size' and 'count'", r.Name)
			}
		}
	}

	alloc, err := NewAllocator(hj.Flash.Regions)
	if err != nil {
		return err
	}

	if dt.Partitions.Stage0Size == 0 || dt.Partitions.Stage1Size == 0 || dt.Partitions.AppSize == 0 {
		return fmt.Errorf("FATAL: stage0_size, stage1_size, app_size are mandatory in [partitions]")
	}

	s0Addr, s0Budget, err := alloc.Allocate(dt.Partitions.Stage0Size, 0, "Stage 0")
	if err != nil {
		return err
	}
	s1aAddr, s1Budget, err := alloc.Allocate(dt.Partitions.Stage1Size, 0, "Stage 1A")
	if err != nil {
		return err
	}
	s1bAddr, _, err := alloc.Allocate(dt.Partitions.Stage1Size, 0, "Stage 1B")
	if err != nil {
		return err
	}

	appAlign := hj.Flash.AppAlignment
	if appAlign == 0 {
		appAlign = alloc.maxSectorSize
	}

	appAddr, appBudget, err := alloc.Allocate(dt.Partitions.AppSize, appAlign, "App Slot")
	if err != nil {
		return err
	}
	stagingAddr, _, err := alloc.Allocate(dt.Partitions.AppSize, appAlign, "Staging Slot")
	if err != nil {
		return err
	}

	var recAddr, recBudget uint32
	if dt.Partitions.RecoverySize > 0 {
		recAddr, recBudget, err = alloc.Allocate(dt.Partitions.RecoverySize, appAlign, "Recovery OS")
		if err != nil {
			return err
		}
	}

	var netAddr, netBudget uint32
	if dt.Partitions.NetcoreSize > 0 {
		netAddr, netBudget, err = alloc.Allocate(dt.Partitions.NetcoreSize, appAlign, "NetCore Slot")
		if err != nil {
			return err
		}
	}

	// Scratch allocation: only needed when the transport provider performs
	// physical data movement (swapscratch, swapmove, oneway).
	// Pointer-transport (xip_remap) remaps the MMU in-place and needs no scratch.
	var scratchAddr, scratchSize uint32
	transport := strings.ToLower(dt.BootConfig.TransportProvider)
	needsScratch := transport == "swapscratch" || transport == "swapmove" || transport == "oneway"
	if needsScratch {
		scratchBudget := dt.Partitions.ScratchSize
		if scratchBudget == 0 {
			scratchBudget = appBudget
		}
		scratchAddr, scratchSize, err = alloc.Allocate(scratchBudget, 0, "Scratch Buffer")
		if err != nil {
			return err
		}
	}

	walSectors := dt.Partitions.WalSectors
	if walSectors == 0 {
		walSectors = 4
	}

	var walAddrs []uint32
	var walSizes []uint32
	walAddr := uint32(0)
	walSize := uint32(0)

	for i := uint32(0); i < walSectors; i++ {
		newOffset, err := alloc.advanceToWritable(alloc.offset)
		if err != nil {
			return err
		}
		alloc.offset = newOffset

		targetSecSize, err := alloc.GetSectorSizeAt(alloc.offset)
		if err != nil {
			return err
		}
		addr, size, err := alloc.Allocate(targetSecSize, 0, fmt.Sprintf("WAL Sector %d", i))
		if err != nil {
			return err
		}
		walAddrs = append(walAddrs, addr)
		walSizes = append(walSizes, size)
		walSize += size
	}
	if len(walAddrs) > 0 {
		walAddr = walAddrs[0]
	}

	// Allocate KDM Quorum (3 sectors)
	kdmSize := 3 * alloc.maxSectorSize
	kdmAddr, kdmBudget, err := alloc.Allocate(kdmSize, 0, "KDM Quorum")
	if err != nil {
		return err
	}

	// Allocate Cloud Command (1 sector)
	cloudCmdSize := alloc.maxSectorSize
	cloudCmdAddr, cloudCmdBudget, err := alloc.Allocate(cloudCmdSize, 0, "Cloud Command")
	if err != nil {
		return err
	}

	// Allocate OS→Core Mailbox (2 sectors, Double-Slot: 2×SectorSize)
	mailboxSize := 2 * alloc.maxSectorSize
	mailboxAddr, mailboxBudget, err := alloc.Allocate(mailboxSize, 0, "Mailbox")
	if err != nil {
		return err
	}

	// Allocate Forensic Slot (1 sector)
	forensicSize := alloc.maxSectorSize
	forensicAddr, forensicBudget, err := alloc.Allocate(forensicSize, 0, "Forensic Slot")
	if err != nil {
		return err
	}

	if alloc.offset > hj.Flash.Size {
		return fmt.Errorf("FATAL [FLASH_003]: Partitions exceed physical flash size! Required: %d bytes, Available: %d bytes", alloc.offset, hj.Flash.Size)
	}

	if hj.CryptoCapabilities.ArenaSize == 0 {
		return fmt.Errorf("FATAL: crypto_capabilities.arena_size is mandatory in hardware.json")
	}
	if hj.Memory.RamBase == "" || hj.Memory.RamSize == "" {
		return fmt.Errorf("FATAL: memory.ram_base and memory.ram_size are mandatory in hardware.json")
	}

	err = GenerateHeadersAndScripts(dt, hj, alloc, outDir,
		s0Addr, s0Budget, s1aAddr, s1bAddr, s1Budget, appAddr, stagingAddr, appBudget,
		recAddr, recBudget, netAddr, netBudget, scratchAddr, scratchSize, walAddr, walSize,
		walAddrs, walSizes, kdmAddr, kdmBudget, cloudCmdAddr, cloudCmdBudget, mailboxAddr, mailboxBudget, forensicAddr, forensicBudget)
	if err != nil {
		return fmt.Errorf("failed to generate outputs: %w", err)
	}

	ui.Success("Manifest Compiler (Go Native): Successfully generated headers and ld scripts to %s", outDir)

	if err := VerifyMacroUsage(outDir+"/generated_boot_config.h", bootloaderDir, halChipDir, extraDirs); err != nil {
		return err
	}

	return nil
}
