package manifest

import (
	"fmt"
	"strings"
)

func Compile(tomlPath, hardwarePath, outDir, bootloaderDir string) error {
	dt, hj, err := LoadConfig(tomlPath, hardwarePath)
	if err != nil {
		return err
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

	alloc, err := NewAllocator(hj.Flash.Regions)
	if err != nil {
		return err
	}

	if dt.Partitions.Stage0Size == 0 || dt.Partitions.Stage1Size == 0 || dt.Partitions.AppSize == 0 {
		return fmt.Errorf("FATAL: stage0_size, stage1_size, app_size are mandatory in [partitions]")
	}

	s0Addr, s0Budget, err := alloc.Allocate(dt.Partitions.Stage0Size, 0, "Stage 0")
	if err != nil { return err }
	s1aAddr, s1Budget, err := alloc.Allocate(dt.Partitions.Stage1Size, 0, "Stage 1A")
	if err != nil { return err }
	s1bAddr, _, err := alloc.Allocate(dt.Partitions.Stage1Size, 0, "Stage 1B")
	if err != nil { return err }

	appAlign := hj.Flash.AppAlignment
	if appAlign == 0 {
		appAlign = alloc.maxSectorSize
	}

	appAddr, appBudget, err := alloc.Allocate(dt.Partitions.AppSize, appAlign, "App Slot")
	if err != nil { return err }
	stagingAddr, _, err := alloc.Allocate(dt.Partitions.AppSize, appAlign, "Staging Slot")
	if err != nil { return err }

	var recAddr, recBudget uint32
	if dt.Partitions.RecoverySize > 0 {
		recAddr, recBudget, err = alloc.Allocate(dt.Partitions.RecoverySize, appAlign, "Recovery OS")
		if err != nil { return err }
	}

	var netAddr, netBudget uint32
	if dt.Partitions.NetcoreSize > 0 {
		netAddr, netBudget, err = alloc.Allocate(dt.Partitions.NetcoreSize, appAlign, "NetCore Slot")
		if err != nil { return err }
	}

	scratchBudget := dt.Partitions.ScratchSize
	if scratchBudget == 0 {
		scratchBudget = appBudget
	}
	scratchAddr, scratchSize, err := alloc.Allocate(scratchBudget, 0, "Scratch Buffer")
	if err != nil { return err }

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
		if err != nil { return err }
		alloc.offset = newOffset

		targetSecSize, err := alloc.GetSectorSizeAt(alloc.offset)
		if err != nil { return err }
		addr, size, err := alloc.Allocate(targetSecSize, 0, fmt.Sprintf("WAL Sector %d", i))
		if err != nil { return err }
		walAddrs = append(walAddrs, addr)
		walSizes = append(walSizes, size)
		walSize += size
	}
	if len(walAddrs) > 0 {
		walAddr = walAddrs[0]
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
		walAddrs, walSizes)
	if err != nil {
		return fmt.Errorf("failed to generate outputs: %w", err)
	}

	fmt.Printf("Manifest Compiler (Go Native): Successfully generated headers and ld scripts to %s\n", outDir)

	if err := VerifyMacroUsage(outDir+"/generated_boot_config.h", bootloaderDir); err != nil {
		return err
	}

	return nil
}
