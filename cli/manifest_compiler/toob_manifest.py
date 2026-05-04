#!/usr/bin/env python3
import os
import sys
import json
import argparse
import tomllib


def align_up(val, alignment):
    return (val + alignment - 1) & ~(alignment - 1)


def align_down(val, alignment):
    return val & ~(alignment - 1)


def main():
    parser = argparse.ArgumentParser(description="Toob-Boot Manifest Compiler")
    parser.add_argument("--toml", required=True, help="Path to device.toml")
    parser.add_argument("--hardware", required=True, help="Path to hardware.json")
    parser.add_argument(
        "--outdir", required=True, help="Output directory for headers and ld scripts"
    )

    args = parser.parse_args()

    # Load inputs
    try:
        with open(args.toml, "rb") as f:
            toml_data = tomllib.load(f)
    except Exception as e:
        print(f"FATAL: Could not read {args.toml}: {e}")
        sys.exit(1)

    try:
        with open(args.hardware, "r") as f:
            blueprint_data = json.load(f)
    except Exception as e:
        print(f"FATAL: Could not read {args.hardware}: {e}")
        sys.exit(1)

    # GAP-15: Cross-file validation
    toml_chip = toml_data.get("device", {}).get("chip", "").replace("-", "").lower()
    hw_chip = blueprint_data.get("chip_family", "").replace("-", "").lower()
    if toml_chip != hw_chip:
        print(f"FATAL: device.toml chip ({toml_chip}) does not match hardware.json chip_family ({hw_chip})")
        sys.exit(1)

    # Hardware facts
    flash_info = blueprint_data.get("flash", {})
    # GAP-05: Mandatory flash size
    if "size" not in flash_info:
        print("FATAL: flash.size is mandatory in hardware.json")
        sys.exit(1)
    flash_size = flash_info["size"]
    
    # GAP-06: Safe minimum write alignment
    write_align = flash_info.get("write_alignment", 1)
    
    regions = flash_info.get("regions", [])
    # GAP-08: Remove legacy fallback with 999999 count
    if not regions:
        print("FATAL: flash.regions array is mandatory in hardware.json")
        sys.exit(1)

    # GAP-02: Pre-calculate max_sector_size correctly once
    max_sector_size = 0
    for r in regions:
        if r.get("type", "writable") == "writable":
            max_sector_size = max(max_sector_size, r.get("sector_size", 0))
    if max_sector_size == 0:
        print("FATAL: No writable regions defined with valid sector_size")
        sys.exit(1)

    def get_sector_size_at(addr):
        for r in regions:
            if r.get("type", "writable") == "writable":
                base = r.get("base", 0)
                sec_sz = r.get("sector_size", max_sector_size)
                count = r.get("count", 0)
                if base <= addr < base + sec_sz * count:
                    return sec_sz
        # GAP-07: Abort instead of 4096 fallback
        print(f"FATAL: Address 0x{addr:X} does not fall within any writable flash region")
        sys.exit(1)

    def advance_to_writable(addr):
        while True:
            in_reserved = False
            for r in regions:
                if r.get("type", "writable") == "reserved":
                    base = r.get("base", 0)
                    size = r.get("size", 0)
                    if base <= addr < base + size:
                        addr = base + size
                        in_reserved = True
                        break
            if not in_reserved:
                break

        # Align to sector
        sec_sz = get_sector_size_at(addr)
        if addr % sec_sz != 0:
            addr = ((addr + sec_sz - 1) // sec_sz) * sec_sz
            return advance_to_writable(
                addr
            )  # Re-check if alignment pushed us into reserved
        return addr

    current_offset = 0

    def allocate(budget_req, force_align=0):
        nonlocal current_offset
        if force_align > 0:
            current_offset = (
                (current_offset + force_align - 1) // force_align
            ) * force_align

        current_offset = advance_to_writable(current_offset)

        sec_sz = get_sector_size_at(current_offset)
        budget = ((budget_req + sec_sz - 1) // sec_sz) * sec_sz

        addr = current_offset
        current_offset += budget

        # Fast-forward past any reserved regions we might have hit
        for r in regions:
            if r.get("type", "writable") == "reserved":
                base = r.get("base", 0)
                size = r.get("size", 0)
                if addr < base + size and current_offset > base:
                    current_offset = advance_to_writable(base + size)
                    return allocate(budget_req, force_align)

        return addr, budget

    # Budgets from user
    partitions = toml_data.get("partitions", {})
    # GAP-09: Mandatory core partitions
    for key in ("stage0_size", "stage1_size", "app_size"):
        if key not in partitions:
            print(f"FATAL: {key} is mandatory in [partitions]")
            sys.exit(1)
            
    enable_deltas = partitions.get("enable_deltas", True)
    wal_sectors = partitions.get("wal_sectors", 4)

    boot_config = toml_data.get("boot_config", {})
    max_retries = boot_config.get("max_retries", 3)
    max_recovery_retries = boot_config.get("max_recovery_retries", 3)
    # GAP-14: Emit 1 or 0 instead of true/false string
    edge_unattended_mode = "1" if boot_config.get("edge_unattended_mode", False) else "0"
    backoff_base_s = boot_config.get("backoff_base_s", 3600)
    wdt_timeout_ms = boot_config.get("wdt_timeout_ms", 4100)

    # Phase 2: Memory Allocation Engine (Sequential Flash Pack)
    s0_addr, s0_budget = allocate(partitions["stage0_size"])
    s1a_addr, s1_budget = allocate(partitions["stage1_size"])
    s1b_addr, _ = allocate(partitions["stage1_size"])

    # GAP-10: Dynamic APP alignment, fallback to sector size instead of 64KB
    app_align = flash_info.get("app_alignment", max_sector_size)
    app_addr, app_budget = allocate(
        partitions["app_size"], force_align=app_align
    )
    staging_addr, _ = allocate(
        partitions["app_size"], force_align=app_align
    )

    if partitions.get("recovery_size"):
        rec_addr, rec_budget = allocate(partitions.get("recovery_size", 128 * 1024))
    else:
        rec_addr, rec_budget = 0x0, 0x0

    if partitions.get("netcore_size"):
        net_addr, net_budget = allocate(partitions.get("netcore_size", 64 * 1024))
    else:
        net_addr, net_budget = 0x0, 0x0

    # Scratch Slot
    scratch_addr, scratch_size = allocate(app_budget)

    # WAL Configuration
    wal_addr_temp = advance_to_writable(current_offset)
    wal_size_req = 0
    tmp_addr = wal_addr_temp
    for _ in range(wal_sectors):
        sec_sz = get_sector_size_at(tmp_addr)
        wal_size_req += sec_sz
        tmp_addr += sec_sz

    wal_addr, wal_size = allocate(wal_size_req)

    if current_offset > flash_size:
        print(
            f"FATAL [FLASH_003]: Partitions exceed physical flash size! Required: {current_offset} bytes, Available: {flash_size} bytes"
        )
        sys.exit(1)

    # Output Generation
    os.makedirs(args.outdir, exist_ok=True)

    header_path = os.path.join(args.outdir, "generated_boot_config.h")
    ld_path = os.path.join(args.outdir, "generated_memory.ld")

    # Generate generated_boot_config.h
    with open(header_path, "w") as f:
        f.write("/* AUTO-GENERATED BY TOOB MANIFEST COMPILER */\n")
        f.write("#ifndef GENERATED_BOOT_CONFIG_H\n")
        f.write("#define GENERATED_BOOT_CONFIG_H\n\n")
        f.write("#include <stdint.h>\n\n")

        # GAP-01: Removed duplicate CHIP_FLASH_MAX_SECTOR_SIZE definition here. It is defined at the bottom.
        
        f.write(f"#define CHIP_FLASH_WRITE_ALIGNMENT  {write_align}U\n")
        # GAP-03: Dynamic Flash Base
        flash_base = flash_info.get("base_addr", "0x00000000")
        f.write(f"#define CHIP_FLASH_BASE_ADDR        {flash_base}U\n")

        # Calculate bootrom_reserved dynamically from reserved regions starting at 0
        bootrom_end = 0
        for r in regions:
            if r.get("base", 0) == 0 and r.get("type", "writable") == "reserved":
                bootrom_end = r.get("size", 0)
        f.write(f"#define CHIP_BOOTROM_RESERVED_END   0x{bootrom_end:08X}U\n\n")

        f.write(f"#define CHIP_STAGE0_ABS_ADDR        0x{s0_addr:08X}U\n")
        f.write(f"#define CHIP_STAGE0_SIZE            0x{s0_budget:08X}U\n")
        f.write(f"#define CHIP_STAGE1A_ABS_ADDR       0x{s1a_addr:08X}U\n")
        f.write(f"#define CHIP_STAGE1A_SIZE           0x{s1_budget:08X}U\n")
        f.write(f"#define CHIP_STAGE1B_ABS_ADDR       0x{s1b_addr:08X}U\n")
        f.write(f"#define CHIP_STAGE1B_SIZE           0x{s1_budget:08X}U\n\n")

        f.write(f"#define CHIP_APP_SLOT_ABS_ADDR      0x{app_addr:08X}U\n")
        f.write(f"#define CHIP_APP_SLOT_SIZE          0x{app_budget:08X}U\n")
        f.write(f"#define CHIP_STAGING_SLOT_ABS_ADDR  0x{staging_addr:08X}U\n")
        f.write(f"#define CHIP_STAGING_SLOT_SIZE      0x{app_budget:08X}U\n")
        # GAP-04: Dynamic Staging Slot ID (App is usually 1, Staging is usually 2)
        staging_slot_id = partitions.get("staging_slot_id", 2)
        f.write(f"#define CHIP_STAGING_SLOT_ID        {staging_slot_id}U\n\n")

        f.write(f"#define CHIP_RECOVERY_OS_ABS_ADDR   0x{rec_addr:08X}U\n")
        f.write(f"#define CHIP_RECOVERY_OS_SIZE       0x{rec_budget:08X}U\n")
        f.write(f"#define CHIP_NETCORE_SLOT_ABS_ADDR  0x{net_addr:08X}U\n")
        f.write(f"#define CHIP_NETCORE_SLOT_SIZE      0x{net_budget:08X}U\n\n")

        f.write(
            f"/* CRITICAL: Must be >= CHIP_APP_SLOT_SIZE for boot_delta_apply output */\n"
        )
        f.write(f"#define CHIP_SCRATCH_SLOT_ABS_ADDR  0x{scratch_addr:08X}U\n")
        f.write(f"#define CHIP_SCRATCH_SLOT_SIZE      0x{scratch_size:08X}U\n\n")

        f.write(f"#define TOOB_WAL_BASE_ADDR          0x{wal_addr:08X}U\n")
        f.write(f"#define TOOB_WAL_SECTORS            {wal_sectors}U\n")
        f.write(f"#define CHIP_WAL_SECTORS            TOOB_WAL_SECTORS\n")
        f.write(f"#define TOOB_WAL_SIZE               0x{wal_size:04X}U\n\n")

        # WAL Arrays
        wal_addrs = []
        wal_sizes = []
        tmp = wal_addr
        for i in range(wal_sectors):
            wal_addrs.append(tmp)
            sz = get_sector_size_at(tmp)
            wal_sizes.append(sz)
            tmp += sz

        f.write("#define TOOB_WAL_SECTOR_ADDRS { \\\n")
        for i, a in enumerate(wal_addrs):
            f.write(f"    0x{a:08X}U{',' if i < wal_sectors - 1 else ''} \\\n")
        f.write("}\n")

        f.write("#define TOOB_WAL_SECTOR_SIZES { \\\n")
        for i, s in enumerate(wal_sizes):
            f.write(f"    {s}U{',' if i < wal_sectors - 1 else ''} \\\n")
        f.write("}\n\n")

        # Crypto Arena (Derived from blueprint)
        # GAP-13: Mandatory crypto arena size
        crypto_caps = blueprint_data.get("crypto_capabilities", {})
        if "arena_size" not in crypto_caps:
            print("FATAL: crypto_capabilities.arena_size is mandatory in hardware.json")
            sys.exit(1)
        crypto_size = crypto_caps["arena_size"]
        f.write(f"#define BOOT_CRYPTO_ARENA_SIZE      {crypto_size}U\n\n")

        # WDT Timeout
        f.write(f"#define BOOT_WDT_TIMEOUT_MS         {wdt_timeout_ms}U\n\n")

        # Dynamic XIP Base from hardware.json
        xip_base_str = flash_info.get("xip_base", "0x0")
        f.write(f"#define CHIP_FLASH_XIP_BASE         {xip_base_str}U\n\n")
        f.write(f"#define CHIP_FLASH_TOTAL_SIZE       0x{flash_size:08X}U\n")

        # Global Boot Config Constants
        f.write(f"#define CHIP_FLASH_MAX_SECTOR_SIZE  {max_sector_size}U\n")
        f.write(f"#define BOOT_CONFIG_MAX_RETRIES     {max_retries}U\n")
        f.write(f"#define BOOT_CONFIG_MAX_RECOVERY_RETRIES {max_recovery_retries}U\n")
        f.write(f"#define BOOT_CONFIG_EDGE_UNATTENDED_MODE {edge_unattended_mode}\n")
        f.write(f"#define BOOT_CONFIG_BACKOFF_BASE_S  {backoff_base_s}U\n\n")

        f.write("#endif /* GENERATED_BOOT_CONFIG_H */\n")

    # Generate generated_memory.ld
    with open(ld_path, "w") as f:
        f.write("/* AUTO-GENERATED BY TOOB MANIFEST COMPILER */\n")
        f.write(f"__S0_BUDGET_START = 0x{s0_addr:08X};\n")
        f.write(f"__S0_BUDGET_SIZE = 0x{s0_budget:08X};\n")
        f.write(f"__S1A_BUDGET_START = 0x{s1a_addr:08X};\n")
        f.write(f"__S1B_BUDGET_START = 0x{s1b_addr:08X};\n")
        f.write(f"__S1_BUDGET_SIZE = 0x{s1_budget:08X};\n")
        f.write(f"__APP_BUDGET_START = 0x{app_addr:08X};\n")
        f.write(f"__APP_BUDGET_SIZE = 0x{app_budget:08X};\n")

    # Generate stage0_layout.ld
    memory_info = blueprint_data.get("memory", {})
    # GAP-11 & GAP-12: Mandatory RAM configurations
    if "ram_base" not in memory_info or "ram_size" not in memory_info:
        print("FATAL: memory.ram_base and memory.ram_size are mandatory in hardware.json")
        sys.exit(1)
    s0_ram_base = memory_info["ram_base"]
    s0_ram_size = memory_info["ram_size"]

    stage0_ld_path = os.path.join(args.outdir, "stage0_layout.ld")
    with open(stage0_ld_path, "w") as f:
        f.write("/* AUTO-GENERATED BY TOOB MANIFEST COMPILER */\n")
        f.write("/* Valid Stage 0 Layout */\n")
        f.write("ENTRY(main)\n\n")
        f.write("INCLUDE generated_memory.ld\n\n")
        f.write("MEMORY {\n")
        f.write(f"    S0_RAM (rwx) : ORIGIN = {s0_ram_base}, LENGTH = {s0_ram_size}\n")
        f.write(
            "    S0_ROM (rx)  : ORIGIN = __S0_BUDGET_START, LENGTH = __S0_BUDGET_SIZE\n"
        )
        f.write("}\n\n")
        f.write("SECTIONS {\n")
        f.write("    .text : {\n")
        f.write("        KEEP(*(.text.main))\n")
        f.write("        *(.text .text.*)\n")
        f.write("    } > S0_ROM\n\n")
        f.write("    .rodata : {\n")
        f.write("        *(.rodata .rodata.*)\n")
        f.write("        *(.srodata .srodata.*)\n")
        f.write("    } > S0_ROM\n\n")
        f.write("    .data : {\n")
        f.write("        *(.data .data.*)\n")
        f.write("        *(.sdata .sdata.*)\n")
        f.write("    } > S0_RAM AT > S0_ROM\n\n")
        f.write("    .bss (NOLOAD) : {\n")
        f.write("        *(.bss .bss.*)\n")
        f.write("        *(.sbss .sbss.*)\n")
        f.write("        *(COMMON)\n")
        f.write("    } > S0_RAM\n\n")
        f.write("    .toob_mock_section : {\n")
        f.write("        KEEP(*(.toob_mock_section))\n")
        f.write("    } > S0_ROM\n")
        f.write("}\n")

    print(
        f"Manifest Compiler: Successfully generated generated_boot_config.h, generated_memory.ld and stage0_layout.ld to {args.outdir}"
    )


if __name__ == "__main__":
    main()
