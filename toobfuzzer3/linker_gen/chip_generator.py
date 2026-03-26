import json
import os


def generate_chip_capabilities(spec, chip_name, out_dir):
    os.makedirs(out_dir, exist_ok=True)

    c_path = os.path.join(out_dir, f"capabilities_{chip_name}.c")

    sec = spec.get("security_registers", {})
    boot = spec.get("boot_vectors", {})
    mem = spec.get("memory", {})
    toolchain = spec.get("toolchain_requirements", {})

    # Helper to safely parse AI output which might contain "null" strings
    def parse_hex_addr(val):
        if not val or str(val).lower() == "null" or val == "None":
            return "0x0"
        return val

    # Extract Flash Encryption
    fe = sec.get("flash_encryption", {})
    fe_addr = parse_hex_addr(fe.get("register_addr"))
    fe_mask = parse_hex_addr(fe.get("bit_mask"))
    fe_active = str(fe.get("active_if_true", "true")).lower()

    # Extract RAM Layouts from new memory_regions format
    regions = mem.get("memory_regions", [])
    exec_seg_name = mem.get("executable_segment", "iram")
    data_seg_name = mem.get("data_segment", "dram")

    iram_base = "0x0"
    iram_length = "0x10000"
    dram_base = "0x0"
    dram_length = "0x10000"

    protected_blocks = []

    for r in regions:
        if r.get("name") == exec_seg_name:
            iram_base = parse_hex_addr(r.get("origin"))
            iram_length = parse_hex_addr(r.get("length"))
        elif r.get("name") == data_seg_name:
            dram_base = parse_hex_addr(r.get("origin"))
            dram_length = parse_hex_addr(r.get("length"))

        # Register Hardware Skips (BootROM, Caches, Reserved)
        is_skipped = (
            ("-" in r.get("permissions", ""))
            or ("cache" in r.get("name", "").lower())
            or ("reserved" in r.get("name", "").lower())
        )
        if is_skipped:
            origin = parse_hex_addr(r.get("origin"))
            length = parse_hex_addr(r.get("length"))
            if origin != "0x0" and length != "0x0":
                protected_blocks.append(
                    f"    {{ {origin}, {length} }}, // {r.get('name')}"
                )

    # Extract JTAG
    jtag = sec.get("jtag_disabled", {})
    jtag_addr = parse_hex_addr(jtag.get("register_addr"))
    jtag_mask = parse_hex_addr(jtag.get("bit_mask"))
    jtag_active = str(jtag.get("active_if_true", "true")).lower()

    # Extract RDP
    rdp = sec.get("rdp_level", {})
    rdp_addr = parse_hex_addr(rdp.get("register_addr"))
    rdp_mask = parse_hex_addr(rdp.get("bit_mask"))

    # Boot Vectors & Physical Flash Mapping
    user_app = parse_hex_addr(boot.get("user_app_base", "0x1000"))
    rom_base = parse_hex_addr(boot.get("rom_base", "0x0"))

    # Calculate True Physical Shield Base (ROM Base + Flash Flashing Offset)
    flash_config = toolchain.get("flashing", {})
    flash_offset = parse_hex_addr(flash_config.get("flash_offset", "0x0"))

    try:
        flash_shield_base = hex(int(rom_base, 16) + int(flash_offset, 16))
    except:
        flash_shield_base = user_app  # Fallback to XIP map if parsing fails

    # Construct the protected arrays string
    protected_blocks_c = "\n".join(protected_blocks)

    # Generate C Blocks for Security Reads conditionally
    rdp_block = f"// [AI] Mask not provided for RDP"
    if rdp_addr != "0x0" and rdp_mask != "0x0":
        rdp_block = f"""
    if ({rdp_addr} != 0x0) {{
        uint32_t val = raw_read32({rdp_addr});
        // We assume RDP level is indicated directly by the masked value
        caps.rdp_level = (val & {rdp_mask}); 
    }}"""

    fe_block = f"// [AI] Mask not provided for Flash Encryption"
    if fe_addr != "0x0" and fe_mask != "0x0":
        fe_block = f"""
    if ({fe_addr} != 0x0) {{
        uint32_t val = raw_read32({fe_addr});
        if ((val & {fe_mask}) != 0) {{
            caps.flash_encrypted = {fe_active};
        }}
    }}"""

    jtag_block = f"// [AI] Mask not provided for JTAG Disable"
    if jtag_addr != "0x0" and jtag_mask != "0x0":
        jtag_block = f"""
    if ({jtag_addr} != 0x0) {{
        uint32_t val = raw_read32({jtag_addr});
        if ((val & {jtag_mask}) != 0) {{
            caps.debug_access = !{jtag_active}; // If 'jtag_disabled' is true, debug_access is false
        }}
    }}"""

    c_content = f"""/* Auto-Generated Bare-Metal Capabilities for {chip_name} */
#include "fz_types.h"
#include <stdint.h>
#include <stdbool.h>

/* Safe direct memory reader for bare-metal no-HAL environments */
static inline uint32_t raw_read32(uint32_t addr) {{
    if (addr == 0x0) return 0;
    return *((volatile uint32_t*)addr);
}}

/* Dynamic Memory Shielding Arrays */
const fz_protect_region_t chip_protected_regions[] = {{
    {{ {flash_shield_base}, 0x80000 }}, // 512KB firmware self-preservation
{protected_blocks_c}
}};
const uint32_t chip_protected_count = sizeof(chip_protected_regions) / sizeof(chip_protected_regions[0]);

fz_caps_t chip_get_capabilities(void) {{
    fz_caps_t caps = {{0}};
    
    // AI-Discovered Boot Vectors & Memory Mappings
    caps.user_flash_base = {flash_shield_base}; // Natively aligns Fuzzer API with Physical Deployment Bounds
    caps.rom_base = {rom_base};
    
    caps.iram_base = {iram_base};
    caps.iram_length = {iram_length};
    caps.dram_base = {dram_base};
    caps.dram_length = {dram_length};
    
    // Physical Readout Protection (STM32, etc.)
    caps.rdp_level = 0;
    {rdp_block}
    
    // Flash Encryption (ESP32, nRF, etc.)
    {fe_block}
    
    // JTAG / Debug Interface Locks
    caps.debug_access = true; // Default open
    {jtag_block}

    
    // Baseline Capability Inference
    caps.raw_flash_rw = (caps.rdp_level == 0 && !caps.flash_encrypted);
    caps.bootrom_access = (caps.rdp_level == 0);
    
    return caps;
}}
"""
    with open(c_path, "w") as f:
        f.write(c_content)

    print(f"[*] Generated Capabilities Shim: {c_path}")
    return c_path
