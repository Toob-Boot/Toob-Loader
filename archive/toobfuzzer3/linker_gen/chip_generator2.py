import json
import os


def generate_chip_capabilities(spec, chip_name, out_dir, footprint_size=0x80000):
    os.makedirs(out_dir, exist_ok=True)

    c_path = os.path.join(out_dir, f"capabilities_{chip_name}.c")

    sec = spec.get("security_registers", {})
    boot = spec.get("boot_vectors", {})
    mem = spec.get("memory", {})

    # Helper to safely parse AI output which might contain "null" strings
    def parse_hex_addr(val):
        if not val or str(val).lower() == "null" or val == "None":
            return "0x0"
        return str(val).replace("_", "")

    # Extract Flash Encryption
    fe = sec.get("flash_encryption", {})
    fe_addr = parse_hex_addr(fe.get("register_addr"))
    fe_mask = parse_hex_addr(fe.get("bit_mask"))
    fe_active = str(fe.get("active_if_true", "true")).lower()

    # Extract RAM Layouts from new memory_regions format
    regions = mem.get("memory_regions", [])
    
    protected_blocks = []
    testable_ram_blocks = []

    for r in regions:
        origin = parse_hex_addr(r.get("origin"))
        length = parse_hex_addr(r.get("length"))
        
        # Check if RAM region
        is_ram = (
            "ram" in str(r.get("name", "")).lower()
            or "data" in str(r.get("name", "")).lower()
        )

        # Register Hardware Skips (BootROM, Caches, Reserved)
        is_skipped = (
            ("-" in str(r.get("permissions", "")))
            or ("cache" in str(r.get("name", "")).lower())
            or ("reserved" in str(r.get("name", "")).lower())
        )
        
        if is_skipped:
            if origin != "0x0" and length != "0x0":
                protected_blocks.append(
                    f"    {{ {origin}, {length} }}, // {r.get('name')}"
                )
        elif is_ram:
            if origin != "0x0" and length != "0x0":
                testable_ram_blocks.append(
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

    # True Physical Architecture:
    # Fuzzer ALWAYS discovers Physical Memory starting at Sector 0.
    # Shielding the first 512KB (0x0 to 0x80000) natively protects the Bootloader AND Payload.
    # This automatically triggers the Ping-Pong displacement oracle without shifting JSON values.
    flash_shield_base = "0x0"

    rom_base = parse_hex_addr(boot.get("rom_base", "0x0"))

    # Construct the protected arrays string
    protected_blocks_c = "\n".join(protected_blocks)
    testable_ram_c = "\n".join(testable_ram_blocks)

    # Generate C Blocks for Security Reads conditionally
    rdp_block = f"// [AI] Mask not provided for RDP"
    if rdp_addr != "0x0" and rdp_mask != "0x0":
        rdp_block = f"""
    if ({rdp_addr} != 0x0) {{
        uint32_t val = raw_read32({rdp_addr});
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
            caps.debug_access = !{jtag_active};
        }}
    }}"""

    c_content = f"""/* Auto-Generated Bare-Metal Capabilities for {chip_name} (Physical Architecture) */
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
    {{ {flash_shield_base}, {hex(footprint_size)} }}, // {footprint_size//1024}KB True Physical Bare-Metal Shield
{protected_blocks_c}
}};
const uint32_t chip_protected_count = sizeof(chip_protected_regions) / sizeof(chip_protected_regions[0]);

/* Dynamic Application RAM Array */
const fz_ram_region_t chip_testable_ram_regions[] = {{
{testable_ram_c}
}};
const uint32_t chip_testable_ram_count = sizeof(chip_testable_ram_regions) / sizeof(chip_testable_ram_regions[0]);

fz_caps_t chip_get_capabilities(void) {{
    fz_caps_t caps = {{0}};
    
    // AI-Discovered Boot Vectors & Memory Mappings
    caps.user_flash_base = 0x0; // Natively aligns Fuzzer API 1:1 with True Physical Silicon
    caps.rom_base = {rom_base};
    
    // Physical Readout Protection
    caps.rdp_level = 0;
    {rdp_block}
    
    // Flash Encryption
    {fe_block}
    
    // JTAG / Debug Interface Locks
    caps.debug_access = true;
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


def generate_flash_hal(spec, chip_name, out_dir):
    """
    Consumes the declarative JSON instruction array for pure bare-metal Flash operations.
    Translates literal JSON operations into raw C pointer manipulations natively linked
    to pure physical boundaries.
    """
    flash_ctrl = spec.get("flash_controller", {})
    if not flash_ctrl or not flash_ctrl.get("erase_sector_sequence"):
        return None  # No flash generation requested/possible yet

    c_path = os.path.join(out_dir, f"hal_flash_{chip_name}.c")

    def compile_sequence(seq):
        lines = []
        for step in seq:
            t = step.get("type")
            offset = step.get("offset", "0x0")
            desc = step.get("desc", "")

            if desc:
                lines.append(f"    // {desc}")

            base_addr = flash_ctrl.get("base_address", "0x0")
            ptr_macro = f"(*((volatile uint32_t*)({base_addr} + {offset})))"

            if t == "rom_function_call":
                fn = step.get("function_name", "UNKNOWN_ROM_FN")
                args = step.get("args_csv", "")
                addr = step.get("rom_address", "0x0")

                # In Physical Architecture, BootROM Erase/Write sequences take 'sector_addr' blindly.
                # No mmu_offset calculation needed. The Hardware obeys physics.

                proto = step.get("prototype", "void(*)()")
                if addr != "0x0" and addr:
                    lines.append(f"    // ROM ABI: {fn} @ {addr}")
                    lines.append(f"    (({proto}){addr})({args});")
                else:
                    lines.append(f"    // ERROR: Missing rom_address for {fn}!")
            elif t == "poll_bit_clear":
                mask = step.get("bit_mask", "0x0")
                lines.append(f"    while( {ptr_macro} & {mask} );")
            elif t == "set_bit":
                mask = step.get("bit_mask", "0x0")
                lines.append(f"    {ptr_macro} |= {mask};")
            elif t == "clear_bit":
                mask = step.get("bit_mask", "0x0")
                lines.append(f"    {ptr_macro} &= ~({mask});")
            elif t == "write_addr":
                if "value_hex" in step:
                    val = step.get("value_hex")
                    lines.append(f"    {ptr_macro} = {val};")
                elif "value_source" in step:
                    val = step.get("value_source")
                    lines.append(f"    {ptr_macro} = {val};")
            elif t == "raw_c":
                lines.append("    " + step.get("code", "").replace("\n", "\n    "))

        return "\n".join(lines)

    unlock_c = compile_sequence(flash_ctrl.get("unlock_sequence", []))
    erase_c = compile_sequence(flash_ctrl.get("erase_sector_sequence", []))
    write_c = compile_sequence(flash_ctrl.get("write_word_sequence", []))

    # -------------------------------------------------------------------------
    # DYNAMIC FLASH READ GENERATION (Hardware-Agnostic Physical Read Bypass)
    # -------------------------------------------------------------------------
    read_seq = flash_ctrl.get("read_word_sequence", [])
    if read_seq:
        read_c = compile_sequence(read_seq)
    else:
        # Fallback for Cortex-M (No external SPI cache controller deadlocks)
        read_c = "    if (out_val) *out_val = *((volatile uint32_t*)sector_addr);\n"

    # Universal D-Cache Eviction Hook was removed since we use physical BootROM Cache Control
    # or rely strictly on internal RAM boundaries for non-XiP architectures.

    # -------------------------------------------------------------------------
    # DYNAMIC WATCHDOG FEED GENERATION
    # -------------------------------------------------------------------------
    watchdog_seq = spec.get("watchdog_feed_sequence", [])
    watchdog_feed_lines = []
    for step in watchdog_seq:
        t = step.get("type")
        addr = step.get("address", "0x0")
        val = step.get("value", "0x0")
        desc = step.get("desc", "")
        if desc:
            watchdog_feed_lines.append(f"    // {desc}")
        ptr_macro = f"(*((volatile uint32_t*)({addr})))"
        
        if t == "memory_write":
            watchdog_feed_lines.append(f"    {ptr_macro} = {val};")
        elif t == "memory_or":
            watchdog_feed_lines.append(f"    {ptr_macro} |= {val};")
        elif t == "raw_c":
            watchdog_feed_lines.append("    " + step.get("code", "").replace("\n", "\n    "))
    watchdog_feed_c = "\n".join(watchdog_feed_lines)

    c_content = f"""/* Auto-Generated Bare-Metal Flash HAL for {chip_name} (Physical Architecture) */
#include <stdint.h>
#include <stdbool.h>

#include "logger.h"

void hal_print_status(void) {{
    fz_log("[HAL] Active Backend: True Physical Hardware MMU Driver\\n");
}}

void feed_hardware_watchdogs(void) {{
{watchdog_feed_c}
}}

bool chip_flash_erase(uint32_t sector_addr) {{
    // Unlock Sequence
{unlock_c}
    // Erase Sequence
{erase_c}
    
    return true;
}}

bool chip_flash_write32(uint32_t sector_addr, uint32_t data_word) {{
    // Unlock Sequence
{unlock_c}
    // Write Sequence
{write_c}

    return true;
}}

bool chip_flash_read32(uint32_t sector_addr, uint32_t *out_val) {{
    // Read Sequence
{read_c}
    return true;
}}
"""
    with open(c_path, "w") as f:
        f.write(c_content)

    print(f"[*] Generated True Physical SPI Flash HAL: {c_path}")
    return c_path
