import json
import os


def generate_chip_capabilities(spec, chip_name, out_dir, footprint_size=0x40000):
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
        return str(val).replace("_", "")

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

    # True Physical Shield Base is the MMIO mapped flash address where the user app lives
    flash_shield_base = user_app

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
    {{ {flash_shield_base}, {hex(footprint_size)} }}, // {footprint_size//1024}KB firmware self-preservation
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

def generate_flash_hal(spec, chip_name, out_dir):
    """
    Consumes the declarative JSON instruction array for pure bare-metal Flash operations.
    Translates literal JSON operations into raw C pointer manipulations.
    """
    flash_ctrl = spec.get("flash_controller", {})
    if not flash_ctrl or not flash_ctrl.get("erase_sector_sequence"):
        return None # No flash generation requested/possible yet
    
    c_path = os.path.join(out_dir, f"hal_flash_{chip_name}.c")
    
    def compile_sequence(seq):
        lines = []
        for step in seq:
            t = step.get("type")
            offset = step.get("offset", "0x0")
            desc = step.get("desc", "")
            
            if desc:
                lines.append(f"    // {desc}")
                
            base_str = "0x0" # To be replaced with macro or hardcode if needed
            # We assume offset includes the base address or we construct it.
            # In our prompt, the LLM sets the base in flash_controller and offset is relative, 
            # OR LLM provides absolute offsets. Let's do BASE + OFFSET safely.
            base_addr = flash_ctrl.get("base_address", "0x0")
            ptr_macro = f"(*((volatile uint32_t*)({base_addr} + {offset})))"
            
            if t == "rom_function_call":
                fn = step.get("function_name", "UNKNOWN_ROM_FN")
                args = step.get("args_csv", "")
                addr = step.get("rom_address", "0x0")
                
                # Architecture-Agnostic Memory Map Translation
                if step.get("requires_physical_offset") and "sector_addr" in args:
                    # Dynamically extract the flash origin mapped by Stage 1 Memory Rules
                    flash_origin = "0x0"
                    for r in spec.get("memory", {}).get("memory_regions", []):
                        if "rx" in r.get("permissions", "") and "w" not in r.get("permissions", ""):
                            flash_origin = r.get("origin", "0x0")
                            break
                    
                    # C-Compiler translates Memory-Mapped Address -> Physical 0-Indexed Offset
                    args = args.replace("sector_addr", f"(sector_addr - {flash_origin})")
                
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
            
        return "\n".join(lines)
        
    unlock_c = compile_sequence(flash_ctrl.get("unlock_sequence", []))
    erase_c = compile_sequence(flash_ctrl.get("erase_sector_sequence", []))
    write_c = compile_sequence(flash_ctrl.get("write_word_sequence", []))
    
    # -------------------------------------------------------------------------
    # DYNAMIC FLASH READ GENERATION (Hardware-Agnostic MMU/Cache Bypass)
    # -------------------------------------------------------------------------
    read_seq = flash_ctrl.get("read_word_sequence", [])
    if not read_seq and chip_name == "esp32":
        # Temporary declarative inject for ESP32 MMU bypass until LLM Prompt 5 is updated
        read_seq = [{
            "args_csv": "(sector_addr - 0x40000000), out_val, 4",
            "desc": "Direct SPIRead via BootROM (MMU/Cache Bypass)",
            "function_name": "SPIRead",
            "requires_physical_offset": False, # We handled the -0x40000000 manually above
            "rom_address": "0x40062B18",
            "type": "rom_function_call",
            "prototype": "void(*)(uint32_t, uint32_t*, int32_t)"
        }]
    
    if read_seq:
        read_c = compile_sequence(read_seq)
    else:
        # 100% agnostic fallback for architectures without external MMUs (Cortex-M)
        read_c = "    if (out_val) *out_val = *((volatile uint32_t*)sector_addr);\n"

    c_content = f"""/* Auto-Generated Bare-Metal Flash HAL for {chip_name} */
#include <stdint.h>
#include <stdbool.h>

extern void fz_log(const char *msg); // Ensure logger availability

void hal_print_status(void) {{
    fz_log("[HAL] Active Backend: Real Hardware SPI Driver (AI Generated)\\n");
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
        
    print(f"[*] Generated True SPI Flash HAL: {c_path}")
    return c_path
