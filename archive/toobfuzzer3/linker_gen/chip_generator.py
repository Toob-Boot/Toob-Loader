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

    # Boot Vectors & Physical Flash Mapping
    user_app = parse_hex_addr(boot.get("user_app_base", "0x1000"))
    rom_base = parse_hex_addr(boot.get("rom_base", "0x0"))

    # True Physical Shield Base is the MMIO mapped flash address where the user app lives
    flash_shield_base = user_app

    # Construct the protected arrays string
    protected_blocks_c = "\n".join(protected_blocks)
    testable_ram_c = "\n".join(testable_ram_blocks)

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

/* Dynamic Application RAM Array */
const fz_ram_region_t chip_testable_ram_regions[] = {{
{testable_ram_c}
}};
const uint32_t chip_testable_ram_count = sizeof(chip_testable_ram_regions) / sizeof(chip_testable_ram_regions[0]);

fz_caps_t chip_get_capabilities(void) {{
    fz_caps_t caps = {{0}};
    
    // AI-Discovered Boot Vectors & Memory Mappings
    caps.user_flash_base = {flash_shield_base}; // Natively aligns Fuzzer API with Physical Deployment Bounds
    caps.rom_base = {rom_base};
    
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
                    mmu_offset = "0x0"
                    
                    # AI-Extracted 100% Agnostic Math: Virtual Origin - Physical Flash Offset = MMU Offset
                    try:
                        v_base_str = spec.get("boot_vectors", {}).get("user_app_base", "0x0").replace("_", "")
                        p_base_str = spec.get("toolchain_requirements", {}).get("flashing", {}).get("flash_offset", "0x0").replace("_", "")
                        
                        v_base = int(v_base_str, 16)
                        p_base = int(p_base_str, 16)
                        
                        if v_base > 0 and p_base > 0:
                            mmu_offset = f"0x{(v_base - p_base):X}"
                        else:
                            for r in spec.get("memory", {}).get("memory_regions", []):
                                if "rx" in r.get("permissions", "") and "w" not in r.get("permissions", ""):
                                    mmu_offset = r.get("origin", "0x0")
                                    break
                    except Exception:
                        pass
                    
                    # C-Compiler translates Memory-Mapped Address -> Physical 0-Indexed Offset
                    args = args.replace("sector_addr", f"(sector_addr - {mmu_offset})")
                
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
        # WINNING THE BET: Omnipotent Hardware MMU Seizure
        # BootROM SPIRead deadlocks the ESP32 when the cache is enabled. Virtual Pointers are shifted by esptool.
        # Solution: At runtime, we seize direct control of the MMU table for Virtual Page 12 (0x400C0000).
        # We manually map the requested Physical Page to it, flush the cache via BootROM, and read safely!
        read_c = """    // ESP32 Fallback: Agnostic Physical Read via MMU Seizure
    uint32_t p_page = sector_addr / 0x10000;
    uint32_t p_offset = sector_addr % 0x10000;
    
    // ESP32 PRO_MMU_TABLE: Virtual 0x400C0000 is entry 12 (offset 48)
    *((volatile uint32_t*)(0x3FF10000 + (12 * 4))) = p_page;
    
    // BootROM Cache Disable/Enable (Flushes Stale Lines from previous pages or SPIWrites)
    ((void(*)(int))0x40004270)(0); // Cache_Read_Disable(0)
    ((void(*)(int))0x400041B0)(0); // Cache_Read_Enable(0)
    
    // Safe Virtual Read of the dynamically pinned Physical Silicon Atom
    if (out_val) *out_val = *((volatile uint32_t*)(0x400C0000 + p_offset));
"""
    elif read_seq:
        read_c = compile_sequence(read_seq)
    else:
        # 100% agnostic fallback for architectures without external MMUs (Cortex-M)
        # For ESP32, this strictly relies on the virtual MMU mapping and D-Cache evictions below.
        read_c = "    if (out_val) *out_val = *((volatile uint32_t*)sector_addr);\n"

    # Universal D-Cache Eviction for Sticky XiP Architectures
    # By reading 32KB of our own execution memory, we reliably force the hardware Cache Controller
    # to evict deeply cached external flash buffers without utilizing vendor-specific Cache flush registers.
    dcache_flush = ""
    try:
        v_base_str = spec.get("boot_vectors", {}).get("user_app_base", "0x0").replace("_", "")
        v_base = int(v_base_str, 16)
        if v_base > 0:
            flush_end = v_base + (32 * 1024)
            dcache_flush = f"""
    // Universal D-Cache Eviction Hook
    volatile uint32_t dummy = 0;
    for (uint32_t i = 0x{v_base:X}; i < 0x{flush_end:X}; i += 32) {{ dummy ^= *((volatile uint32_t*)i); }}
    (void)dummy;
"""
    except Exception:
        pass

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
{erase_c}{dcache_flush}
    return true;
}}

bool chip_flash_write32(uint32_t sector_addr, uint32_t data_word) {{
    // Unlock Sequence
{unlock_c}
    // Write Sequence
{write_c}{dcache_flush}
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
