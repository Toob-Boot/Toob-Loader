/* Auto-Generated Bare-Metal Capabilities for esp32 (Physical Architecture) */
#include "fz_types.h"
#include <stdint.h>
#include <stdbool.h>

/* Safe direct memory reader for bare-metal no-HAL environments */
static inline uint32_t raw_read32(uint32_t addr) {
    if (addr == 0x0) return 0;
    return *((volatile uint32_t*)addr);
}

/* Dynamic Memory Shielding Arrays */
const fz_protect_region_t chip_protected_regions[] = {
    { 0x0, 0x40000 }, // 256KB True Physical Bare-Metal Shield
    { 0x40070000, 0x10000 }, // hardware_reserved_cache
    { 0x3FFAE000, 0x2000 }, // bootrom_reserved_dram
};
const uint32_t chip_protected_count = sizeof(chip_protected_regions) / sizeof(chip_protected_regions[0]);

fz_caps_t chip_get_capabilities(void) {
    fz_caps_t caps = {0};
    
    // AI-Discovered Boot Vectors & Memory Mappings
    caps.user_flash_base = 0x0; // Natively aligns Fuzzer API 1:1 with True Physical Silicon
    caps.rom_base = 0x40000000;
    
    caps.iram_base = 0x40080000;
    caps.iram_length = 0x20000;
    caps.dram_base = 0x3FFB0000;
    caps.dram_length = 0x30000;
    
    // Physical Readout Protection
    caps.rdp_level = 0;
    // [AI] Mask not provided for RDP
    
    // Flash Encryption
    // [AI] Mask not provided for Flash Encryption
    
    // JTAG / Debug Interface Locks
    caps.debug_access = true;
    // [AI] Mask not provided for JTAG Disable
    
    // Baseline Capability Inference
    caps.raw_flash_rw = (caps.rdp_level == 0 && !caps.flash_encrypted);
    caps.bootrom_access = (caps.rdp_level == 0);
    
    return caps;
}
