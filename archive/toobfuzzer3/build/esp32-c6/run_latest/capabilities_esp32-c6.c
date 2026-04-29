/* Auto-Generated Bare-Metal Capabilities for esp32-c6 (Physical Architecture) */
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
    { 0x4087C000, 0x4000 }, // bootrom_reserved_ram
};
const uint32_t chip_protected_count = sizeof(chip_protected_regions) / sizeof(chip_protected_regions[0]);

/* Dynamic Application RAM Array */
const fz_ram_region_t chip_testable_ram_regions[] = {
    { 0x40800000, 0x7C000 }, // iram
    { 0x50000000, 0x4000 }, // lp_ram
};
const uint32_t chip_testable_ram_count = sizeof(chip_testable_ram_regions) / sizeof(chip_testable_ram_regions[0]);

fz_caps_t chip_get_capabilities(void) {
    fz_caps_t caps = {0};
    
    // AI-Discovered Boot Vectors & Memory Mappings
    caps.user_flash_base = 0x0; // Natively aligns Fuzzer API 1:1 with True Physical Silicon
    caps.rom_base = 0x40000000;
    
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
