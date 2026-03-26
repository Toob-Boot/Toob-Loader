/* Auto-Generated Bare-Metal Capabilities for esp32-c6 */
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
    { 0x40000000, 0x80000 }, // 512KB firmware self-preservation

};
const uint32_t chip_protected_count = sizeof(chip_protected_regions) / sizeof(chip_protected_regions[0]);

fz_caps_t chip_get_capabilities(void) {
    fz_caps_t caps = {0};
    
    // AI-Discovered Boot Vectors & Memory Mappings
    caps.user_flash_base = 0x40000000; // Natively aligns Fuzzer API with Physical Deployment Bounds
    caps.rom_base = 0x40000000;
    
    caps.iram_base = 0x40800000;
    caps.iram_length = 0x80000;
    caps.dram_base = 0x0;
    caps.dram_length = 0x10000;
    
    // Physical Readout Protection (STM32, etc.)
    caps.rdp_level = 0;
    // [AI] Mask not provided for RDP
    
    // Flash Encryption (ESP32, nRF, etc.)
    // [AI] Mask not provided for Flash Encryption
    
    // JTAG / Debug Interface Locks
    caps.debug_access = true; // Default open
    // [AI] Mask not provided for JTAG Disable

    
    // Baseline Capability Inference
    caps.raw_flash_rw = (caps.rdp_level == 0 && !caps.flash_encrypted);
    caps.bootrom_access = (caps.rdp_level == 0);
    
    return caps;
}
