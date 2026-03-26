/* Auto-Generated Bare-Metal Capabilities for esp32 */
#include "fz_types.h"
#include <stdint.h>
#include <stdbool.h>

/* Safe direct memory reader for bare-metal no-HAL environments */
static inline uint32_t raw_read32(uint32_t addr) {
    if (addr == 0x0) return 0;
    return *((volatile uint32_t*)addr);
}

fz_caps_t chip_get_capabilities(void) {
    fz_caps_t caps = {0};
    
    // AI-Discovered Boot Vectors & Memory Mappings
    caps.user_flash_base = 0x400C2000;
    caps.rom_base = 0x40000000;
    
    caps.iram_base = 0x40070000;
    caps.iram_length = 0x30000;
    caps.dram_base = 0x3FFAE000;
    caps.dram_length = 0x32000;
    
    // Physical Readout Protection (STM32, etc.)
    caps.rdp_level = 0;
    if (0x0 != 0x0) {
        uint32_t val = raw_read32(0x0);
        // We assume RDP level is indicated directly by the masked value
        caps.rdp_level = (val & 0x0); 
    }
    
    // Flash Encryption (ESP32, nRF, etc.)
    if (0x0 != 0x0) {
        uint32_t val = raw_read32(0x0);
        if ((val & 0x0) != 0) {
            caps.flash_encrypted = true;
        }
    }
    
    // JTAG / Debug Interface Locks
    caps.debug_access = true; // Default open
    if (0x0 != 0x0) {
        uint32_t val = raw_read32(0x0);
        if ((val & 0x0) != 0) {
            caps.debug_access = !true; // If 'jtag_disabled' is true, debug_access is false
        }
    }
    
    // Baseline Capability Inference
    caps.raw_flash_rw = (caps.rdp_level == 0 && !caps.flash_encrypted);
    caps.bootrom_access = (caps.rdp_level == 0);
    
    return caps;
}
