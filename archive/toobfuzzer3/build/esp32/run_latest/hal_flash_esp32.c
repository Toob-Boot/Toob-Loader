/* Auto-Generated Bare-Metal Flash HAL for esp32 (Physical Architecture) */
#include <stdint.h>
#include <stdbool.h>

#include "logger.h"

void hal_print_status(void) {
    fz_log("[HAL] Active Backend: True Physical Hardware MMU Driver\n");
}

bool chip_flash_erase(uint32_t sector_addr) {
    // Unlock Sequence

    // Erase Sequence
    // Kill Hardware DPORT Prefetch Pipeline to prevent SPI Arbiter Collisions
    FZ_LOG_DEBUG("[E1]\n");
        #define DPORT_PRO_CACHE_CTRL_REG 0x3FF00040
        *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) &= ~(1<<3); // DPORT_HW_CACHE_DISABLE
    // Hardware BootROM Unlock
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Hardware BootROM Erase
    // ROM ABI: SPIEraseSector @ 0x40062CCC
    ((void(*)())0x40062CCC)(sector_addr / 4096);
    // Restore Hardware DPORT Pipeline
    *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) |= (1<<3); // DPORT_HW_CACHE_ENABLE
    
    return true;
}

bool chip_flash_write32(uint32_t sector_addr, uint32_t data_word) {
    // Unlock Sequence

    // Write Sequence
    // Kill Hardware DPORT Prefetch Pipeline
    FZ_LOG_DEBUG("[W1]\n");
        #define DPORT_PRO_CACHE_CTRL_REG 0x3FF00040
        *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) &= ~(1<<3);
    // Hardware BootROM Unlock
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Hardware BootROM Write
    // ROM ABI: SPIWriteWord @ 0x40062D50
    ((void(*)())0x40062D50)(sector_addr, &data_word, 4);
    // Restore Hardware DPORT Pipeline
    *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) |= (1<<3);

    return true;
}

bool chip_flash_read32(uint32_t sector_addr, uint32_t *out_val) {
    // Read Sequence
    // MMU Seizure with Instant DPORT Cache Flush
    uint32_t p_page = sector_addr / 0x10000;
        uint32_t p_offset = sector_addr % 0x10000;
        FZ_LOG_DEBUG("[R1]\n");
        #define DPORT_PRO_CACHE_CTRL_REG 0x3FF00040
        /* PRO_MMU_TABLE Virtual 0x400D0000 mapped dynamically */
        *((volatile uint32_t*)(0x3FF10000 + (13 * 4))) = p_page;
        /* Flush hardware cache explicitly to prevent 64KB boundary arbiter crashes */
        *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) &= ~(1<<3);
        *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) |= (1<<3);
        if (out_val) *out_val = *((volatile uint32_t*)(0x400D0000 + p_offset));
    return true;
}
