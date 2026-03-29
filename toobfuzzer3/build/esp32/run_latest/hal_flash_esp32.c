/* Auto-Generated Bare-Metal Flash HAL for esp32 (Physical Architecture) */
#include <stdint.h>
#include <stdbool.h>

extern void fz_log(const char *msg);

void hal_print_status(void) {
    fz_log("[HAL] Active Backend: True Physical Hardware MMU Driver\n");
}

bool chip_flash_erase(uint32_t sector_addr) {
    // Unlock Sequence
    // Unlock SPI Flash via BootROM
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Erase Sequence
    // Kill Hardware DPORT Prefetch Pipeline to prevent SPI Arbiter Collisions
    #define ESP32_UART0_STATUS_REG 0x3FF4001C
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[E1]\n");
        #define DPORT_PRO_CACHE_CTRL_REG 0x3FF00040
        *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) &= ~(1<<3); // DPORT_HW_CACHE_DISABLE
    // Hardware BootROM Erase
    // ROM ABI: SPIEraseSector @ 0x40062CCC
    ((void(*)())0x40062CCC)(sector_addr / 4096);
    // Restore Hardware DPORT Pipeline
    *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) |= (1<<3); // DPORT_HW_CACHE_ENABLE
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[E2]\n");
    
    return true;
}

bool chip_flash_write32(uint32_t sector_addr, uint32_t data_word) {
    // Unlock Sequence
    // Unlock SPI Flash via BootROM
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Write Sequence
    // Kill Hardware DPORT Prefetch Pipeline
    #define ESP32_UART0_STATUS_REG 0x3FF4001C
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[W1]\n");
        #define DPORT_PRO_CACHE_CTRL_REG 0x3FF00040
        *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) &= ~(1<<3);
    // Hardware BootROM Write
    // ROM ABI: SPIWriteWord @ 0x40062D50
    ((void(*)())0x40062D50)(sector_addr, &data_word, 4);
    // Restore Hardware DPORT Pipeline
    *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) |= (1<<3);
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[W2]\n");

    return true;
}

bool chip_flash_read32(uint32_t sector_addr, uint32_t *out_val) {
    // Read Sequence
    // MMU Seizure Physical Silicon Atom By-pass
    #define ESP32_UART0_STATUS_REG 0x3FF4001C
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[R1]\n");
        uint32_t p_page = sector_addr / 0x10000;
        uint32_t p_offset = sector_addr % 0x10000;
        
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[R2]\n");
        /* PRO_MMU_TABLE Virtual 0x400D0000 mapped dynamically */
        *((volatile uint32_t*)(0x3FF10000 + (13 * 4))) = p_page;
        
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[R3]\n");
        
        if (out_val) *out_val = *((volatile uint32_t*)(0x400D0000 + p_offset));
        
        while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
        fz_log("[R4]\n");
    return true;
}
