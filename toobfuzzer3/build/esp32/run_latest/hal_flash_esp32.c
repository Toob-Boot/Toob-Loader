/* Auto-Generated Bare-Metal Flash HAL for esp32 (Physical Architecture) */
#include <stdint.h>
#include <stdbool.h>

extern void fz_log(const char *msg);
#define ESP32_UART0_STATUS_REG 0x3FF4001C
#define FZ_FLUSH() while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);

void hal_print_status(void) {
    fz_log("[HAL] Active Backend: True Physical Hardware MMU Driver\n");
}

bool chip_flash_erase(uint32_t sector_addr) {
    fz_log("[E1]\n"); FZ_FLUSH();
    // Hardware Arbiter Arbitration: Disconnect Cache (SPI0)
    ((void(*)(int))0x40004270)(0); // Cache_Read_Disable(0)
    
    // Unlock Sequence
    // Unlock SPI Flash via BootROM
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Erase Sequence
    // Erase Flash Sector via BootROM
    // ROM ABI: SPIEraseSector @ 0x40062CCC
    ((void(*)())0x40062CCC)(sector_addr / 4096);
    
    // Yield Arbiter back to Cache (SPI0)
    ((void(*)(int))0x400041B0)(0); // Cache_Read_Enable(0)
    fz_log("[E2]\n"); FZ_FLUSH();
    return true;
}

bool chip_flash_write32(uint32_t sector_addr, uint32_t data_word) {
    fz_log("[W1]\n"); FZ_FLUSH();
    // Hardware Arbiter Arbitration: Disconnect Cache (SPI0)
    ((void(*)(int))0x40004270)(0); // Cache_Read_Disable(0)

    // Unlock Sequence
    // Unlock SPI Flash via BootROM
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Write Sequence
    // Write Flash Word via BootROM
    // ROM ABI: SPIWrite @ 0x40062D50
    ((void(*)())0x40062D50)(sector_addr, &data_word, 4);

    // Yield Arbiter back to Cache (SPI0)
    ((void(*)(int))0x400041B0)(0); // Cache_Read_Enable(0)
    fz_log("[W2]\n"); FZ_FLUSH();
    return true;
}

bool chip_flash_read32(uint32_t sector_addr, uint32_t *out_val) {
    // Read Sequence
    // ESP32 Fallback: Ultra-Lightweight Physical Read via MMU Seizure (No ROM Calls)
    #define ESP32_UART0_STATUS_REG 0x3FF4001C
    #define FZ_FLUSH() while (((*((volatile uint32_t*)ESP32_UART0_STATUS_REG) >> 16) & 0xFF) > 0);
    
    fz_log("[R1]\n"); FZ_FLUSH();
    uint32_t p_page = sector_addr / 0x10000;
    uint32_t p_offset = sector_addr % 0x10000;
    
    fz_log("[R2]\n"); FZ_FLUSH();
    // ESP32 PRO_MMU_TABLE: Virtual 0x400D0000 (irom0) is entry 13 (offset 52)
    // Wir schreiben die Tabelle ON-THE-FLY um, WÄHREND der Cache noch läuft!
    // Dadurch umgehen wir die todbringende Cache_Read_Enable ROM-Funktion, die wegen gelöschtem BSS abstürzt.
    *((volatile uint32_t*)(0x3FF10000 + (13 * 4))) = p_page;
    
    fz_log("[R3]\n"); FZ_FLUSH();
    
    // Safe Virtual Read of the dynamically pinned Physical Silicon Atom in IROM0
    if (out_val) *out_val = *((volatile uint32_t*)(0x400D0000 + p_offset));
    
    fz_log("[R4]\n"); FZ_FLUSH();
    return true;

    return true;
}
