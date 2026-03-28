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
    // Erase Flash Sector via BootROM
    // ROM ABI: SPIEraseSector @ 0x40062CCC
    ((void(*)())0x40062CCC)(sector_addr / 4096);
    return true;
}

bool chip_flash_write32(uint32_t sector_addr, uint32_t data_word) {
    // Unlock Sequence
    // Unlock SPI Flash via BootROM
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Write Sequence
    // Write Flash Word via BootROM
    // ROM ABI: SPIWrite @ 0x40062D50
    ((void(*)())0x40062D50)(sector_addr, &data_word, 4);
    return true;
}

bool chip_flash_read32(uint32_t sector_addr, uint32_t *out_val) {
    // Read Sequence
    // ESP32 Fallback: Agnostic Physical Read via MMU Seizure
    uint32_t p_page = sector_addr / 0x10000;
    uint32_t p_offset = sector_addr % 0x10000;
    
    // ESP32 PRO_MMU_TABLE: Virtual 0x400C0000 is entry 12 (offset 48)
    *((volatile uint32_t*)(0x3FF10000 + (12 * 4))) = p_page;
    
    // BootROM Cache Disable/Enable (Flushes Stale Lines from previous pages or SPIWrites)
    ((void(*)(int))0x40004270)(0); // Cache_Read_Disable(0)
    ((void(*)(int))0x400041B0)(0); // Cache_Read_Enable(0)
    
    // Safe Virtual Read of the dynamically pinned Physical Silicon Atom
    if (out_val) *out_val = *((volatile uint32_t*)(0x400C0000 + p_offset));

    return true;
}
