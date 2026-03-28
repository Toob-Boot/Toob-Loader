/* Auto-Generated Bare-Metal Flash HAL for esp32 */
#include <stdint.h>
#include <stdbool.h>

extern void fz_log(const char *msg); // Ensure logger availability

void hal_print_status(void) {
    fz_log("[HAL] Active Backend: Real Hardware SPI Driver (AI Generated)\n");
}

bool chip_flash_erase(uint32_t sector_addr) {
    // Unlock Sequence
    // Unlock SPI Flash via BootROM
    // ROM ABI: SPIUnlock @ 0x40062738
    ((void(*)())0x40062738)();
    // Erase Sequence
    // Erase Flash Sector via BootROM
    // ROM ABI: SPIEraseSector @ 0x40062CCC
    ((void(*)())0x40062CCC)((sector_addr - 0x40000000) / 4096);
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
    ((void(*)())0x40062D50)((sector_addr - 0x40000000), &data_word, 4);
    return true;
}
