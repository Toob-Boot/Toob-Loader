/* Auto-Generated Bare-Metal Flash HAL for esp32-c6 (Physical Architecture) */
#include <stdint.h>
#include <stdbool.h>

#include "logger.h"

void hal_print_status(void) {
    fz_log("[HAL] Active Backend: True Physical Hardware MMU Driver\n");
}

void feed_hardware_watchdogs(void) {
    // Disable SWD with correct key 0x50D83AA1
    (*((volatile uint32_t*)(0x600B1C20))) = 0x50D83AA1;
        uint32_t swd_cfg = (*((volatile uint32_t*)(0x600B1C1C)));
        swd_cfg |= (1 << 30);
        (*((volatile uint32_t*)(0x600B1C1C))) = swd_cfg;
        fz_log(" [SWD DISABLED] \n");
}

bool chip_flash_erase(uint32_t sector_addr) {
    // Unlock Sequence
    // Hardware BootROM Unlock (from ESP-IDF ROM linker)
    // ROM ABI: esp_rom_spiflash_unlock @ 0x40000154
    ((void(*)())0x40000154)();
    // Erase Sequence
    // Hardware BootROM Erase (from ESP-IDF ROM linker)
    // ROM ABI: esp_rom_spiflash_erase_sector @ 0x40000144
    ((void(*)())0x40000144)(sector_addr / 4096);
    
    return true;
}

bool chip_flash_write32(uint32_t sector_addr, uint32_t data_word) {
    // Unlock Sequence
    // Hardware BootROM Unlock (from ESP-IDF ROM linker)
    // ROM ABI: esp_rom_spiflash_unlock @ 0x40000154
    ((void(*)())0x40000154)();
    // Write Sequence
    // Hardware BootROM Write (from ESP-IDF ROM linker)
    // ROM ABI: esp_rom_spiflash_write @ 0x4000014c
    ((void(*)())0x4000014c)(sector_addr, &data_word, 4);

    return true;
}

bool chip_flash_read32(uint32_t sector_addr, uint32_t *out_val) {
    // Read Sequence
    if (out_val) *out_val = *((volatile uint32_t*)sector_addr);

    return true;
}
