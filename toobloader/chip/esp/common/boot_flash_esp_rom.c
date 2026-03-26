/**
 * @file boot_flash_esp_rom.c
 * @brief Common Espressif ROM Flash Bindings
 *
 * This file contains the identically shared flash routines used across the
 * Espressif chip family (e.g., ESP32, ESP32-C6). By centralizing this,
 * we reduce boilerplate in the individual `boot_hal_<chip>.c` files.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../../include/boot_config.h"
#include <stddef.h>
#include <stdint.h>


#include "../../../include/common/kb_tags.h"
#include "../../../include/common/rp_assert.h"

/* ============================================================================
 * ESP-ROM SPI Flash Bindings (Zero Dependency)
 * ========================================================================== */

extern int32_t esp_rom_spiflash_read(uint32_t src_addr, void *data,
                                     uint32_t len);
extern int32_t esp_rom_spiflash_write(uint32_t dest_addr, const void *data,
                                      uint32_t len);
extern int32_t esp_rom_spiflash_erase_sector(uint32_t sector_number);

/* ============================================================================
 * Common Espressif Flash Operations
 * ========================================================================== */

/**
 * @osv
 * component: Bootloader.HAL
 */
KB_CORE()
int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
  RP_ASSERT(buf != NULL, "buf is NULL");

  /* P10 R5/OSV: Defensive assertion for 4-byte memory alignment requested by
   * ESP ROM */
  if ((addr % 4) != 0 || (len % 4) != 0 || ((uintptr_t)buf % 4) != 0) {
    return -1;
  }

  return esp_rom_spiflash_read(addr, buf, len);
}

/**
 * @osv
 * component: Bootloader.HAL
 */
KB_CORE()
int32_t boot_flash_erase(uint32_t addr, uint32_t len) {
  /* Provide sector erase interface (assume 4KB sectors) */
  (void)len;
  return esp_rom_spiflash_erase_sector(addr / 4096);
}

/**
 * @osv
 * component: Bootloader.HAL
 */
KB_CORE()
int32_t boot_flash_write(uint32_t addr, const uint8_t *data, uint32_t len) {
  RP_ASSERT(data != NULL, "data is NULL");

  if ((addr % 4) != 0 || (len % 4) != 0 || ((uintptr_t)data % 4) != 0) {
    return -1;
  }

  return esp_rom_spiflash_write(addr, data, len);
}
