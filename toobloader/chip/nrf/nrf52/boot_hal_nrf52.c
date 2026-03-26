/**
 * @file boot_hal_nrf52.c
 * @brief Bootloader HAL Shim — nRF52 Specific
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../../include/boot_config.h"
#include <stdint.h>

/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_CORE()
int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) { return 0; }
/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_CORE()
static int32_t boot_flash_erase_sector(uint32_t addr) { return 0; }
/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_CORE()
static int32_t boot_flash_write_raw(uint32_t addr, const uint8_t *data,
                                    uint32_t len) {
  return 0;
}

void boot_uart_puts(const char *msg) {}

KB_FEATURE("boot_hal_nrf52")
void boot_hal_init(void) {}

KB_FEATURE("Hardware Recovery Button")
bool boot_hal_is_recovery_button_pressed(void) {
  /* TODO: Implement physical GPIO read for recovery button */
  return false;
}
