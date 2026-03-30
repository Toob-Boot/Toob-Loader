/**
 * @file boot_hal_esp32.c
 * @brief Bootloader HAL Shim — ESP32 Specific
 *
 * Provides the absolute minimum hardware abstraction for the
 * bootloader: flash read, NVS read/write, and UART console.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../../include/boot_config.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../../include/common/kb_tags.h"
#include "../../../include/common/rp_assert.h"

/* (UART handling is now abstracted to chip/esp/common) */

KB_CORE()
uint8_t boot_hal_gpio_get_level(uint32_t pin) {
  uint32_t gpio_in = 0;
  if (pin < 32) {
    gpio_in = *((volatile uint32_t *)0x3FF4403C); /* ESP32 GPIO_IN_REG */
  } else {
    gpio_in = *((volatile uint32_t *)0x3FF44040); /* ESP32 GPIO_IN1_REG */
  }
  return (gpio_in & (1U << (pin % 32))) ? 1 : 0;
}

/* ============================================================================
 * Internal Hardware Reliability (Watchdog)
 * ========================================================================== */

#define TIMG0_BASE 0x3FF5F000U
#define WDT_FEED (TIMG0_BASE + 0x60)
#define WDT_WPROTECT (TIMG0_BASE + 0x64)

#define WDT_UNLOCK_KEY 0x50D83AA1U
#define REG32(addr) (*(volatile uint32_t *)(addr))

/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_CORE()
void boot_hal_wdt_feed(void) {
  /* Atomically Unlock, Feed, and Lock the TIMG0 Watchdog */
  REG32(WDT_WPROTECT) = WDT_UNLOCK_KEY;
  REG32(WDT_FEED) = 1;
  REG32(WDT_WPROTECT) = 0;
}

/* ============================================================================
 * HAL Init
 * ========================================================================== */

/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_FEATURE("boot_hal_esp")
void boot_hal_init(void) {
  /* ESP32: Clock, WDT, and UART0 already initialized by Xtensa ROM */
}

/* ============================================================================
 * Hardware Secrets (eFuse & Fixed Flash)
 * ========================================================================== */

#define EFUSE_BLK2_RDATA0_REG 0x3FF5A05Cu

/**
 * @osv
 * component: Bootloader.HAL
 */
extern void boot_hal_read_regs_to_bytes(uint32_t base_addr, uint8_t *buf,
                                        uint32_t num_words);

KB_CORE()
void boot_hal_get_root_key(uint8_t out_key[32]) {
  /* ESP32: BLK2 stores the ROOT_KEY. 8 32-bit registers. */
  boot_hal_read_regs_to_bytes(EFUSE_BLK2_RDATA0_REG, out_key, 8);
}
