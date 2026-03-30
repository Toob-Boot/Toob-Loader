/**
 * @file boot_hal_esp32s2.c
 * @brief Bootloader HAL Shim — ESP32-S2 Specific
 *
 * Implements the Tier 3 Chip Specific bare-metal primitives for ESP32-S2.
 * Timeouts, global configurations, and UART abstractions are inherited
 * from the Tier 1 Global Common and Tier 2 Vendor Common layers.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../../include/boot_config.h"
#include "../../../include/common/kb_tags.h"
#include <stdint.h>

/* ============================================================================
 * Internal Hardware Reliability (Watchdog)
 * ========================================================================== */

KB_CORE()
void boot_hal_wdt_feed(void) {
  /* ESP32-S2 TIMG0 WDT */
  *((volatile uint32_t *)0x3f41f060) = 0x50D83AA1; /* WDT_WPROTECT_REG */
  *((volatile uint32_t *)0x3f41f054) = 1;          /* WDT_FEED_REG */
  *((volatile uint32_t *)0x3f41f060) = 0;          /* WDT_WPROTECT_REG */
}

/* ============================================================================
 * Hardware Specific Bootloader Identifiers
 * ========================================================================== */

KB_CORE()
void boot_hal_get_root_key(uint8_t out_key[32]) {
  /* ESP32-S2: BLOCK_KEY0 stores the ROOT_KEY. 8 32-bit registers. */
  extern void boot_hal_read_regs_to_bytes(uint32_t base_addr, uint8_t *buf,
                                          uint32_t num_words);
  boot_hal_read_regs_to_bytes(0x3f41A044, out_key,
                              8); /* EFUSE_BLOCK_KEY0_DATA0_REG */
}

/* ============================================================================
 * Hardware Specific Primitives
 * ========================================================================== */

KB_CORE()
uint8_t boot_hal_gpio_get_level(uint32_t pin) {
  uint32_t gpio_in = 0;
  if (pin < 32) {
    gpio_in = *((volatile uint32_t *)0x3f40403C); /* ESP32-S2 GPIO_IN_REG */
  } else {
    gpio_in = *((volatile uint32_t *)0x3f404040); /* ESP32-S2 GPIO_IN1_REG */
  }
  return (gpio_in & (1U << (pin % 32))) ? 1 : 0;
}

KB_FEATURE("boot_hal_esp32s2")
void boot_hal_init(void) {}
