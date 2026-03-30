/**
 * @file boot_hal_esp32c6.c
 * @brief Bootloader HAL Shim — ESP32-C6 (RISC-V) Specific
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../../include/boot_config.h"
#include <stddef.h>
#include <stdint.h>

#include "../../../include/common/kb_tags.h"
#include "../../../include/common/rp_assert.h"

/* (UART handling is now abstracted to chip/esp/common) */

KB_CORE()
uint8_t boot_hal_gpio_get_level(uint32_t pin) {
  /* ESP32-C6 GPIO_IN_REG is at 0x6009103C */
  uint32_t gpio_in = *((volatile uint32_t *)0x6009103C);
  return (gpio_in & (1U << pin)) ? 1 : 0;
}

/* ============================================================================
 * Hardware Watchdog (TIMG0)
 * ========================================================================== */

#define TIMG0_BASE 0x60008000U
#define WDT_FEED (TIMG0_BASE + 0x60)
#define WDT_WPROTECT (TIMG0_BASE + 0x64)

#define WDT_UNLOCK_KEY 0x50D83AA1U
#define REG32(addr) (*(volatile uint32_t *)(addr))

KB_CORE()
void boot_hal_wdt_feed(void) {
  REG32(WDT_WPROTECT) = WDT_UNLOCK_KEY;
  REG32(WDT_FEED) = 1;
  REG32(WDT_WPROTECT) = 0;
}

/* ============================================================================
 * HAL Init
 * ========================================================================== */

KB_FEATURE("boot_hal_esp_c6")
void boot_hal_init(void) {
  /* Minimal Init: RISC-V Trap vectors and Clocks are pre-configured by ROM */
}

/* ============================================================================
 * Hardware Secrets (eFuse & Fixed Flash)
 * ========================================================================== */

#define EFUSE_BLOCK_KEY0_DATA0_REG 0x60007050u

/**
 * @osv
 * component: Bootloader.HAL
 */
extern void boot_hal_read_regs_to_bytes(uint32_t base_addr, uint8_t *buf,
                                        uint32_t num_words);

KB_CORE()
void boot_hal_get_root_key(uint8_t out_key[32]) {
  /* ESP32-C6: BLOCK_KEY0 stores the ROOT_KEY. 8 32-bit registers. */
  boot_hal_read_regs_to_bytes(EFUSE_BLOCK_KEY0_DATA0_REG, out_key, 8);
}
