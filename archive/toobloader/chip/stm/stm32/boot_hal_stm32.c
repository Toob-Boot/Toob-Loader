/**
 * @file boot_hal_stm32.c
 * @brief Bootloader HAL Shim — STM32 Specific
 *
 * Provides the absolute minimum hardware abstraction for the
 * bootloader: flash read, NVS read/write, and UART console.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../include/boot_config.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ============================================================================
 * STM32 Flash Operations
 * ========================================================================== */

/* STM32: Flash memory-mapped starting at 0x08000000 */
#define STM32_FLASH_BASE 0x08000000u

/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_CORE()
int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
  if (!buf)
    return -1;
  const uint8_t *src = (const uint8_t *)(BOOT_FLASH_MAP_BASE + addr);
  memcpy(buf, src, len);
  return 0;
}

/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_CORE()
static int32_t boot_flash_erase_sector(uint32_t addr) {
  /* STM32 HAL flash erase (sector-based) */
  extern int32_t stm32_flash_erase(uint32_t addr, uint32_t size);
  return stm32_flash_erase(addr, 4096);
}

/**
 * @osv
 * component: Bootloader.HAL
 * tag_status: auto
 */
KB_CORE()
static int32_t boot_flash_write_raw(uint32_t addr, const uint8_t *data,
                                    uint32_t len) {
  extern int32_t stm32_flash_write(uint32_t addr, const uint8_t *data,
                                   uint32_t len);
  return stm32_flash_write(addr, data, len);
}

/* ============================================================================
 * STM32 UART Console
 * ========================================================================== */

void boot_uart_puts(const char *msg) {
  extern void stm32_uart_send_string(const char *s);
  if (msg)
    stm32_uart_send_string(msg);
}

/* ============================================================================
 * HAL Init
 * ========================================================================== */

KB_FEATURE("boot_hal_stm32")
void boot_hal_init(void) {
  extern void SystemInit(void);
  extern void stm32_uart_init(void);
  SystemInit();
  stm32_uart_init();
}

KB_FEATURE("Hardware Recovery Button")
bool boot_hal_is_recovery_button_pressed(void) {
  /* TODO: Implement physical GPIO read for recovery button */
  return false;
}
