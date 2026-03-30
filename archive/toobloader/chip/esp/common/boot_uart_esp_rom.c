/**
 * @file boot_uart_esp_rom.c
 * @brief Common Espressif ROM UART Bindings
 *
 * This file contains the identically shared UART ROM wrappers used across the
 * Espressif chip family (e.g., ESP32, ESP32-C6). By centralizing this in the
 * Vendor Common Layer (chip/esp/common), chip-specific HALs are free of UART
 * boilerplate.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../../include/boot_config.h"
#include <stdint.h>

#include "../../../include/common/kb_tags.h"

/* ============================================================================
 * ESP-ROM UART Bindings (Zero Dependency)
 * ========================================================================== */

extern uint8_t uart_rx_one_char(uint8_t *c);
extern void uart_tx_one_char(uint8_t c);

/**
 * @osv
 * component: Bootloader.HAL
 */
KB_CORE()
void boot_hal_uart_tx_char(char c) { uart_tx_one_char((uint8_t)c); }

/**
 * @osv
 * component: Bootloader.HAL
 */
KB_CORE()
int32_t boot_uart_rx_char(uint8_t *c) { return (int32_t)uart_rx_one_char(c); }
