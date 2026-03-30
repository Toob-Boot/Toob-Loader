/**
 * @file dev_policy.c
 * @brief Bootloader Link-Time Developer Mock (Signature Bypass)
 *
 * This file replaces `boot_verify_signature` at LINK TIME when
 * `TOOBLOADER_DEV_MODE=ON` is defined in CMake.
 *
 * It completely bypasses NASA P10 kernel signature enforcement,
 * allowing developers to iteratively flash test payloads without
 * continuously managing Ed25519 signing keys.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include <stddef.h>
#include <stdint.h>

#include "../include/common/kb_tags.h"

extern void boot_uart_puts(const char *msg);

/**
 * @osv
 * component: Bootloader.Security.Mock
 */
KB_FEATURE("Developer Mode Signature Bypass")
int32_t __wrap_boot_verify_signature(const uint8_t *msg, size_t msg_len,
                                     const uint8_t *sig) {
  (void)msg;
  (void)msg_len;
  (void)sig;

  boot_uart_puts("\r\n===================================================\r\n");
  boot_uart_puts("   [WARNING] DEV-MODE: Signature Check BYPASSED!   \r\n");
  boot_uart_puts("===================================================\r\n");

  /* Return 0 to simulate mathematical success */
  return 0;
}
