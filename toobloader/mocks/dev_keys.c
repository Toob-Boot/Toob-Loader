/**
 * @file dev_keys.c
 * @brief Bootloader Link-Time Mocks (Development Keys)
 *
 * Implements GNU LD `--wrap` targets for hardware eFuse abstraction.
 * When `BOOTLOADER_MOCK_EFUSE=ON` is defined, the linker reroutes calls to
 * `boot_hal_get_root_key` and `boot_hal_get_dslc` to these functions, allowing
 * software verification of cryptographic flows without physical eFuses.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include <stdint.h>
#include <string.h>

#include "../include/common/kb_tags.h"

/**
 * @osv
 * component: Bootloader.Security.Mock
 * tag_status: auto
 */
KB_FEATURE("Link-Time eFuse Mocking")
void __wrap_boot_hal_get_root_key(uint8_t out_key[32]) {
  static const uint8_t dev_pub_key[32] = {
      0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56,
      0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
      0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
  (void)memcpy(out_key, dev_pub_key, 32);
}

/**
 * @osv
 * component: Bootloader.Security.Mock
 * tag_status: auto
 */
KB_FEATURE("Link-Time eFuse Mocking")
void __wrap_boot_hal_get_dslc(uint8_t out_dslc[32]) {
  static const uint8_t dev_dslc[32] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
      0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  (void)memcpy(out_dslc, dev_dslc, 32);
}

/**
 * @osv
 * component: Bootloader.Security.Mock
 * tag_status: auto
 */
KB_FEATURE("Link-Time eFuse Mocking")
void __wrap_boot_hal_get_firmware_key(uint8_t out_key[32]) {
  static const uint8_t dev_fek[32] = {
      0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
      0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
      0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
  (void)memcpy(out_key, dev_fek, 32);
}
