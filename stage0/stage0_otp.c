/**
 * @file stage0_otp.c
 * @brief OTP Key-Index Rotation
 *
 * Key-Index Rotation via OTP-eFuses to protect against Root-Key Bricks.
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_hal.h"
#include "stage0_crypto.h"

uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform) {
  if (!platform || !platform->crypto ||
      !platform->crypto->read_monotonic_counter) {
    return 0; /* Fallback auf Key 0 */
  }

  uint32_t epoch = 0;
  if (platform->crypto->read_monotonic_counter(&epoch) == BOOT_OK) {
    if (epoch > 255)
      return 255;
    return (uint8_t)epoch;
  }
  return 0;
}