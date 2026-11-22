/**
 * @file stage0_otp.c
 * @brief OTP Key-Index Discovery & Rotation
 *
 * Resolves the highest contiguous provisioned OTP Root Key slot via the
 * hardware-agnostic read_pubkey() contract (matching Stage 1 boot_verify.c),
 * keeping OTP key rotation strictly decoupled from the SVN monotonic counter.
 *
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_ct_utils.h"
#include "boot_hal.h"
#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"

uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform) {
  if (!platform || !platform->keystore || !platform->keystore->read_pubkey) {
    while (1) {
      BOOT_GLITCH_DELAY();
    }
  }

  uint8_t tmp_key[32] __attribute__((aligned(8)));
  uint8_t active_idx = 0U;

  for (uint32_t idx = 0U; idx <= 255U; idx++) {
    boot_secure_zeroize(tmp_key, sizeof(tmp_key));
    boot_status_t stat = platform->keystore->read_pubkey(tmp_key, sizeof(tmp_key), (uint8_t)idx);

    if (stat == BOOT_OK) {
      if (verify_not_all_zeros_glitch_safe(tmp_key, sizeof(tmp_key)) != BOOT_OK) {
        boot_secure_zeroize(tmp_key, sizeof(tmp_key));
        while (1) {
          BOOT_GLITCH_DELAY();
        }
      }
      active_idx = (uint8_t)idx;
      continue;
    }

    if (stat == BOOT_ERR_NOT_FOUND) {
      break;
    }

    /* Fail-Closed on hardware/bus faults to prevent EMFI key-downgrade */
    boot_secure_zeroize(tmp_key, sizeof(tmp_key));
    while (1) {
      BOOT_GLITCH_DELAY();
    }
  }

  boot_secure_zeroize(tmp_key, sizeof(tmp_key));
  return active_idx;
}
