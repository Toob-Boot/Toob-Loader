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
#include "boot_fih.h"
#include "boot_hal.h"
#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"

#ifndef TOOB_MAX_OTP_SLOTS
#ifdef TOOB_OTP_MAX_SLOTS
#define TOOB_MAX_OTP_SLOTS TOOB_OTP_MAX_SLOTS
#else
#define TOOB_MAX_OTP_SLOTS 256U
#endif
#endif

_Static_assert((TOOB_MAX_OTP_SLOTS > 0U) && (TOOB_MAX_OTP_SLOTS <= 256U),
               "TOOB_MAX_OTP_SLOTS must be in [1, 256]");

uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform) {
  if (!platform || !platform->keystore || !platform->keystore->read_pubkey) {
    while (1) {
      BOOT_GLITCH_DELAY();
    }
  }

  uint8_t key_1[32] __attribute__((aligned(8)));
  uint8_t key_2[32] __attribute__((aligned(8)));
  uint8_t active_idx = 0U;
  bool blank_seen = false;

  for (uint32_t idx = 0U; idx < (uint32_t)TOOB_MAX_OTP_SLOTS; idx++) {
    if ((idx & 0x1FU) == 0U && platform->wdt != NULL && platform->wdt->kick != NULL) {
      platform->wdt->kick();
    }

    boot_secure_zeroize(key_1, sizeof(key_1));
    boot_secure_zeroize(key_2, sizeof(key_2));

    boot_status_t stat_1 = platform->keystore->read_pubkey(key_1, sizeof(key_1), (uint8_t)idx);
    BOOT_GLITCH_DELAY();
    boot_status_t stat_2 = platform->keystore->read_pubkey(key_2, sizeof(key_2), (uint8_t)idx);

    if (stat_1 != stat_2) {
      boot_secure_zeroize(key_1, sizeof(key_1));
      boot_secure_zeroize(key_2, sizeof(key_2));
      while (1) {
        BOOT_GLITCH_DELAY();
      }
    }

    if (blank_seen) {
      /* Stage0Chain.v all_blank_tail: reject any populated or faulted slot after first blank. */
      if (stat_1 != BOOT_ERR_NOT_FOUND) {
        boot_secure_zeroize(key_1, sizeof(key_1));
        boot_secure_zeroize(key_2, sizeof(key_2));
        while (1) {
          BOOT_GLITCH_DELAY();
        }
      }
      continue;
    }

    if (stat_1 == BOOT_OK) {
      if (verify_not_all_zeros_glitch_safe(key_1, sizeof(key_1)) != BOOT_OK ||
          verify_not_all_zeros_glitch_safe(key_2, sizeof(key_2)) != BOOT_OK ||
          constant_time_memcmp_glitch_safe(key_1, key_2, sizeof(key_1)) != BOOT_OK) {
        boot_secure_zeroize(key_1, sizeof(key_1));
        boot_secure_zeroize(key_2, sizeof(key_2));
        while (1) {
          BOOT_GLITCH_DELAY();
        }
      }
      active_idx = (uint8_t)idx;
      continue;
    }

    if (stat_1 == BOOT_ERR_NOT_FOUND) {
      blank_seen = true;
      continue;
    }

    /* Fail-Closed on hardware/bus faults to prevent EMFI key-downgrade */
    boot_secure_zeroize(key_1, sizeof(key_1));
    boot_secure_zeroize(key_2, sizeof(key_2));
    while (1) {
      BOOT_GLITCH_DELAY();
    }
  }

  boot_secure_zeroize(key_1, sizeof(key_1));
  boot_secure_zeroize(key_2, sizeof(key_2));
  return active_idx;
}
