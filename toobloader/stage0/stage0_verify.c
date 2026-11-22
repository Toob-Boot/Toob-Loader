/**
 * @file stage0_verify.c
 * @brief Glitch-Resistant Ed25519 Check
 *
 * Hardware-agnostic, glitch-resistant Ed25519 signature verification using
 * Double-Check patterns over the 32-byte SHA-256 Stage 1 bank digest.
 *
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_fih.h"
#include "boot_merkle.h"
#include "boot_types.h"
#include "stage0_crypto.h"

int stage0_verify_signature(const boot_platform_t *platform, const uint8_t *sig,
                            const uint8_t *pubkey, const uint8_t *msg_digest) {
  volatile uint32_t shield_1 = (uint32_t)BOOT_ERR_VERIFY;
  volatile uint32_t shield_2 = (uint32_t)BOOT_ERR_CRYPTO;

#if defined(TOOB_STAGE0_VERIFY_MODE_HASH_ONLY)
#if !defined(TOOB_ALLOW_DEV_BYPASS)
#error "HASH_ONLY mode requires TOOB_ALLOW_DEV_BYPASS — do NOT ship in production!"
#endif
  (void)sig;
  (void)pubkey;
  (void)msg_digest;
  (void)platform;
  shield_1 = (uint32_t)BOOT_OK;
  BOOT_GLITCH_DELAY();
  shield_2 = (uint32_t)BOOT_OK;
#else
  if (!platform || !platform->crypto || !platform->crypto->verify_signature || !sig || !pubkey ||
      !msg_digest) {
    return -1;
  }

  boot_status_t raw_st =
      platform->crypto->verify_signature(msg_digest, BOOT_MERKLE_HASH_LEN, sig, pubkey);
  if (raw_st == BOOT_OK) {
    shield_1 = (uint32_t)raw_st;
  }
  BOOT_GLITCH_DELAY();
  if (shield_1 == (uint32_t)BOOT_OK && raw_st == BOOT_OK) {
    shield_2 = (uint32_t)raw_st;
  }
#endif

  if (shield_1 == (uint32_t)BOOT_OK && shield_2 == (uint32_t)BOOT_OK && shield_1 == shield_2 &&
      boot_secure_confirm((boot_status_t)shield_2) == BOOT_OK) {
    return 0;
  }
  return -1;
}
