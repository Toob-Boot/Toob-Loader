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

boot_status_t stage0_verify_signature(const boot_platform_t *platform, const uint8_t *sig,
                                      const uint8_t *pubkey, const uint8_t *msg_digest) {
  volatile uint32_t shield_1 = (uint32_t)BOOT_ERR_VERIFY;
  volatile uint32_t shield_2 = (uint32_t)BOOT_ERR_CRYPTO;

#if defined(TOOB_STAGE0_VERIFY_MODE_HASH_ONLY)
#if !defined(TOOB_ALLOW_DEV_BYPASS) || !TOOB_ALLOW_DEV_BYPASS || defined(TOOB_PROFILE_PRODUCTION)
#error "HASH_ONLY mode requires non-production TOOB_ALLOW_DEV_BYPASS!"
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
    return BOOT_ERR_INVALID_ARG;
  }

  boot_status_t raw_st =
      platform->crypto->verify_signature(msg_digest, BOOT_MERKLE_HASH_LEN, sig, pubkey);
#if defined(TOOB_DOUBLE_VERIFY) && TOOB_DOUBLE_VERIFY
  BOOT_GLITCH_DELAY();
  boot_status_t raw_st_2 =
      platform->crypto->verify_signature(msg_digest, BOOT_MERKLE_HASH_LEN, sig, pubkey);
  BOOT_SECURE_REQUIRE(raw_st == BOOT_OK && raw_st_2 == BOOT_OK, { return BOOT_ERR_VERIFY; });
#else
  BOOT_SECURE_REQUIRE(raw_st == BOOT_OK, { return BOOT_ERR_VERIFY; });
#endif
  if (raw_st == BOOT_OK) {
    shield_1 = (uint32_t)raw_st;
  }
  BOOT_GLITCH_DELAY();
  if (shield_1 == (uint32_t)BOOT_OK && raw_st == BOOT_OK) {
    shield_2 = (uint32_t)raw_st;
  }
#endif

  BOOT_SECURE_REQUIRE(shield_1 == (uint32_t)BOOT_OK && shield_2 == (uint32_t)BOOT_OK &&
                          shield_1 == shield_2 &&
                          boot_secure_confirm((boot_status_t)shield_2) == BOOT_OK,
                      { return BOOT_ERR_VERIFY; });
  return BOOT_OK;
}
