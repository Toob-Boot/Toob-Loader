/**
 * @file stage0_verify.c
 * @brief Glitch-Resistant Ed25519 Check
 *
 * Hardware-agnostic, glitch-resistant Ed25519 signature verification using
 * Double-Check patterns.
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_types.h"
#include "stage0_crypto.h"
#include "boot_fih.h"

int stage0_verify_signature(const boot_platform_t *platform, const uint8_t *sig, const uint8_t *pubkey,
                            const uint8_t *msg_digest) {
  int status = -1;

#if defined(TOOB_STAGE0_VERIFY_MODE_HASH_ONLY)
  #if !defined(TOOB_ALLOW_DEV_BYPASS)
    #error "HASH_ONLY mode requires TOOB_ALLOW_DEV_BYPASS — do NOT ship in production!"
  #endif
  (void)sig;
  (void)pubkey;
  (void)msg_digest;
  (void)platform;
  status = 0; /* Bypass Signature */
#else
  if (platform && platform->crypto && platform->crypto->verify_signature_ph) {
    status = (platform->crypto->verify_signature_ph(msg_digest, sig, pubkey) == BOOT_OK) ? 0 : -1;
  }
#endif

  /* P10 Glitch-Defense Double-Check Pattern */
  boot_status_t stat_to_confirm = (status == 0) ? BOOT_OK : BOOT_ERR_VERIFY;
  if (boot_secure_confirm(stat_to_confirm) == BOOT_OK) {
    return 0; /* OK */
  }
  return -1; /* FAIL */
}