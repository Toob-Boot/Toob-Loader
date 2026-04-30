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

#include "../../crypto/monocypher/monocypher-ed25519.h"
#include "boot_types.h"
#include "stage0_crypto.h"

int stage0_verify_signature(const boot_platform_t *platform, const uint8_t *sig, const uint8_t *pubkey,
                            const uint8_t *msg_digest) {
  /* WICHTIG: Pre-Hashed (ph) Funktion nutzen, da wir den Digest übergeben! */
  int status = -1;

#if defined(TOOB_STAGE0_VERIFY_MODE_HW)
  if (platform && platform->crypto && platform->crypto->verify_ed25519) {
    status = (platform->crypto->verify_ed25519(msg_digest, 32, sig, pubkey) == BOOT_OK) ? 0 : -1;
  }
#elif defined(TOOB_STAGE0_VERIFY_MODE_HASH_ONLY)
  (void)sig;
  (void)pubkey;
  (void)msg_digest;
  (void)platform;
  status = 0; /* Bypass Signature */
#else
  (void)platform;
  /* Software Ed25519 */
  status = crypto_ed25519_ph_check(sig, pubkey, msg_digest);
#endif

  /* P10 Glitch-Defense Double-Check Pattern */
  volatile uint32_t s1 = 0, s2 = 0;
  if (status == 0)
    s1 = BOOT_OK;

  BOOT_GLITCH_DELAY();

  if (s1 == BOOT_OK && status == 0)
    s2 = BOOT_OK;

  if (s1 == BOOT_OK && s2 == BOOT_OK && s1 == s2) {
    return 0; /* OK */
  }
  return -1; /* FAIL */
}