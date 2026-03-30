/**
 * @file signature_verify.c
 * @brief Bootloader Ed25519 Signature Verification
 *
 * Implements a standalone verification routine for the Stage 1 Bootloader
 * to validate the RPK (Toobloader Package) Kernel image against a hardcoded
 * public key before jumping to it.
 *
 * Uses the compact25519 library located in components/third_party.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../include/boot_config.h"
#include "../include/common/kb_tags.h"
#include "../include/common/rp_assert.h"


#include "../third_party/compact25519/src/compact_ed25519.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ============================================================================
 * Verification Logic
 * ========================================================================== */

/**
 * @osv
 * component: Bootloader.Security
 * tag_status: auto
 */
KB_CORE()
int32_t boot_verify_signature(const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig) {
  RP_ASSERT(msg != NULL, "boot_sig msg NULL");
  RP_ASSERT(sig != NULL, "boot_sig sig NULL");

  /* Kernel partition size limit (Defense in Depth against DoS) */
#ifndef BOOT_KERNEL_MAX_SIZE
#define BOOT_KERNEL_MAX_SIZE (128u * 1024u)
#endif

  if (!msg || !sig || msg_len == 0 || msg_len > BOOT_KERNEL_MAX_SIZE) {
    return -1;
  }

  uint8_t root_pub_key[32];
  (void)boot_hal_get_root_key(root_pub_key);

  /* Compact25519 verifies the signature against the message and pubkey */
  bool valid = compact_ed25519_verify(sig, root_pub_key, msg, msg_len);

  return valid ? 0 : -2;
}
