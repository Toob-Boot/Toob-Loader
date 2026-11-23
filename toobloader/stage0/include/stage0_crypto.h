#ifndef STAGE0_CRYPTO_H
#define STAGE0_CRYPTO_H

#include "boot_hal.h"
#include "libtoob_types.h"
#include <stddef.h>
#include <stdint.h>

extern TOOB_NOINIT_VAR(toob_handoff_state) toob_handoff_t toob_handoff_state;
void _stage0_start(void); /* NOLINT(bugprone-reserved-identifier,cert-dcl37-c) */

boot_status_t stage0_hash_compute(const boot_platform_t *platform, uint32_t addr, size_t len,
                                  uint8_t *digest);
boot_status_t stage0_verify_signature(const boot_platform_t *platform, const uint8_t *sig,
                                      const uint8_t *pubkey, const uint8_t *msg_digest);

uint32_t stage0_read_wal_boot_meta(const boot_platform_t *platform, uint32_t *out_svn);
uint32_t stage0_evaluate_tentative(const boot_platform_t *platform, uint32_t current_slot);
uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform);

#endif /* STAGE0_CRYPTO_H */
