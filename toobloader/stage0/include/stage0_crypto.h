#ifndef STAGE0_CRYPTO_H
#define STAGE0_CRYPTO_H

#include "boot_hal.h"
#include <stddef.h>
#include <stdint.h>

void stage0_hash_compute(const boot_platform_t *platform, uint32_t addr,
                         size_t len, uint8_t *digest);
int stage0_verify_signature(const boot_platform_t *platform, const uint8_t *sig, const uint8_t *pubkey,
                            const uint8_t *msg_digest);

uint32_t stage0_get_active_slot(const boot_platform_t *platform);
uint32_t stage0_evaluate_tentative(const boot_platform_t *platform, uint32_t current_slot);
uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform);

#endif /* STAGE0_CRYPTO_H */