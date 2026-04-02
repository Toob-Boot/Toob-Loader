/**
 * ==============================================================================
 * Toob-Boot Crypto Wrapper: Monocypher Backend Header
 * ==============================================================================
 */

#ifndef CRYPTO_MONOCYPHER_H
#define CRYPTO_MONOCYPHER_H

#include "boot_hal.h"
#include <stdint.h>
#include <stddef.h>

boot_status_t crypto_monocypher_init(void);
void crypto_monocypher_deinit(void);

boot_status_t crypto_monocypher_hash_init(void *ctx, size_t ctx_size);
boot_status_t crypto_monocypher_hash_update(void *ctx, const void *data, size_t len);
boot_status_t crypto_monocypher_hash_finish(void *ctx, uint8_t *digest, size_t *digest_len);

boot_status_t crypto_monocypher_verify(const uint8_t *msg, size_t len, const uint8_t *sig, const uint8_t *pubkey);

#endif /* CRYPTO_MONOCYPHER_H */
