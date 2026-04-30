#ifndef STAGE0_CRYPTO_H
#define STAGE0_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void stage0_hash_compute(const uint8_t *data, size_t len, uint8_t *digest);
int stage0_verify_signature(const uint8_t *sig, const uint8_t *pubkey, const uint8_t *msg, size_t len);

#endif /* STAGE0_CRYPTO_H */
