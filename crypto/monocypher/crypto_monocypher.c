/**
 * ==============================================================================
 * Toob-Boot Crypto Wrapper: Monocypher Backend Implementation
 * ==============================================================================
 */

#include "crypto_monocypher.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

boot_status_t crypto_monocypher_init(void) {
    /* Monocypher benötigt keinen globalen HW-State zum Initialisieren. */
    return BOOT_OK;
}

void crypto_monocypher_deinit(void) {
    /* Mocks nothing to do */
}

boot_status_t crypto_monocypher_hash_init(void *ctx, size_t ctx_size) {
    if (!ctx || ctx_size < sizeof(crypto_sha512_ctx)) {
        return BOOT_ERR_INVALID_ARG;
    }
    crypto_sha512_init((crypto_sha512_ctx *)ctx);
    return BOOT_OK;
}

boot_status_t crypto_monocypher_hash_update(void *ctx, const void *data, size_t len) {
    if (!ctx || (len > 0 && !data)) {
        return BOOT_ERR_INVALID_ARG;
    }
    crypto_sha512_update((crypto_sha512_ctx *)ctx, (const uint8_t *)data, len);
    return BOOT_OK;
}

boot_status_t crypto_monocypher_hash_finish(void *ctx, uint8_t *digest, size_t *digest_len) {
    if (!ctx || !digest || !digest_len || *digest_len < 64) {
        return BOOT_ERR_INVALID_ARG;
    }
    crypto_sha512_final((crypto_sha512_ctx *)ctx, digest);
    *digest_len = 64;
    return BOOT_OK;
}

boot_status_t crypto_monocypher_verify(const uint8_t *msg, size_t len, const uint8_t *sig, const uint8_t *pubkey) {
    if (!msg && len > 0) return BOOT_ERR_INVALID_ARG;
    if (!sig || !pubkey) return BOOT_ERR_INVALID_ARG;
    
    /* crypto_ed25519_check returns 0 on success, -1 on failure */
    int status = crypto_ed25519_check(sig, pubkey, msg, len);
    if (status == 0) {
        return BOOT_OK;
    }
    return BOOT_ERR_VERIFY;
}
