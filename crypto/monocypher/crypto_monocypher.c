/**
 * ==============================================================================
 * Toob-Boot Crypto Wrapper: Monocypher Backend Implementation
 * ==============================================================================
 */

#include "crypto_monocypher.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "../sha256/sha256.h"
#include "boot_secure_zeroize.h"

boot_status_t crypto_monocypher_init(void) {
    /* Monocypher benötigt keinen globalen HW-State zum Initialisieren. */
    return BOOT_OK;
}

void crypto_monocypher_deinit(void) {
    /* Mocks nothing to do */
}

boot_status_t crypto_monocypher_hash_init(void *ctx, size_t ctx_size) {
    if (!ctx || ctx_size < sizeof(SHA256_CTX)) {
        return BOOT_ERR_INVALID_ARG;
    }
    sha256_init((SHA256_CTX *)ctx);
    return BOOT_OK;
}

boot_status_t crypto_monocypher_hash_update(void *ctx, const void *data, size_t len) {
    if (!ctx || (len > 0 && !data)) {
        return BOOT_ERR_INVALID_ARG;
    }
    sha256_update((SHA256_CTX *)ctx, (const BYTE *)data, len);
    return BOOT_OK;
}

boot_status_t crypto_monocypher_hash_finish(void *ctx, uint8_t *digest, size_t *digest_len) {
    if (!ctx || !digest || !digest_len || *digest_len < SHA256_BLOCK_SIZE) {
        return BOOT_ERR_INVALID_ARG;
    }
    sha256_final((SHA256_CTX *)ctx, digest);
    *digest_len = SHA256_BLOCK_SIZE;
    
    /* P10 Leakage Prevention: Ensure no hash fragments remain in RAM */
    boot_secure_zeroize(ctx, sizeof(SHA256_CTX));
    
    return BOOT_OK;
}

size_t crypto_monocypher_get_hash_ctx_size(void) {
    return sizeof(SHA256_CTX);
}

boot_status_t crypto_monocypher_verify(const uint8_t *msg, size_t len, const uint8_t *sig, const uint8_t *pubkey) {
    if (!msg && len > 0) return BOOT_ERR_INVALID_ARG;
    if (!sig || !pubkey) return BOOT_ERR_INVALID_ARG;
    
    /* crypto_ed25519_check returns 0 on success, -1 on failure */
    int status = crypto_ed25519_check(sig, pubkey, msg, len);
    
    /* P10 Glitch-Defense Double-Check Pattern */
    volatile uint32_t s1 = 0, s2 = 0;
    if (status == 0) {
        s1 = BOOT_OK;
    }
    
    BOOT_GLITCH_DELAY();
    
    if (s1 == BOOT_OK && status == 0) {
        s2 = BOOT_OK;
    }
    
    if (s1 == BOOT_OK && s2 == BOOT_OK && s1 == s2) {
        return BOOT_OK;
    }
    
    return BOOT_ERR_VERIFY;
}
