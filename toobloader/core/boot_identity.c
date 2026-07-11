#include "boot_identity.h"
#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

/**
 * @brief Common KDF core: H(chip_uid ‖ root_pubkey ‖ domain_separator).
 *
 * Writes a full 32-byte SHA-256 digest into out_digest.
 * Caller is responsible for truncation if fewer bytes are needed.
 */
static boot_status_t kdf_core(const boot_platform_t *platform,
                               const char *domain_sep, size_t sep_len,
                               uint8_t out_digest[32]) {
    /* 1. Read Chip UID (variable length, max 32) */
    uint8_t uid[32];
    size_t uid_len = 0;
    boot_secure_zeroize(uid, sizeof(uid));
    boot_status_t status = platform->crypto->read_chip_uid(uid, sizeof(uid), &uid_len);
    if (status != BOOT_OK || uid_len == 0 || uid_len > sizeof(uid)) {
        boot_secure_zeroize(uid, sizeof(uid));
        return (status != BOOT_OK) ? status : BOOT_ERR_INVALID_ARG;
    }

    /* 2. Read Root Public Key (Index 0) */
    uint8_t pubkey[32] __attribute__((aligned(8)));
    boot_secure_zeroize(pubkey, sizeof(pubkey));
    status = platform->crypto->read_pubkey(pubkey, sizeof(pubkey), 0);
    if (status != BOOT_OK) {
        boot_secure_zeroize(uid, sizeof(uid));
        boot_secure_zeroize(pubkey, sizeof(pubkey));
        return status;
    }

    /* 3. Iterative Hashing: H(uid ‖ pubkey ‖ domain_separator) */
    uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    status = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
    if (status != BOOT_OK) {
        boot_secure_zeroize(uid, sizeof(uid));
        boot_secure_zeroize(pubkey, sizeof(pubkey));
        boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
        return status;
    }

    status = platform->crypto->hash_update(hash_ctx, uid, uid_len);
    if (status == BOOT_OK) {
        status = platform->crypto->hash_update(hash_ctx, pubkey, 32);
    }
    if (status == BOOT_OK) {
        status = platform->crypto->hash_update(hash_ctx, (const uint8_t *)domain_sep, sep_len);
    }
    size_t digest_len = 32;
    if (status == BOOT_OK) {
        status = platform->crypto->hash_finish(hash_ctx, out_digest, &digest_len);
    } else {
        /* Finalize to clean up ctx even on error */
        uint8_t dummy[64];
        size_t dummy_len = sizeof(dummy);
        (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
        boot_secure_zeroize(dummy, sizeof(dummy));
        boot_secure_zeroize(out_digest, 32);
    }

    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    boot_secure_zeroize(uid, sizeof(uid));
    boot_secure_zeroize(pubkey, sizeof(pubkey));

    return status;
}

/**
 * @brief Validates crypto HAL prerequisites common to all KDF operations.
 */
static boot_status_t validate_kdf_prerequisites(const boot_platform_t *platform) {
    if (platform == NULL || platform->crypto == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (platform->crypto->read_chip_uid == NULL ||
        platform->crypto->read_pubkey == NULL ||
        platform->crypto->hash_init == NULL ||
        platform->crypto->hash_update == NULL ||
        platform->crypto->hash_finish == NULL ||
        (platform->crypto->get_hash_ctx_size &&
         platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE)) {
        return BOOT_ERR_INVALID_ARG;
    }
    return BOOT_OK;
}

boot_status_t boot_derive_device_id(const boot_platform_t *platform, uint8_t out_id[32]) {
    if (out_id == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    boot_status_t status = validate_kdf_prerequisites(platform);
    if (status != BOOT_OK) {
        return status;
    }

    boot_secure_zeroize(out_id, 32);

    const char domain_separator[] = "toob-device-id-v1";
    return kdf_core(platform, domain_separator, sizeof(domain_separator) - 1, out_id);
}

boot_status_t boot_derive_journal_key(const boot_platform_t *platform, uint8_t out_key[16]) {
    if (out_key == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    boot_status_t status = validate_kdf_prerequisites(platform);
    if (status != BOOT_OK) {
        return status;
    }

    boot_secure_zeroize(out_key, 16);

    /* Derive full 32-byte digest, then truncate to 16 bytes */
    uint8_t full_digest[32];
    boot_secure_zeroize(full_digest, sizeof(full_digest));

    const char domain_separator[] = "toob-journal-key-v1";
    status = kdf_core(platform, domain_separator, sizeof(domain_separator) - 1, full_digest);
    if (status == BOOT_OK) {
        memcpy(out_key, full_digest, 16);
    }

    boot_secure_zeroize(full_digest, sizeof(full_digest));
    return status;
}
