#include "boot_identity.h"
#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>

boot_status_t boot_derive_device_id(const boot_platform_t *platform, uint8_t out_id[32]) {
    if (platform == NULL || platform->crypto == NULL || out_id == NULL) {
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

    /* P10 Defensive: Nullize output initially */
    boot_secure_zeroize(out_id, 32);

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

    /* 3. Domain Separator */
    const char domain_separator[] = "toob-device-id-v1";
    size_t sep_len = 17;

    /* 4. Iterative Hashing (O(1) memory footprint) */
    uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    status = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
    if (status != BOOT_OK) {
        boot_secure_zeroize(uid, sizeof(uid));
        boot_secure_zeroize(pubkey, sizeof(pubkey));
        boot_secure_zeroize(hash_ctx, sizeof(hash_ctx)); /* P10 Anti-Leakage */
        return status;
    }

    status = platform->crypto->hash_update(hash_ctx, uid, uid_len);
    if (status == BOOT_OK) {
        status = platform->crypto->hash_update(hash_ctx, pubkey, 32);
    }
    if (status == BOOT_OK) {
        status = platform->crypto->hash_update(hash_ctx, (const uint8_t *)domain_separator, sep_len);
    }
    size_t digest_len = 32;
    if (status == BOOT_OK) {
        status = platform->crypto->hash_finish(hash_ctx, out_id, &digest_len);
    } else {
        /* If update failed, we still need to finalize to free/clean up ctx if necessary */
        uint8_t dummy[64];
        size_t dummy_len = sizeof(dummy);
        (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
        boot_secure_zeroize(dummy, sizeof(dummy));
        boot_secure_zeroize(out_id, 32);
    }
    
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

    /* 5. Cleanup */
    boot_secure_zeroize(uid, sizeof(uid));
    boot_secure_zeroize(pubkey, sizeof(pubkey));

    return status;
}
