/*
 * Toob-Boot Core File: boot_merkle.c
 * Relevant Spec-Dateien:
 * - docs/merkle_spec.md (Chunk-wise Streaming, RAM Limit)
 */

#include "boot_types.h"
#include "boot_merkle.h"
#include <string.h>
#include "boot_secure_zeroize.h"
/**
 * @brief Führt einen speichersicheren, konstanten Zeit-Vergleich durch.
 * Verhindert Timing-Orakel Angriffe bei kryptografischen Vergleichen.
 */
static bool constant_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

boot_status_t boot_merkle_verify_stream(const boot_platform_t* platform,
                                        uint32_t image_flash_addr,
                                        uint32_t image_size,
                                        uint32_t chunk_size,
                                        const uint8_t* chunk_hashes,
                                        uint32_t chunk_hashes_len,
                                        uint32_t num_chunks,
                                        uint8_t* crypto_arena,
                                        size_t arena_size) {
    
    /* 1. P10 Pointer & HAL Validation (GAP-03 Defensive Hardware Bounding) */
    if (!platform || !platform->wdt || !platform->crypto || !platform->flash) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* Strenges HAL-Capability Gating: Krypto/Flash Traits müssen zwingend existieren */
    if (!platform->crypto->hash_init || !platform->crypto->hash_update || 
        !platform->crypto->hash_finish || !platform->crypto->get_hash_ctx_size ||
        !platform->flash->read || !platform->wdt->kick) {
        return BOOT_ERR_NOT_SUPPORTED;
    }

    /* P10 VLA Defense: Verhindert Stack-Overflows, wenn Vendor-HAL PQC konfiguriert
     * und den fixen BSS/Stack-Puffer BOOT_MERKLE_MAX_CTX_SIZE übersteigen will. */
    if (platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* P10 Pointer Sicherheit für externe Puffer */
    if (!chunk_hashes || !crypto_arena) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* Keine Arrays/Images mit der Größe 0 oder Chunk-Größen mit 0 zulassen */
    if (image_size == 0 || chunk_size == 0 || num_chunks == 0 || arena_size == 0 || chunk_hashes_len == 0) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* Wrap-Check: Verhindert (i * chunk_size) Overflow bei Arrays von > 4GB Coverage */
    if (num_chunks > (UINT32_MAX / chunk_size)) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* Array Bounds Check: Der Pointer chunk_hashes_len muss die geforderte Matrix aufnehmen können */
    if ((num_chunks * BOOT_MERKLE_HASH_LEN) > chunk_hashes_len) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* 2. GAP-F17 Chunk-Size Verifikation */
    /* Chunk-Größen dürfen die Sektor-Größen nicht übersteigen, da Teil-Patches
     * beim Delta-Rollback Sektor-korrespondierend aufgebaut sein müssen. */
    if (chunk_size > platform->flash->max_sector_size) {
        return BOOT_ERR_INVALID_ARG;
    }
    /* Chunk-Size muss page-aligned sein, um Memory-Parity-Fehler abzuwehren */
    if (platform->flash->write_align > 0) {
        if ((chunk_size % platform->flash->write_align) != 0) {
            return BOOT_ERR_INVALID_ARG;
        }
    }

    /* 3. SRAM Buffer Bounds-Check */
    /* Der allokierte crypto_arena RAM Puffer muss ausreichen, 
     * um mindestens einen vollen Chunk temporär aufzunehmen. */
    if (arena_size < chunk_size) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* 4. Mathematische Coverage-Bounds (Truncation-Defense & OOB-Defense) */
    /* Verhindert "Malleability by Truncation" UND "Out-of-Bounds" Underflows: Das Manifest 
     * muss EXAKT die Menge an Hashes liefern, um die Payload-Size (image_size) lückenlos zu verifizieren! 
     * Wäre num_chunks größer als required_chunks, würde der Tail-End Kalkulator für verbleibende 
     * Bytes (`remaining`) einen Unsigned Underflow (z.B. 0xFFFFF000) erleiden und RAM korrumpieren. */
    uint32_t required_chunks = (image_size / chunk_size) + ((image_size % chunk_size) > 0 ? 1 : 0);
    if (num_chunks != required_chunks) {
        return BOOT_ERR_VERIFY; /* Abkürzungsangriff oder OOB-Expoloit-Versuch blockiert */
    }

    /* 5. Die Streaming Loop (GAP-08) */
    /* Generischer Hash-Context auf dem Stack (Opaque Buffer abstrahiert HW/SW Varianten)
     * P10 Rule: Max erlaubte Stack-Allokation ~256 Bytes für State-Maschinen. */
    _Static_assert(BOOT_MERKLE_MAX_CTX_SIZE % sizeof(uint64_t) == 0, "BOOT_MERKLE_MAX_CTX_SIZE must be exactly divisible by 8 for correct array sizing");
    uint64_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE / sizeof(uint64_t)];
    memset(hash_ctx, 0, sizeof(hash_ctx));

    boot_status_t stat = BOOT_OK;

    for (uint32_t i = 0; i < num_chunks; i++) {
        /* Anti-Lockup (concept_fusion.md): Watchdog vor IO-Operationen füttern */
        platform->wdt->kick();
        
        /* Tail-End Kalkulation: Verhindert Lesen über die Payload-Grenze (Flash OOB / Memory Corruption) */
        uint32_t bytes_processed = i * chunk_size;
        uint32_t remaining = image_size - bytes_processed;
        uint32_t read_len = (remaining < chunk_size) ? remaining : chunk_size;
        
        /* O(1) Chunk RAM-Transfer */
        stat = platform->flash->read(image_flash_addr + bytes_processed, crypto_arena, read_len);
        
        /* Anti-Lockup nach schwerem Block-Read */
        platform->wdt->kick();
        
        if (stat != BOOT_OK) {
            boot_secure_zeroize(crypto_arena, arena_size);
            boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
            return stat;
        }

        /* Stream-basiertes asymmetrisches Flat-Hashing */
        stat = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
        if (stat != BOOT_OK) goto cleanup_err;

        stat = platform->crypto->hash_update(hash_ctx, crypto_arena, read_len);
        if (stat != BOOT_OK) goto cleanup_err;

        uint8_t computed_hash[BOOT_MERKLE_HASH_LEN];
        memset(computed_hash, 0, sizeof(computed_hash));
        
        size_t digest_len = BOOT_MERKLE_HASH_LEN;
        stat = platform->crypto->hash_finish(hash_ctx, computed_hash, &digest_len);
        
        if (stat != BOOT_OK || digest_len != BOOT_MERKLE_HASH_LEN) {
            boot_secure_zeroize(computed_hash, sizeof(computed_hash));
            goto cleanup_err;
        }

        /* CONSTANT-TIME Verifizieren gegen das authentifizierte Manifest-Array (Direct Flash Mapping) */
        bool is_match = constant_time_memcmp(computed_hash, &chunk_hashes[i * BOOT_MERKLE_HASH_LEN], BOOT_MERKLE_HASH_LEN);
        
        /* O(1) Säuberung transienter Secrets */
        boot_secure_zeroize(computed_hash, sizeof(computed_hash));

        if (!is_match) {
            stat = BOOT_ERR_VERIFY; /* Bit-Rot oder Angriffsversuch erkannt! */
            goto cleanup_err;
        }
    }

    /* Update Loop Finalisiert: O(1) Secure Cleanup */
    boot_secure_zeroize(crypto_arena, arena_size);
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    return BOOT_OK;

cleanup_err:
    /* 6. SECURE ZEROIZE Fallback */
    /* Manipulierte oder korrupte OS-Daten hart aus dem RAM wischen, bevor Stage-Failures eskalieren */
    boot_secure_zeroize(crypto_arena, arena_size);
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    return stat;
}
