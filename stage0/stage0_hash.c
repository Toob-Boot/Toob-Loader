/*
 * Toob-Boot Stage 0: stage0_hash.c
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md (SHA-256 Software)
 *
 * TODO (Architecture Requirements):
 * - Hash-Computation: Hardware- oder Software-basierte SHA-256 (bzw. PQC) Hashing-Funktion über den gesamten Stage 1 Slot.
 * - Constant-Time Verification: Sicherstellen, dass Hash-Vergleiche absolut konstant ablaufen, um Timing-Sidechannels auf Stage 0 Ebene zu blockieren.
 */
#include "../../crypto/sha256/sha256.h"
#include "stage0_crypto.h"
#include <stddef.h>
#include <stdint.h>

/* Berechnet einen Bare-Metal Hash über einen Flash-Speicherbereich (Zero-Allocation) */
void stage0_hash_compute(const uint8_t *data, size_t len, uint8_t *digest) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)data, len);
    sha256_final(&ctx, (uint8_t *)digest);
    
    /* P10 Leakage Prevention (ohne externe boot_secure_zeroize Dependency) */
    volatile uint8_t *p = (volatile uint8_t *)&ctx;
    for (size_t i = 0; i < sizeof(ctx); i++) {
        p[i] = 0;
    }
}
