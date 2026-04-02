/*
 * Toob-Boot Core File: boot_merkle.c
 * Relevant Spec-Dateien:
 * - docs/merkle_spec.md (Chunk-wise Streaming, RAM Limit)
 */

#include "boot_types.h"

__attribute__((used)) static void boot_merkle_dummy(void) {
    // TODO: GAP-08 Stream-Hashing Implementierung (merkle_spec.md)
    // - Lese den Stream chunk-weise (z.B. 4 KB MAX via chunk_size) aus SPI-Flash direkt in die RAM `crypto_arena` (`flash_hal.read`)
    // - Berechne inkrementell SHA-256 (`crypto_hal.hash_update`) über jeden RAM-Chunk
    // - Vergleiche berechneten Hash live mit dem Array-Eintrag `chunk_hashes[i]` (befindet sich im Flash, O(1) Random Access)
    // - Triggere zwingend WDT-Kick `wdt_hal.kick()` vor jedem Chunk-Loop-Durchlauf
    // - GAP-F17: Pruefe strikt ob `chunk_size <= flash_hal.max_sector_size` und Page-Aligned.
}
