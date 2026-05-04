/**
 * @file boot_merkle.h
 * @brief O(1) Flat-Hash-List Streaming-Verifikation
 *
 * Führt den GAP-08 Stream-Hashing Algorithmus aus. Erlaubt die Signatur- / Hashprüfung
 * extrem großer Firmware-Images, ohne O(N) SRAM zu konsumieren. 
 * Anmerkung zur Nomenklatur: Funktional operiert dies als Flat-Hash-Array, nicht als binärer Merkle-Tree.
 * 
 * Relevant Specs:
 * - docs/merkle_spec.md (RAM Limit, Streaming)
 * - docs/concept_fusion.md (WDT Kicks, Hash Alignment)
 */

#ifndef TOOB_BOOT_MERKLE_H
#define TOOB_BOOT_MERKLE_H

#include "boot_hal.h"
#include <stddef.h>
#include <stdint.h>

#define BOOT_MERKLE_HASH_LEN 32 /* Feste SHA-256 Breite nach Spec */

/* P10 Contract: Maximale Stack-Allokation für Krypto-Hashes.
 * HAL Hersteller MÜSSEN garantieren, dass ihre hash_init Contexts hier hineinpassen 
 * (z.B. SHA-256 benötigt typisch <120 Bytes). */
#define BOOT_MERKLE_MAX_CTX_SIZE 256 

/**
 * @brief Führt eine chunk-weise Verifikation eines OS-Images durch.
 *
 * @param platform          Boot HAL Platform Pointer
 * @param image_flash_addr  Start-Adresse der zu überprüfenden Partition
 * @param image_size        Exakte Dateigröße des OS-Images (Bounds-Limit)
 * @param chunk_size        Blockgröße laut Manifest (z.B. 4096 Bytes)
 * @param chunk_hashes      Array der Hashes (32 Bytes Array, liegt i.d.R. im XIP Flash)
 * @param chunk_hashes_len  Gesamtlänge des zugewiesenen Hash-Arrays in Bytes (Bounds-Enforcement)
 * @param num_chunks        Anzahl der erwarteten Hashes (Array-Grenze)
 * @param crypto_arena      SRAM Temp-Buffer (No-Malloc Allocation)
 * @param arena_size        SRAM Budget (MUSS >= chunk_size sein)
 * @return BOOT_OK wenn Hash-Liste komplett valide, BOOT_ERR_VERIFY bei Bit-Rot / Manipulation.
 */
boot_status_t boot_merkle_verify_stream(const boot_platform_t* platform,
                                        uint32_t image_flash_addr,
                                        uint32_t image_size,
                                        uint32_t chunk_size,
                                        const uint8_t* chunk_hashes,
                                        uint32_t chunk_hashes_len,
                                        uint32_t num_chunks,
                                        uint8_t* crypto_arena,
                                        size_t arena_size);

#endif /* TOOB_BOOT_MERKLE_H */
