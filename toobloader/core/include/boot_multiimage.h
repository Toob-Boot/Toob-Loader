/**
 * @file boot_multiimage.h
 * @brief Toob-Boot Multi-Image Orchestrator (NASA P10 Revision)
 *
 * Spezifikation:
 * - docs/concept_fusion.md (Partial Brick Prevention)
 * - docs/merkle_spec.md (SUIT Multi-Target Extraction)
 *
 * Verwaltet das atomare und Tearing-sichere Flashen von bis zu 256
 * unabhängigen Peripherie-Images (z.B. BLE-Cores, Modems, DSPs)
 * unter Nutzung der WAL Transfer-Bitmaps.
 */

#ifndef TOOB_BOOT_MULTIIMAGE_H
#define TOOB_BOOT_MULTIIMAGE_H

#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Definition eines Sub-Images aus dem Manifest.
 * Striktes 8-Byte Alignment für DMA/Cortex-M0 Sicherheit.
 */
typedef struct __attribute__((aligned(8))) {
  uint32_t component_id;            /**< ID (0-255) gebunden an das WAL Transfer-Bitmap */
  uint32_t staging_offset;          /**< Start-Offset dieses Images relativ zu staging_base */
  uint32_t target_addr;             /**< Absolute physikalische Zieladresse (intern/extern) */
  uint32_t image_size;              /**< Größe der zu schreibenden Firmware */
  uint8_t expected_hash[32];        /**< Legacy Whole-Image SHA-256 (falls chunk_size == 0) */
  uint32_t chunk_hashes_flash_addr; /**< Flash-Adresse des Per-Chunk SHA-256 Arrays (TBM1 v2) */
  uint32_t chunk_size;              /**< TBM1 v2 Blockgröße (0 = nutze expected_hash[32]) */
  uint32_t num_chunks;              /**< TBM1 v2 Anzahl Chunks */
  uint32_t _pad_mi;                 /**< Explizites 8-Byte Alignment Padding */
} boot_component_t;

_Static_assert(sizeof(boot_component_t) == 64, "boot_component_t ABI Size Drift!");

/**
 * @brief Whitelist für erlaubte Speicherbereiche (Arbitrary Write Defense).
 * Zwingend 8-Byte Aligned.
 */
typedef struct __attribute__((aligned(8))) {
  uint32_t base_addr;
  uint32_t max_size;
} boot_allowed_region_t;

typedef struct flash_effect_s flash_effect_t;

boot_status_t boot_multiimage_apply(const boot_platform_t *platform, uint32_t staging_base,
                                    const boot_component_t *components, uint32_t num_components,
                                    const boot_allowed_region_t *whitelist, uint32_t num_regions,
                                    wal_entry_payload_t *open_txn, uint8_t *arena,
                                    size_t arena_len);

boot_status_t boot_multiimage_plan_component(const boot_platform_t *platform, uint32_t staging_base,
                                             const boot_component_t *comp, uint32_t src_crc,
                                             flash_effect_t *out_fx, size_t cap, size_t *n_out);

#endif /* TOOB_BOOT_MULTIIMAGE_H */
