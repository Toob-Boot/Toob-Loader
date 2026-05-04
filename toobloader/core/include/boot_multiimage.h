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
#include <stddef.h>
#include <stdint.h>


/**
 * @brief Definition eines Sub-Images aus dem SUIT Manifest
 * Striktes 8-Byte Alignment für DMA/Cortex-M0 Sicherheit.
 */
typedef struct __attribute__((aligned(8))) {
  uint32_t component_id; /**< ID (0-255) gebunden an das WAL Transfer-Bitmap */
  uint32_t staging_offset; /**< Start-Offset dieses Images im Staging-Slot */
  uint32_t
      target_addr; /**< Absolute physikalische Zieladresse (intern/extern) */
  uint32_t image_size;       /**< Größe der zu schreibenden Firmware */
  uint8_t expected_hash[32]; /**< Erwarteter SHA-256 Hash für den Read-Back
                                Beweis */
} boot_component_t;

_Static_assert(sizeof(boot_component_t) == 48,
               "boot_component_t ABI Size Drift!");

/**
 * @brief Whitelist für erlaubte Speicherbereiche (Arbitrary Write Defense).
 * Zwingend 8-Byte Aligned.
 */
typedef struct __attribute__((aligned(8))) {
  uint32_t base_addr;
  uint32_t max_size;
} boot_allowed_region_t;

/**
 * @brief Extrahiert, verifiziert und flasht n-sekundäre Images aus dem
 * Staging-Bereich.
 *
 * @param platform Boot HAL Pointer
 * @param staging_base Physische Startadresse des Update-Pakets
 * @param components Array der zu flashenden Komponenten-Deskriptoren
 * @param num_components Anzahl der Komponenten im Array
 * @param whitelist Array der erlaubten Zielspeicher-Regionen
 * @param num_regions Anzahl der Whitelist-Zonen
 * @param open_txn Das offene WAL Journal für O(1) Resume Bitmapping
 * @return BOOT_OK bei komplettem Erfolg, Error-Code bei
 * Glitch/Bounds-Breach/HW-Fault.
 */
boot_status_t boot_multiimage_apply(const boot_platform_t *platform,
                                    uint32_t staging_base,
                                    const boot_component_t *components,
                                    uint32_t num_components,
                                    const boot_allowed_region_t *whitelist,
                                    uint32_t num_regions,
                                    wal_entry_payload_t *open_txn);

#endif /* TOOB_BOOT_MULTIIMAGE_H */