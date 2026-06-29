/**
 * @file boot_rstore.h
 * @brief Generic Quorum-Protected Redundant Store (Phase 4)
 *
 * Provides a reusable quorum-based storage primitive for any fixed-size
 * record that needs N-of-M redundancy with self-healing. Extracted from
 * boot_journal.c's TMR machinery per plan.md Phase 4.
 *
 * SECURITY CONTRACT:
 * - Whole-Struct majority vote (no byte-mixing / Frankenstein records)
 * - Bounded opportunistic healing: max 1 erase + 1 write under WDT suspend
 * - Underflow-safe sequence arithmetic (RFC 1982)
 * - Constant-time record comparison (timing side-channel safe)
 * - Smart-Erase: skips hardware erase if sector is already 0xFF
 */

#ifndef BOOT_RSTORE_H
#define BOOT_RSTORE_H

#include "boot_hal.h"
#include "boot_types.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Descriptor for a quorum-protected store instance.
 *
 * Each instance describes a set of flash sectors that collectively
 * protect a single record type via majority vote.
 */
typedef struct {
    const uint32_t *slot_addrs;  /**< Array of slot base addresses */
    const size_t   *slot_sizes;  /**< Array of slot sizes (sector sizes) */
    uint8_t         slot_count;  /**< Number of slots (>= 3 for true quorum) */
    uint16_t        record_size; /**< Size of the user record in bytes */
    uint32_t        magic;       /**< Sector-level magic for identification */
} boot_rstore_desc_t;

/**
 * @brief Per-slot envelope header written at the start of each sector.
 *
 * Layout: [header (16 bytes)] [record_data (record_size bytes)] [padding to sector end]
 */
typedef struct {
    uint32_t magic;        /**< Must match desc->magic */
    uint32_t sequence_id;  /**< Monotonic sequence for ordering */
    uint32_t erase_count;  /**< Cumulative erase counter for wear tracking */
    uint32_t header_crc32; /**< CRC-32 over header + record_data */
} boot_rstore_slot_header_t;

_Static_assert(sizeof(boot_rstore_slot_header_t) == 16,
               "rstore slot header must be exactly 16 bytes");
_Static_assert(sizeof(boot_rstore_slot_header_t) % 4 == 0,
               "rstore slot header must be 4-byte aligned");

/**
 * @brief Reads a record from the quorum store via majority vote.
 *
 * Reads all slots, validates CRC, performs whole-struct majority vote.
 * If a defective slot is detected and a valid majority exists, performs
 * bounded opportunistic healing (1 erase + 1 write under WDT suspension).
 *
 * @param platform  Hardware abstraction
 * @param desc      Store descriptor
 * @param out_record  Output buffer (must be >= desc->record_size bytes)
 * @return BOOT_OK on success, BOOT_ERR_NOT_FOUND if no valid majority
 */
boot_status_t boot_rstore_read(const boot_platform_t *platform,
                               const boot_rstore_desc_t *desc,
                               void *out_record);

/**
 * @brief Writes a record to all slots in the quorum store.
 *
 * Performs a full quorum write: erases and writes all slot_count slots
 * sequentially with incrementing sequence IDs. Uses smart-erase to
 * skip unnecessary hardware erases.
 *
 * @param platform  Hardware abstraction
 * @param desc      Store descriptor
 * @param record    Record data to write (must be desc->record_size bytes)
 * @return BOOT_OK on success, error code on flash failure
 */
boot_status_t boot_rstore_write(const boot_platform_t *platform,
                                const boot_rstore_desc_t *desc,
                                const void *record);

#endif /* BOOT_RSTORE_H */
