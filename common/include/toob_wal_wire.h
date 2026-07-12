/**
 * @file toob_wal_wire.h
 * @brief Shared WAL (Write-Ahead-Log) wire format — the ONE source of truth.
 *
 * This header defines the on-flash layout of WAL entries and sector headers
 * shared between the Bootloader (Core/Stage 1) and the OS SDK (libtoob).
 * Both sides include this file. Neither may define their own copy.
 *
 * The Core extends the sector header with TMR internals via its own typed
 * struct; the OS sees the TMR region as opaque reserved bytes.
 */

#ifndef TOOB_WAL_WIRE_H
#define TOOB_WAL_WIRE_H

#include <stdint.h>
#include <stddef.h>

/* ===== Wire Constants ===== */

#define TOOB_WAL_ENTRY_MAGIC          0xB007BEEF
#define TOOB_WAL_SECTOR_MAGIC_LEGACY  0x57414C02  /* "WAL\x02" */
#define TOOB_WAL_SECTOR_MAGIC_CURRENT 0x57414C03  /* "WAL\x03" */
#define TOOB_WAL_SECTOR_MAGIC         TOOB_WAL_SECTOR_MAGIC_CURRENT
#define TOOB_WAL_HEADER_SIZE          128

/* ===== Intent Enum (shared ABI, fixed to uint32_t width) ===== */

typedef enum {
    TOOB_WAL_INTENT_NONE                = 0,
    TOOB_WAL_INTENT_TXN_BEGIN           = 1,
    TOOB_WAL_INTENT_UPDATE_PENDING      = 2,
    TOOB_WAL_INTENT_TXN_COMMIT          = 3,
    TOOB_WAL_INTENT_CONFIRM_COMMIT      = 4,
    TOOB_WAL_INTENT_RECOVERY_RESOLVED   = 5,
    TOOB_WAL_INTENT_TXN_ROLLBACK        = 6,
    TOOB_WAL_INTENT_DEPRECATED_NONCE    = 7,   /**< Deprecated. Nonce resides in TMR now. */
    TOOB_WAL_INTENT_NET_SEARCH_ACCUM    = 8,   /**< Anti-Lagerhaus: accumulated net-search time. */
    TOOB_WAL_INTENT_SLEEP_BACKOFF       = 9,   /**< Edge Recovery: exponential backoff level. */
    TOOB_WAL_INTENT_TXN_ROLLBACK_PENDING = 10, /**< 1-way firmware restore in progress. */
    TOOB_WAL_INTENT_DOWNLOAD_CHECKPOINT = 11,  /**< OS-side checkpoint for resumable OTA. */
    TOOB_WAL_INTENT_CLOUD_CMD           = 12,
    TOOB_WAL_INTENT_DEVICE_LOCKED       = 13
} toob_wal_intent_t;

/* ===== WAL Entry Payload (64 Bytes, append-only) ===== */

typedef struct {
    uint32_t magic;              /**< Always TOOB_WAL_ENTRY_MAGIC */
    uint32_t intent;             /**< Transaction intent (toob_wal_intent_t), fixed 32-bit ABI */

    uint64_t expected_nonce;     /**< Anti-replay nonce, naturally 8-byte aligned */

    uint32_t update_deadline;
    uint32_t transfer_bitmap[8]; /**< 1 bit = 1 chunk (256 chunks max) */
    uint32_t delta_chunk_id;     /**< Delta-patch checkpoint */
    uint32_t offset;             /**< Generic offset. For UPDATE_PENDING: manifest_flash_addr. */

    uint32_t crc32_trailer;      /**< CRC-32 over [0 .. offsetof(crc32_trailer)) */
} toob_wal_entry_payload_t;

typedef union {
    toob_wal_entry_payload_t data;
    uint8_t padding[64]; /**< Hardware-flash alignment padding */
} toob_wal_entry_aligned_t;

_Static_assert(sizeof(toob_wal_entry_payload_t) == 64,
               "WAL entry ABI drift: must be exactly 64 bytes");
_Static_assert(sizeof(toob_wal_entry_aligned_t) % 8 == 0,
               "WAL entry alignment violation");

/* ===== Sector Header (128 Bytes) =====
 * The Core's wal_sector_header_t extends this with typed TMR fields;
 * the OS sees _reserved_tmr_space as opaque. Both must agree on total size. */

typedef struct {
    uint32_t sector_magic;           /**< Always TOOB_WAL_SECTOR_MAGIC */
    uint32_t sequence_id;            /**< Monotonic for O(1) sliding-window discovery */
    uint32_t erase_count;            /**< Wear-leveling counter */
    uint8_t  _reserved_tmr_space[112]; /**< TMR payload — opaque to OS */
    uint32_t header_crc32;           /**< CRC-32 over sector header */
} toob_wal_sector_header_t;

typedef union {
    toob_wal_sector_header_t head;
    uint8_t raw[TOOB_WAL_HEADER_SIZE];
} toob_wal_sector_header_aligned_t;

_Static_assert(sizeof(toob_wal_sector_header_aligned_t) == TOOB_WAL_HEADER_SIZE,
               "WAL sector header boundary breach");
_Static_assert(offsetof(toob_wal_sector_header_t, header_crc32) == 124,
               "Sector header layout drift: CRC32 must be at offset 124");

#endif /* TOOB_WAL_WIRE_H */
