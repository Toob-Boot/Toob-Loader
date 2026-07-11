/**
 * @file boot_journal.h
 * @brief Write-Ahead-Log (WAL) & TMR Storage
 *
 * Implements the atomic sector management, persisting boot-status,
 * and rollback safety against brownouts.
 *
 * Complies with GAP-C01 (TMR in Headers), GAP-C03 (union padding) and GAP-37.
 */

#ifndef BOOT_JOURNAL_H
#define BOOT_JOURNAL_H

#include "boot_hal.h"
#include "boot_types.h"

#define WAL_ABI_VERSION_MAGIC_LEGACY 0x57414C02  /* "WAL\x02" */
#define WAL_ABI_VERSION_MAGIC_CURRENT 0x57414C03 /* "WAL\x03" */
#define WAL_ABI_VERSION_MAGIC WAL_ABI_VERSION_MAGIC_CURRENT
#define WAL_ENTRY_MAGIC 0xB007BEEF

/**
 * @brief Spezifische Boot-Intents (WAL Transaction States)
 */
typedef enum {
  WAL_INTENT_NONE = 0,
  WAL_INTENT_TXN_BEGIN = 1,
  WAL_INTENT_UPDATE_PENDING = 2,
  WAL_INTENT_TXN_COMMIT = 3,
  WAL_INTENT_CONFIRM_COMMIT = 4,
  WAL_INTENT_RECOVERY_RESOLVED = 5,
  WAL_INTENT_TXN_ROLLBACK = 6,
  WAL_INTENT_DEPRECATED_NONCE =
      7, /**< Deprecated. Nonce resides in TMR payload now */
  WAL_INTENT_NET_SEARCH_ACCUM = 8, /**< Anti-Lagerhaus Lockout: Persistiert die
                                      akkumulierte Netz-Suchzeit */
  WAL_INTENT_SLEEP_BACKOFF =
      9, /**< Edge Recovery: Exponential Backoff Level vor Deep-Sleep */
  WAL_INTENT_TXN_ROLLBACK_PENDING =
      10, /**< 1-way Firmware restore in progress */
  WAL_INTENT_DOWNLOAD_CHECKPOINT =
      11, /**< OS-Side Checkpoint for resumable OTA downloads */
  WAL_INTENT_CLOUD_CMD = 12,
  WAL_INTENT_DEVICE_LOCKED = 13
} wal_intent_t;

/**
 * @brief K4: Classifies whether a WAL intent is security-bearing.
 * Only security-bearing intents participate in the device-bound chain.
 */
static inline bool wal_intent_is_security_bearing(uint32_t intent) {
  return intent == WAL_INTENT_DEVICE_LOCKED ||
         intent == WAL_INTENT_CONFIRM_COMMIT ||
         intent == WAL_INTENT_TXN_COMMIT;
}

#define TMR_PAYLOAD_SLOT_BYTES 112
#define WAL_TMR_VERSION_1 1
#define WAL_TMR_VERSION_2 2
#define WAL_TMR_VERSION_CURRENT WAL_TMR_VERSION_2

#define WAL_CHAIN_TAG_BYTES 16

/**
 * @brief Legacy v1 structure layout for backward compatibility and migration mapping.
 */
typedef struct {
  uint32_t primary_slot_id;
  uint32_t active_stage1_bank;
  uint32_t app_svn;
  uint32_t boot_failure_counter;
  uint32_t svn_recovery_counter;
  uint32_t app_slot_erase_counter;
  uint32_t staging_slot_erase_counter;
  uint32_t swap_buffer_erase_counter;
  uint32_t active_nonce_lo;
  uint32_t active_nonce_hi;
  uint32_t kdm_sequence;
  uint32_t active_kdm_slot;
} wal_tmr_payload_v1_t;

typedef struct {
  uint32_t sector_magic;
  uint32_t sequence_id;
  uint32_t erase_count;
  wal_tmr_payload_v1_t tmr_data;
  uint32_t header_crc32;
} wal_sector_header_v1_t;

/**
 * @brief GAP-C01: TMR Payload (Langlebige Status-Werte)
 * Diese Struktur wird durch Majority-Vote über 3 Sektoren geschützt.
 */
typedef struct {
  uint16_t struct_version;   /* Bumped on each new field addition */
  uint16_t populated_size;   /* Actual written bytes of this version */

  /* --- v1-Felder (heutiger Bestand) --- */
  uint32_t primary_slot_id;
  uint32_t active_stage1_bank;
  uint32_t app_svn;
  uint32_t boot_failure_counter;
  uint32_t svn_recovery_counter;
  uint32_t app_slot_erase_counter;
  uint32_t staging_slot_erase_counter;
  uint32_t swap_buffer_erase_counter;

  /* P10 Anti-Replay: Nonce resides in TMR (Hardware-Signed), Not WAL!
     Splitted into 32-bit chunks to strictly prevent 8-Byte struct alignment
     padding. */
  uint32_t active_nonce_lo;
  uint32_t active_nonce_hi;

  /* P4 Deprecated: KDM is now quorum-stored via boot_rstore */
  uint32_t _deprecated_kdm_sequence;
  uint32_t _deprecated_active_kdm_slot;

  /* --- v2-Felder (Phase 7a: Self-Anti-Rollback) --- */
  uint32_t stage1_svn;  /* Last-confirmed Stage 1 SVN (defense-in-depth, A1 protection) */

  /* --- v3-Felder (K4: Device-Bound Journal Chain) --- */
  uint8_t  chain_tag[WAL_CHAIN_TAG_BYTES]; /* H(k_journal, entry ‖ prev_tag), truncated */
  uint32_t chain_entry_count;              /* Monotonic counter of chained entries */

  /* --- reserved tail (for future versions) --- */
  uint8_t reserved[TMR_PAYLOAD_SLOT_BYTES - 4 - 52 - WAL_CHAIN_TAG_BYTES - 4];
} wal_tmr_payload_t;

/**
 * @brief Der Header eines jeden WAL-Sektors
 * Liegt am Offset 0 eines jeden der 4-8 physikalischen WAL-Sektoren.
 */
typedef struct {
  uint32_t sector_magic; /**< Immer WAL_ABI_VERSION_MAGIC */
  uint32_t
      sequence_id; /**< Fortlaufende ID für O(1) Sliding-Window Discovery */
  uint32_t erase_count;       /**< Tracks sector wear leveling */
  wal_tmr_payload_t tmr_data; /**< Eine von 3 TMR Kopien (GAP-C01) */
  uint32_t header_crc32;      /**< Sichert den Sector-Header */
} wal_sector_header_t;

/**
 * @brief GAP-C03: WAL Sector Header Padding Pattern
 */
typedef union {
  wal_sector_header_t data;
  /* Festes 128-Byte Padding für Hardware-Alignment */
  uint8_t padding[128];
} wal_sector_header_aligned_t;

_Static_assert(
    sizeof(wal_sector_header_aligned_t) % 8 == 0,
    "GAP-C03: WAL Sector Header padding violates hardware alignment!");
_Static_assert(sizeof(wal_tmr_payload_t) <= TMR_PAYLOAD_SLOT_BYTES,
               "ABI Drift: TMR payload exceeds slot size!");
_Static_assert(sizeof(wal_sector_header_t) <= 128,
               "ABI Drift: WAL Header exceeds slot size!");
_Static_assert(sizeof(wal_sector_header_aligned_t) == 128,
               "ABI Drift: Aligned WAL Header must be exactly 128 bytes!");

/**
 * @brief Der Payload eines einzelnen angehängten WAL-Eintrags.
 */
typedef struct {
  uint32_t magic;  /**< Immer WAL_ENTRY_MAGIC (0xBEEF) */
  uint32_t intent; /**< Der Transaction Intent (enum wal_intent_t) */

  /* FIX: 64-bit Nonce direkt hier für 8-Byte Alignment ohne Struct-Padding (P10
   * Struct Geometry) */
  uint64_t expected_nonce; /**< Sichert EXPECTED_NONCE vor dem OS-Jump */

  /* Transaktionale Daten für Resume/Checkpointing */
  uint32_t update_deadline;
  uint32_t transfer_bitmap[8]; /**< 1 Bit = 1 Chunk (256 Chunks max) */
  uint32_t delta_chunk_id;     /**< Aktueller Checkpoint für Delta-Patches */
  uint32_t offset; /**< Generisches Offset (z.B. für Net-Search Accumulator) */

  uint32_t crc32_trailer; /**< CRC-32 Trailer über den Entry */
} wal_entry_payload_t;

/**
 * @brief GAP-C03: WAL Struct Padding Pattern
 * Jeder Append-Eintrag muss auf Hardware-Flash-Größen aligned sein.
 */
typedef union {
  wal_entry_payload_t data;
  /* Festes 64-Byte Padding für Hardware-Alignment */
  uint8_t padding[64];
} wal_entry_aligned_t;

_Static_assert(sizeof(wal_entry_aligned_t) % 8 == 0,
               "GAP-C03: WAL padding violates hardware alignment!");

/* P10 Zero-Dependency Sicherung: Zentraler Translation-Layer Check gegen
 * ABI-Drift der Boundaries */
_Static_assert(sizeof(wal_entry_payload_t) == sizeof(toob_wal_entry_payload_t),
               "ABI Drift: WAL Entry Type Size Mismatch!");
_Static_assert((uint32_t)WAL_ENTRY_MAGIC == (uint32_t)TOOB_WAL_ENTRY_MAGIC,
               "ABI Drift: WAL Entry Magic Mismatch!");
_Static_assert((int)WAL_INTENT_CONFIRM_COMMIT ==
                   (int)TOOB_WAL_INTENT_CONFIRM_COMMIT,
               "ABI Drift: Enum Confirm Commit Mismatch!");
_Static_assert((int)WAL_INTENT_UPDATE_PENDING ==
                   (int)TOOB_WAL_INTENT_UPDATE_PENDING,
               "ABI Drift: Enum Update Pending Mismatch!");
_Static_assert((int)WAL_INTENT_CLOUD_CMD == (int)TOOB_WAL_INTENT_CLOUD_CMD,
               "ABI Drift: Enum Cloud Cmd Mismatch!");
_Static_assert((int)WAL_INTENT_DEVICE_LOCKED ==
                   (int)TOOB_WAL_INTENT_DEVICE_LOCKED,
               "ABI Drift: Enum Device Locked Mismatch!");
_Static_assert(sizeof(wal_sector_header_t) == sizeof(toob_wal_sector_header_t),
               "ABI Drift: WAL Header Size Mismatch!");

/**
 * @brief Initialisiert das WAL (Scannt Sliding Window & lädt TMR via Majority
 * Vote)
 */
boot_status_t boot_journal_init(const boot_platform_t *platform);

/**
 * @brief Retrieves the current TMR payload as established during init (Majority
 * Vote).
 */
boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr);

/**
 * @brief Updated die TMR-Werte sicher.
 * Re-Ersast 3 WAL-Sektoren sequenziell, um die TMR Majority zu erneuern.
 */
boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr);

/**
 * @brief Schreibt einen neuen Intent atomar + CRC gesichert als Append in den
 * aktuellen Flash-Sektor.
 */
boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry);

/**
 * @brief Rekonstruiert die letzte unfertige Transaktion / State aus den
 * Append-Entries und extrahiert den aktiven Trial-Nonce (Anti-Replay).
 */
boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform,
                                           wal_entry_payload_t *out_state,
                                           uint32_t *out_net_accum,
                                           uint32_t *out_resume_offset);

#endif /* BOOT_JOURNAL_H */
