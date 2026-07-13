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

#include "toob_wal_wire.h"

/* Core-internal aliases: existing code uses WAL_* names without TOOB_ prefix.
 * These aliases avoid a mass-rename across ~40 call sites in boot_state.c,
 * boot_journal.c, boot_rollback.c, boot_delta.c, boot_multiimage.c. */
typedef toob_wal_intent_t        wal_intent_t;
typedef toob_wal_entry_payload_t wal_entry_payload_t;
typedef toob_wal_entry_aligned_t wal_entry_aligned_t;

#define WAL_ABI_VERSION_MAGIC_LEGACY  TOOB_WAL_SECTOR_MAGIC_LEGACY
#define WAL_ABI_VERSION_MAGIC_CURRENT TOOB_WAL_SECTOR_MAGIC_CURRENT
#define WAL_ABI_VERSION_MAGIC         TOOB_WAL_SECTOR_MAGIC
#define WAL_ENTRY_MAGIC               TOOB_WAL_ENTRY_MAGIC

#define WAL_INTENT_NONE               TOOB_WAL_INTENT_NONE
#define WAL_INTENT_TXN_BEGIN          TOOB_WAL_INTENT_TXN_BEGIN
#define WAL_INTENT_UPDATE_PENDING     TOOB_WAL_INTENT_UPDATE_PENDING
#define WAL_INTENT_TXN_COMMIT         TOOB_WAL_INTENT_TXN_COMMIT
#define WAL_INTENT_CONFIRM_COMMIT     TOOB_WAL_INTENT_CONFIRM_COMMIT
#define WAL_INTENT_RECOVERY_RESOLVED  TOOB_WAL_INTENT_RECOVERY_RESOLVED
#define WAL_INTENT_TXN_ROLLBACK       TOOB_WAL_INTENT_TXN_ROLLBACK
#define WAL_INTENT_DEPRECATED_NONCE   TOOB_WAL_INTENT_DEPRECATED_NONCE
#define WAL_INTENT_NET_SEARCH_ACCUM   TOOB_WAL_INTENT_NET_SEARCH_ACCUM
#define WAL_INTENT_SLEEP_BACKOFF      TOOB_WAL_INTENT_SLEEP_BACKOFF
#define WAL_INTENT_TXN_ROLLBACK_PENDING TOOB_WAL_INTENT_TXN_ROLLBACK_PENDING
#define WAL_INTENT_DOWNLOAD_CHECKPOINT  TOOB_WAL_INTENT_DOWNLOAD_CHECKPOINT
#define WAL_INTENT_CLOUD_CMD          TOOB_WAL_INTENT_CLOUD_CMD
#define WAL_INTENT_DEVICE_LOCKED      TOOB_WAL_INTENT_DEVICE_LOCKED

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
#define WAL_TMR_VERSION_3 3
#define WAL_TMR_VERSION_4 4
#define WAL_TMR_VERSION_5 5
#define WAL_TMR_VERSION_CURRENT WAL_TMR_VERSION_5

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
  uint8_t  chain_tag[WAL_CHAIN_TAG_BYTES]; /* H(k_journal, entry || prev_tag), truncated */
  uint32_t chain_entry_count;              /* Monotonic counter of chained entries */

  /* --- v4-Felder (L1: OS Mailbox Integration) --- */
  uint32_t last_mbx_request_id;            /* Last processed seq number from OS Mailbox */

  /* --- v5-Felder (Recovery Counter Entkopplung) --- */
  uint32_t recovery_failure_counter;       /* Crashes during recovery OS boots */

  /* --- reserved tail (for future versions) --- */
  uint8_t reserved[TMR_PAYLOAD_SLOT_BYTES - 4 - 52 - WAL_CHAIN_TAG_BYTES - 4 - 4 - 4];
} wal_tmr_payload_t;

/** Canonical populated-size: all fields before the reserved tail.
 *  Both factory-blank and migration must use this — never a magic number. */
#define WAL_TMR_POPULATED_SIZE  offsetof(wal_tmr_payload_t, reserved)

/** Number of recent sequence IDs protected from wear-leveling recycling.
 *  TMR quorum uses 3 sectors + 1 cross-sector intent = 4 protected. */
#define WAL_PROTECT_WINDOW  4u

/**
 * @brief Der Header eines jeden WAL-Sektors.
 * Core-internal: contains typed TMR payload (not the opaque _reserved_tmr_space
 * that the OS side sees through toob_wal_wire.h).
 */
typedef struct {
  uint32_t sector_magic;        /**< Immer WAL_ABI_VERSION_MAGIC */
  uint32_t sequence_id;         /**< Fortlaufende ID fuer O(1) Sliding-Window Discovery */
  uint32_t erase_count;         /**< Tracks sector wear leveling */
  wal_tmr_payload_t tmr_data;   /**< Eine von 3 TMR Kopien (GAP-C01) */
  uint32_t header_crc32;        /**< Sichert den Sector-Header */
} wal_sector_header_t;

/**
 * @brief GAP-C03: WAL Sector Header Padding Pattern
 */
typedef union {
  wal_sector_header_t data;
  uint8_t padding[128];
} wal_sector_header_aligned_t;

_Static_assert(sizeof(wal_sector_header_aligned_t) % 8 == 0,
               "GAP-C03: WAL Sector Header padding violates hardware alignment!");
_Static_assert(sizeof(wal_tmr_payload_t) <= TMR_PAYLOAD_SLOT_BYTES,
               "ABI Drift: TMR payload exceeds slot size!");
_Static_assert(sizeof(wal_sector_header_t) <= 128,
               "ABI Drift: WAL Header exceeds slot size!");
_Static_assert(sizeof(wal_sector_header_aligned_t) == 128,
               "ABI Drift: Aligned WAL Header must be exactly 128 bytes!");
_Static_assert(WAL_TMR_POPULATED_SIZE == 84,
               "ABI Drift: populated_size must match hand-computed 84!");

/* Cross-check: Core's typed sector header must match the wire format's opaque version */
_Static_assert(sizeof(wal_sector_header_t) == sizeof(toob_wal_sector_header_t),
               "ABI Drift: Core sector header vs wire format size mismatch!");

/**
 * @brief Initialisiert das WAL (Scannt Sliding Window & laedt TMR via Majority
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
