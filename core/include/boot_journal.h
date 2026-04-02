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

#include "boot_types.h"
#include "boot_hal.h"

/* Magic Header für Vorwärtskompatibilität (P10) */
#define WAL_ABI_VERSION_MAGIC 0x57414C02 /* "WAL\x02" */
#define WAL_ENTRY_MAGIC       0xBEEF

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
    
    /* FIX (Doublecheck): Missing Intents extracted from concept_fusion.md */
    WAL_INTENT_NONCE_INTENT = 7,       /**< Sichert den 64-Bit Boot-Handoff gegen Brute-Force Wraparounds */
    WAL_INTENT_NET_SEARCH_ACCUM = 8,   /**< Anti-Lagerhaus Lockout: Persistiert die akkumulierte Netz-Suchzeit */
    WAL_INTENT_SLEEP_BACKOFF = 9       /**< Edge Recovery: Exponential Backoff Level vor Deep-Sleep */
} wal_intent_t;

/**
 * @brief GAP-C01: TMR Payload (Langlebige Status-Werte)
 * Diese Struktur wird durch Majority-Vote über 3 Sektoren geschützt.
 */
typedef struct {
    uint32_t primary_slot_id;
    uint32_t boot_failure_counter;
    uint32_t svn_recovery_counter;
    uint32_t app_slot_erase_counter;
    uint32_t staging_slot_erase_counter;
    uint32_t swap_buffer_erase_counter;
} wal_tmr_payload_t;

/**
 * @brief Der Header eines jeden WAL-Sektors
 * Liegt am Offset 0 eines jeden der 4-8 physikalischen WAL-Sektoren.
 */
typedef struct {
    uint32_t sector_magic;      /**< Immer WAL_ABI_VERSION_MAGIC */
    uint32_t sequence_id;       /**< Fortlaufende ID für O(1) Sliding-Window Discovery */
    uint32_t erase_count;       /**< Tracks sector wear leveling */
    wal_tmr_payload_t tmr_data; /**< Eine von 3 TMR Kopien (GAP-C01) */
    uint32_t header_crc32;      /**< Sichert den Sector-Header */
} wal_sector_header_t;

/**
 * @brief GAP-C03: WAL Sector Header Padding Pattern
 */
typedef union {
    wal_sector_header_t data;
    /* Festes 64-Byte Padding für Hardware-Alignment */
    uint8_t padding[64]; 
} wal_sector_header_aligned_t;

_Static_assert(sizeof(wal_sector_header_aligned_t) % 8 == 0, 
               "GAP-C03: WAL Sector Header padding violates hardware alignment!");


/**
 * @brief Der Payload eines einzelnen angehängten WAL-Eintrags.
 */
typedef struct {
    uint32_t magic;           /**< Immer WAL_ENTRY_MAGIC (0xBEEF) */
    wal_intent_t intent;      /**< Der Transaction Intent */
    
    /* Transaktionale Daten für Resume/Checkpointing */
    uint32_t update_deadline;
    uint32_t transfer_bitmap[8]; /**< 1 Bit = 1 Chunk (256 Chunks max) */
    uint32_t delta_chunk_id;     /**< Aktueller Checkpoint für Delta-Patches */
    uint32_t offset;             /**< Generisches Offset (z.B. für Net-Search Accumulator) */
    
    /* FIX (Doublecheck): Missing 64-bit Nonce required for Anti-Replay Handoff */
    uint64_t expected_nonce;  /**< Sichert EXPECTED_NONCE vor dem OS-Jump */
    
    uint32_t crc32_trailer;   /**< CRC-32 Trailer über den Entry */
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


/**
 * @brief Initialisiert das WAL (Scannt Sliding Window & lädt TMR via Majority Vote)
 */
boot_status_t boot_journal_init(const boot_platform_t *platform);

/**
 * @brief Retrieves the current TMR payload as established during init (Majority Vote).
 */
boot_status_t boot_journal_get_tmr(const boot_platform_t *platform, wal_tmr_payload_t *out_tmr);

/**
 * @brief Updated die TMR-Werte sicher.
 * Re-Ersast 3 WAL-Sektoren sequenziell, um die TMR Majority zu erneuern.
 */
boot_status_t boot_journal_update_tmr(const boot_platform_t *platform, const wal_tmr_payload_t *new_tmr);

/**
 * @brief Schreibt einen neuen Intent atomar + CRC gesichert als Append in den aktuellen Flash-Sektor.
 */
boot_status_t boot_journal_append(const boot_platform_t *platform, const wal_entry_payload_t *new_entry);

/**
 * @brief Rekonstruiert die letzte unfertige Transaktion / State aus den Append-Entries.
 */
boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform, wal_entry_payload_t *out_state);

#endif /* BOOT_JOURNAL_H */
