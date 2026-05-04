/*
 * Toob-Boot OS Boundary Types (libtoob_types.h)
 * 
 * Diese Datei definiert die mathematisch strikt ausgerichteten Datenstrukturen 
 * und Konstanten, durch die das Feature-OS mit dem Toob-Boot Bootloader 
 * kommuniziert (Zero-Allocation Boundary, .noinit Handoff).
 *
 * Relevante Spezifikationen:
 * - docs/libtoob_api.md: Definition der toob_handoff_t OS-Boundary & RAM Section.
 * - docs/toob_telemetry.md: CBOR Diagnostic Structs (toob_boot_diag_t).
 * - docs/concept_fusion.md: TENTATIVE/COMMITTED State-Machine Logik.
 */

#ifndef LIBTOOB_TYPES_H
#define LIBTOOB_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ========================================================
 * 1. Status & Boot States
 * ======================================================== */

/* GAP-06: Spezifische libtoob Fehlercodes für sauberes OS-Handling */
typedef enum {
    TOOB_OK             = 0x55AA55AA,
    TOOB_ERR_NOT_FOUND  = 0xE1101CAE, /* Abstandskorrekte Hamming-Hex Werte */
    TOOB_ERR_WAL_FULL   = 0xE2201CAE,
    TOOB_ERR_WAL_LOCKED = 0xE3301CAE,
    TOOB_ERR_FLASH      = 0xE4401CAE,
    TOOB_ERR_INVALID_ARG= 0xE5501CAE,
    TOOB_ERR_VERIFY     = 0xE6601CAE, /* RAM Korruption / CRC-32 Mismatch */
    TOOB_ERR_REQUIRES_RESET = 0xE7701CAE, /* Fataler WAL Lock (Reset zwingend) */
    TOOB_ERR_COUNTER_EXHAUSTED = 0xE8801CAE, 
    TOOB_ERR_FLASH_HW   = 0xE9901CAE
} toob_status_t;

/* Partition Layout für boot_target Auswertung */
typedef enum {
    TOOB_PARTITION_APP      = 0x0000000A,
    TOOB_PARTITION_RECOVERY = 0x0000000B
} toob_partition_t;

/* Reset-Gründe (Isoliert von der boot_types.h um Zero-Dependency zu wahren) */
/* HINWEIS: Numeric Mapping muss strikt identisch zur internen reset_reason_t sein! */
typedef enum {
    TOOB_RESET_UNKNOWN    = 0,
    TOOB_RESET_POWER_ON   = 1,
    TOOB_RESET_PIN        = 2,
    TOOB_RESET_WATCHDOG   = 3,
    TOOB_RESET_BROWNOUT   = 4,
    TOOB_RESET_SOFTWARE   = 5,
    TOOB_RESET_HARD_FAULT = 6
} toob_reset_reason_t;

/* GAP-12: Explizite Boot-State Konstanten für TENTATIVE/COMMITTED Logik */
#define TOOB_STATE_TENTATIVE  0xAAAA5555
#define TOOB_STATE_COMMITTED  0x55AA55AA

/* ========================================================
 * 2. OS Interface (.noinit Handoff)
 * ======================================================== */

/* GAP-39: Zwingendes 8-Byte Alignment für 64-bit Architektur-Kompatibilität (z.B. AArch64) */
typedef struct __attribute__((aligned(8))) {
    uint32_t magic;              /* Immer 0x55AA55AA */
    uint32_t struct_version;     /* GAP-11: ABI Versionierung (z.B. 0x01000000) für Abwärtskompatibilität */
    uint64_t boot_nonce;         /* Deterministische Anti-Replay Nonce */
    uint32_t booted_partition;   /* toob_partition_t (0x0A = App Slot A, 0x0B = Recovery OS) */
    uint32_t reset_reason;       /* Letzter Hardware-Reset-Grund (toob_reset_reason_t) */
    uint32_t boot_failure_count; /* Aktueller Stand des Edge-Recovery Counters */
    uint32_t net_search_accum_ms;/* Anti-Lagerhaus Netz-Suchzeit Akkumulator */
    uint32_t _reserved_pad;      /* Erhält das 8-Byte P10 Alignment der Struktur */
    uint32_t crc32_trailer;      /* Kryptographische Versiegelung in .noinit durch S1 */
} toob_handoff_t;

/* Mathematische Perfektion: Compile-Time Checks (P10) */
_Static_assert(sizeof(toob_handoff_t) == 40, "toob_handoff_t size breach - must be exactly 40 bytes");
_Static_assert(sizeof(toob_handoff_t) % 8 == 0, "toob_handoff_t alignment breach - must be 8-byte aligned");
_Static_assert(offsetof(toob_handoff_t, crc32_trailer) == 36, "crc32_trailer ABI offset drift detected");

/* Konstante für struct_version des Handoff-Headers zur Vermeidung von ABI-Drift */
#define TOOB_HANDOFF_STRUCT_VERSION 0x01000000

/*
 * Cross-Compiler Abstraktion für die ".noinit" Linker-Section.
 * Da libtoob OS-seitig eingebunden wird, müssen wir verschiedene Compiler tolerieren.
 */
#if defined(__GNUC__) || defined(__clang__) || defined(__ICCARM__)
    #define TOOB_NOINIT __attribute__((section(".noinit")))
    #define TOOB_TRAP() __builtin_trap()
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION) /* ARM Compiler (Keil) */
    /* 
     * WARNING: .bss.noinit is fragile! Keil requires a dedicated Execution 
     * Region with the `UNINIT` attribute in the scatter file (.sct), 
     * otherwise the C-Runtime WILL zeroize it!
     */
    #define TOOB_NOINIT __attribute__((section(".bss.noinit")))
    #define TOOB_TRAP() __breakpoint(0)
#else
    #warning "Compiler not officially supported by libtoob. Defaulting to GCC syntax."
    #define TOOB_NOINIT __attribute__((section(".noinit")))
    #define TOOB_TRAP() do { volatile int* p = 0; *p = 0; } while(0)
#endif

/* ========================================================
 * 3. Telemetrie & Health Diagnostik (CBOR Extraction)
 * ======================================================== */

/* Health & Wear Data (Sub-Struct für Verschleißdaten) */
typedef struct {
    uint32_t wal_erase_count;          /* Sliding Window Pointer */
    uint32_t app_slot_erase_count;     /* App Image Verschleiß */
    uint32_t staging_slot_erase_count; /* Staging Image Verschleiß */
    uint32_t swap_buffer_erase_count;  /* In-Place Swap Buffer Verschleiß */
} toob_ext_health_t;

/* 
 * Strukturierte Boot-Diagnostik für OS CBOR Extraction 
 * Harmonisiert GAP-F29 & GAP-16 mit toob_telemetry.md
 */
typedef struct __attribute__((aligned(8))) {
    uint32_t struct_version;         /* Abwärtskompatibler Header */
    
    /* Systemwerte */
    uint32_t boot_duration_ms;       /* Gesamtdauer Start (boot_time_ms) */
    uint32_t verify_time_ms;         /* Zeit für Krypto-Hashes */
    
    /* Fehler-State */
    uint32_t last_error_code;        /* z.B. BOOT_ERR_WDT_TRIGGER */
    uint32_t vendor_error;           /* Spezifischer Flash-Fehler / hardware_fault_record */
    
    /* Identity & Revisions */
    uint32_t active_key_index;       /* eFuse Epoch Index */
    uint32_t current_svn;            /* Aktuelle SVN Version */
    
    /* Protection & Crash History */
    uint32_t edge_recovery_events;   /* Aktuelle Edge-Recovery Versuche (boot_failure_count) */
    
    /* SBOM */
    uint8_t  sbom_digest[32];        /* SHA-256 der letzten Stückliste (deterministisch 32 Bytes) */
    
    /* Extended Health (Optional gem. CBOR Spec) */
    uint8_t  ext_health_present;     /* P10: Explicit uint8_t statt bool für ABI Sicherheit */
    uint8_t  _padding[3];            /* P10: Explizites Padding für exaktes 4-Byte Alignment vor der Sub-Struct */
    toob_ext_health_t ext_health;    /* Health & Wear Data */
    
    uint32_t crc32_trailer;          /* CRC32 Versiegelung im .noinit */
} toob_boot_diag_t;

_Static_assert(sizeof(toob_boot_diag_t) == 88, "toob_boot_diag_t size breach - must be exactly 88 bytes for ABI stability");

_Static_assert(offsetof(toob_boot_diag_t, ext_health) % 4 == 0, "toob_ext_health_t alignment is broken in diag struct");
_Static_assert(offsetof(toob_boot_diag_t, crc32_trailer) > offsetof(toob_boot_diag_t, ext_health), "CRC32 trailer must be last field");

/* Konstante für struct_version des Diag-Headers zur Vermeidung von ABI-Drift */
#define TOOB_DIAG_STRUCT_VERSION 0x01000000

/* ========================================================
 * 4. WAL (Write-Ahead-Log) OS Boundary (Zero-Dependency)
 * ======================================================== */

/* GAP-C03: Zero-Dependency WAL Payload Declaration für OS Hooks */
#define TOOB_WAL_ENTRY_MAGIC  0xB007BEEF
#define TOOB_WAL_SECTOR_MAGIC 0x57414C02
#define TOOB_WAL_HEADER_SIZE  64

typedef enum {
    TOOB_WAL_INTENT_NONE = 0,
    TOOB_WAL_INTENT_TXN_BEGIN = 1,
    TOOB_WAL_INTENT_UPDATE_PENDING = 2,
    TOOB_WAL_INTENT_TXN_COMMIT = 3,
    TOOB_WAL_INTENT_CONFIRM_COMMIT = 4,
    TOOB_WAL_INTENT_RECOVERY_RESOLVED = 5,
    TOOB_WAL_INTENT_TXN_ROLLBACK = 6,
    TOOB_WAL_INTENT_DEPRECATED_NONCE = 7,  /**< Deprecated. Stored in TMR now */
    TOOB_WAL_INTENT_NET_SEARCH_ACCUM = 8,
    TOOB_WAL_INTENT_SLEEP_BACKOFF = 9
} toob_wal_intent_t;

/* 
 * Arch-Note (Zero-Dependency): This struct is a bit-perfect OS-safe duplicate 
 * of the internal `wal_entry_payload_t` from Stage 1. ABI safety is mathematically 
 * proven via _Static_assert rules over in boot_journal.h.
 */
typedef struct {
    uint32_t magic;           /**< Immer TOOB_WAL_ENTRY_MAGIC (0xBEEF) */
    uint32_t intent;          /**< Der Transaction Intent (enum toob_wal_intent_t) fixiert auf 32-bit (ABI Safety) */
    
    uint64_t expected_nonce;  /**< Sichert EXPECTED_NONCE vor dem OS-Jump (Aligned nativ ohne Padding) */
    
    /* Transaktionale Daten für Resume/Checkpointing */
    uint32_t update_deadline;
    uint32_t transfer_bitmap[8]; /**< 1 Bit = 1 Chunk (256 Chunks max) */
    uint32_t delta_chunk_id;     /**< Aktueller Checkpoint für Delta-Patches */
    uint32_t offset;             /**< Generisches Offset (z.B. Net-Search Accumulator). \n @note Bei TOOB_WAL_INTENT_UPDATE_PENDING fungiert dies zwingend als manifest_flash_addr! */
    
    uint32_t crc32_trailer;   /**< CRC-32 Trailer über den Entry */
} toob_wal_entry_payload_t;

typedef union {
    toob_wal_entry_payload_t data;
    /* Festes 64-Byte Padding für Hardware-Alignment */
    uint8_t padding[64]; 
} toob_wal_entry_aligned_t;

_Static_assert(sizeof(toob_wal_entry_aligned_t) % 8 == 0, "GAP-C03: WAL padding violates hardware alignment!");
_Static_assert(sizeof(toob_wal_entry_payload_t) == 64, "GAP-C03: toob_wal_entry_payload_t ABI size drift (Tail Padding miscalc)!");

/* ========================================================
 * Sektor Header Boundary Definition
 * ======================================================== */
typedef struct {
    uint32_t sector_magic;    /**< Immer TOOB_WAL_SECTOR_MAGIC (0x57414C02) */
    uint32_t sequence_id;     /**< Fortlaufende ID für O(1) Sliding-Window Discovery */
    uint32_t erase_count;     /**< Tracks sector wear leveling */
    uint8_t  _reserved_tmr_space[40]; /**< TMR Payload vom Bootloader (OS greift nie darauf zu) */
    uint32_t header_crc32;    /**< Sichert den Sector-Header */
    uint8_t  _padding[8];     /**< Definiertes statisches Padding für 64-Byte Alignment */
} toob_wal_sector_header_t;

typedef union {
    toob_wal_sector_header_t head;
    uint8_t raw[TOOB_WAL_HEADER_SIZE];
} toob_wal_sector_header_aligned_t;

_Static_assert(sizeof(toob_wal_sector_header_aligned_t) == TOOB_WAL_HEADER_SIZE, "WAL Header Boundary breach!");
_Static_assert(offsetof(toob_wal_sector_header_t, header_crc32) == 52, "Sector Header Layout Drift: CRC32 must be at offset 52");

/* Extern Definitions (After structs are fully typed!) */
extern TOOB_NOINIT toob_handoff_t toob_handoff_state;
extern TOOB_NOINIT toob_boot_diag_t toob_diag_state;

#endif /* LIBTOOB_TYPES_H */
