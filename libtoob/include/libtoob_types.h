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
    TOOB_ERR_INVALID_ARG= 0xE5501CAE
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
    uint32_t crc32_trailer;      /* Kryptographische Versiegelung in .noinit durch S1 */
} toob_handoff_t;

/* Mathematische Perfektion: Compile-Time Checks (P10) */
_Static_assert(sizeof(toob_handoff_t) == 32, "toob_handoff_t size breach - must be exactly 32 bytes");
_Static_assert(sizeof(toob_handoff_t) % 8 == 0, "toob_handoff_t alignment breach - must be 8-byte aligned");
_Static_assert(offsetof(toob_handoff_t, crc32_trailer) == 28, "crc32_trailer ABI offset drift detected");

/*
 * Cross-Compiler Abstraktion für die ".noinit" Linker-Section.
 * Da libtoob OS-seitig eingebunden wird, müssen wir verschiedene Compiler tolerieren.
 */
#if defined(__GNUC__) || defined(__clang__) || defined(__ICCARM__)
    #define TOOB_NOINIT __attribute__((section(".noinit")))
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION) /* ARM Compiler (Keil) */
    /* 
     * WARNING: .bss.noinit is fragile! Keil requires a dedicated Execution 
     * Region with the `UNINIT` attribute in the scatter file (.sct), 
     * otherwise the C-Runtime WILL zeroize it!
     */
    #define TOOB_NOINIT __attribute__((section(".bss.noinit")))
#else
    #warning "Compiler not officially supported by libtoob. Defaulting to GCC syntax."
    #define TOOB_NOINIT __attribute__((section(".noinit")))
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
typedef struct {
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

/* Extern Definitions (After structs are fully typed!) */
extern TOOB_NOINIT toob_handoff_t toob_handoff_state;
extern TOOB_NOINIT toob_boot_diag_t toob_diag_state;

#endif /* LIBTOOB_TYPES_H */
