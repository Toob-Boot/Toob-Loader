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
 * 0. Cross-Compiler Utilities
 * ======================================================== */

/* Forces callers to check toob_status_t returns at compile time. */
#if defined(__GNUC__) || defined(__clang__)
#  define TOOB_MUST_CHECK __attribute__((warn_unused_result))
#elif defined(__ICCARM__)
#  define TOOB_MUST_CHECK _Pragma("diag_error=Pe940")
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
#  define TOOB_MUST_CHECK __attribute__((warn_unused_result))
#else
#  define TOOB_MUST_CHECK
#endif

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
    TOOB_ERR_FLASH_HW   = 0xE9901CAE,
    TOOB_ERR_STATE      = 0xEAA01CAE, /* GAP-N03: Invalid State/Initialization */
    TOOB_ERR_TIMEOUT    = 0xEBB01CAE, /* GAP-N03: Network/Operation Timeout */
    TOOB_ERR_NOT_SUPPORTED = 0xECC01CAE /* GAP-N03: Feature not implemented */
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
    uint32_t resume_offset;      /* Partielle Download Resume-Stelle (aus WAL Checkpoint) */
    uint8_t  device_id[32];      /* P10: Unique DICE Device Identity for Cloud Sync */
    uint8_t  wipe_requested;     /* OS Instruction to wipe user partitions */
    uint8_t  _padding[7];        /* P10: 8-Byte Alignment Padding */
    uint32_t crc32_trailer;      /* Kryptographische Versiegelung in .noinit durch S1 */
} toob_handoff_t;

/* Mathematische Perfektion: Compile-Time Checks (P10) */
_Static_assert(sizeof(toob_handoff_t) == 80, "toob_handoff_t size breach - must be exactly 80 bytes");
_Static_assert(sizeof(toob_handoff_t) % 8 == 0, "toob_handoff_t alignment breach - must be 8-byte aligned");
_Static_assert(offsetof(toob_handoff_t, crc32_trailer) == 76, "crc32_trailer ABI offset drift detected");

/* ========================================================
 * Handoff ABI Layout Static Asserts (P10)
 * ======================================================== */
_Static_assert(offsetof(toob_handoff_t, magic) == 0, "magic offset drift");
_Static_assert(offsetof(toob_handoff_t, struct_version) == 4, "struct_version offset drift");
_Static_assert(offsetof(toob_handoff_t, boot_nonce) == 8, "boot_nonce offset drift");
_Static_assert(offsetof(toob_handoff_t, booted_partition) == 16, "booted_partition offset drift");
_Static_assert(offsetof(toob_handoff_t, reset_reason) == 20, "reset_reason offset drift");
_Static_assert(offsetof(toob_handoff_t, boot_failure_count) == 24, "boot_failure_count offset drift");
_Static_assert(offsetof(toob_handoff_t, net_search_accum_ms) == 28, "net_search_accum_ms offset drift");
_Static_assert(offsetof(toob_handoff_t, resume_offset) == 32, "resume_offset offset drift");
_Static_assert(offsetof(toob_handoff_t, device_id) == 36, "device_id offset drift");
_Static_assert(offsetof(toob_handoff_t, wipe_requested) == 68, "wipe_requested offset drift");
_Static_assert(offsetof(toob_handoff_t, _padding) == 69, "_padding offset drift");
_Static_assert(offsetof(toob_handoff_t, crc32_trailer) == 76, "crc32_trailer offset drift");

/* Konstante für struct_version des Handoff-Headers zur Vermeidung von ABI-Drift */
#define TOOB_HANDOFF_STRUCT_VERSION 0x02000000

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
    
    /* Telemetry / Version Oracle (v2) */
    uint32_t build_number;           /* CI build number */
    uint16_t fw_ver_major;           /* Firmware version */
    uint16_t fw_ver_minor;
    uint16_t fw_ver_patch;
    uint8_t  _reserved_diag[6];      /* Alignment padding */
    
    /* SBOM */
    uint8_t  sbom_digest[32];        /* SHA-256 der letzten Stückliste (deterministisch 32 Bytes) */
    
    /* Extended Health (Optional gem. CBOR Spec) */
    uint8_t  ext_health_present;     /* P10: Explicit uint8_t statt bool für ABI Sicherheit */
    uint8_t  _padding[3];            /* P10: Explizites Padding für exaktes 4-Byte Alignment vor der Sub-Struct */
    toob_ext_health_t ext_health;    /* Health & Wear Data */
    
    uint32_t crc32_trailer;          /* CRC32 Versiegelung im .noinit */
} toob_boot_diag_t;

_Static_assert(sizeof(toob_boot_diag_t) == 104, "toob_boot_diag_t size breach - must be exactly 104 bytes for ABI stability");

_Static_assert(offsetof(toob_boot_diag_t, ext_health) % 4 == 0, "toob_ext_health_t alignment is broken in diag struct");
_Static_assert(offsetof(toob_boot_diag_t, crc32_trailer) > offsetof(toob_boot_diag_t, ext_health), "CRC32 trailer must be last field");

/* ========================================================
 * Diag ABI Layout Static Asserts (P10)
 * ======================================================== */
_Static_assert(offsetof(toob_boot_diag_t, struct_version) == 0, "struct_version offset drift");
_Static_assert(offsetof(toob_boot_diag_t, boot_duration_ms) == 4, "boot_duration_ms offset drift");
_Static_assert(offsetof(toob_boot_diag_t, verify_time_ms) == 8, "verify_time_ms offset drift");
_Static_assert(offsetof(toob_boot_diag_t, last_error_code) == 12, "last_error_code offset drift");
_Static_assert(offsetof(toob_boot_diag_t, vendor_error) == 16, "vendor_error offset drift");
_Static_assert(offsetof(toob_boot_diag_t, active_key_index) == 20, "active_key_index offset drift");
_Static_assert(offsetof(toob_boot_diag_t, current_svn) == 24, "current_svn offset drift");
_Static_assert(offsetof(toob_boot_diag_t, edge_recovery_events) == 28, "edge_recovery_events offset drift");
_Static_assert(offsetof(toob_boot_diag_t, build_number) == 32, "build_number offset drift");
_Static_assert(offsetof(toob_boot_diag_t, fw_ver_major) == 36, "fw_ver_major offset drift");
_Static_assert(offsetof(toob_boot_diag_t, sbom_digest) == 48, "sbom_digest offset drift");
_Static_assert(offsetof(toob_boot_diag_t, ext_health_present) == 80, "ext_health_present offset drift");
_Static_assert(offsetof(toob_boot_diag_t, _padding) == 81, "_padding offset drift");
_Static_assert(offsetof(toob_boot_diag_t, ext_health) == 84, "ext_health offset drift");
_Static_assert(offsetof(toob_ext_health_t, wal_erase_count) == 0, "wal_erase_count offset drift");
_Static_assert(offsetof(toob_ext_health_t, app_slot_erase_count) == 4, "app_slot_erase_count offset drift");
_Static_assert(offsetof(toob_ext_health_t, staging_slot_erase_count) == 8, "staging_slot_erase_count offset drift");
_Static_assert(offsetof(toob_ext_health_t, swap_buffer_erase_count) == 12, "swap_buffer_erase_count offset drift");
_Static_assert(offsetof(toob_boot_diag_t, crc32_trailer) == 100, "crc32_trailer offset drift");

/* Konstante für struct_version des Diag-Headers zur Vermeidung von ABI-Drift */
#define TOOB_DIAG_STRUCT_VERSION 0x02000000

/* ========================================================
 * 4. WAL (Write-Ahead-Log) Wire Format
 *    Shared definition lives in common/include/toob_wal_wire.h.
 * ======================================================== */
#include "toob_wal_wire.h"

/* OTA Network Failsafe Timeout (Default: 5 Minutes) */
#ifndef TOOB_SMOKE_TEST_TIMEOUT_MS
#define TOOB_SMOKE_TEST_TIMEOUT_MS 300000
#endif

/* Extern Definitions (After structs are fully typed!) */
extern TOOB_NOINIT toob_boot_diag_t toob_diag_state;

#endif /* LIBTOOB_TYPES_H */
