/**
 * @file boot_types.h
 * @brief Core Toob-Boot Data Types and Status Codes
 *
 * Defines all hardware-agnostic enum states, return codes, and system-boundary
 * diagnostic structures shared between the Bootloader, HAL, and Feature OS
 * (libtoob). Adheres strictly to NASA P10 coding rules (statically verifiable,
 * no floats, strong typing).
 *
 * Relevant Specifications:
 * - docs/concept_fusion.md (Magic Headers, RAM-Handoff CRC & Session ID)
 * - docs/libtoob_api.md (ABI definition for toob_handoff_t)
 * - docs/toob_telemetry.md (Diagnostics and toob_boot_diag_t)
 * - docs/dev_plan.md (Phase 5 Wear-Counters context)
 */

#ifndef TOOB_BOOT_TYPES_H
#define TOOB_BOOT_TYPES_H

#include <stdbool.h>
#include <stdint.h>

/* --- 1. Boot Status Codes (Glitch-Resistant Returns) --- */

/**
 * @brief Universal Bootloader Return Type (GAP-06)
 * Uses high-hamming-distance constants to prevent 0x00 / 0x01 glitching.
 */
typedef enum {
    BOOT_OK = 0x55AA55AA,             /**< Clean success (AUTOSAR Anti-Glitch) */
    
    /* HAL Errors (from hals.md) */
    BOOT_ERR_FLASH = 1,               /**< Flash-Operation fehlgeschlagen */
    BOOT_ERR_FLASH_ALIGN = 2,         /**< Adresse/Länge nicht aligned */
    BOOT_ERR_FLASH_BOUNDS = 3,        /**< Adresse außerhalb des Flashs */
    BOOT_ERR_CRYPTO = 4,              /**< Kryptografische Operation fehlgeschlagen */
    BOOT_ERR_VERIFY = 5,              /**< Signatur/Hash ungültig */
    BOOT_ERR_TIMEOUT = 6,             /**< Operation hat Zeitlimit überschritten */
    BOOT_ERR_POWER = 7,               /**< Batteriespannung zu niedrig */
    BOOT_ERR_NOT_SUPPORTED = 8,       /**< Feature auf diesem Chip nicht verfügbar */
    BOOT_ERR_INVALID_ARG = 9,         /**< Ungültiger Parameter (NULL, 0-Länge, etc.) */
    BOOT_ERR_STATE = 10,              /**< Ungültiger Zustand (z.B. init nicht aufgerufen) */
    BOOT_ERR_FLASH_NOT_ERASED = 11,   /**< Zielsektor wurde vor Write nicht gelöscht */
    BOOT_ERR_COUNTER_EXHAUSTED = 12,  /**< OTP/eFuse Counter am Limit */
    BOOT_ERR_ECC_HARDFAULT = 13,      /**< FATAL: NMI Unkorrigierbarer Bit-Rot (hals.md Z.47) */
    
    /* Core State-Machine Errors */
    BOOT_ERR_NOT_FOUND = 14,          /**< Erwartetes Image/Metadata nicht gefunden */
    BOOT_ERR_WDT_TRIGGER = 15,        /**< Watchdog Timeout simuliert/registriert */
    BOOT_ERR_INVALID_STATE = 16,      /**< State-Machine Fehler (z.B. Delta base_mismatch) */
    BOOT_ERR_WAL_FULL = 17,           /**< Journal Ring blockiert/voll */
    BOOT_ERR_WAL_LOCKED = 18,         /**< Transaktion über WAL-Grenzen verboten */
    BOOT_RECOVERY_REQUESTED = 19      /**< Manueller/Hardware-Ausgelöster Fallback auf Serial Rescue */
} boot_status_t;

/* --- 2. Hardware Reset Reasons --- */

/**
 * @brief Hardware-agnostische Reset-Gründe
 * Diese werden durch die `clock_hal_t` abstrahiert und an die State-Machine
 * geliefert.
 */
typedef enum {
  RESET_REASON_UNKNOWN = 0,
  RESET_REASON_POWER_ON = 1,  /**< Kaltstart (Confirm-Flag sicher!) */
  RESET_REASON_PIN_RESET = 2, /**< Externer RST-Pin getriggert */
  RESET_REASON_WATCHDOG = 3,  /**< WDT abgelaufen (Confirm-Flag verwerfen!) */
  RESET_REASON_BROWNOUT = 4,  /**< VDD-Drop Hardware-Erkennung */
  RESET_REASON_SOFTWARE = 5,  /**< NVIC_SystemReset() / Soft-Reboot */
  RESET_REASON_HARD_FAULT = 6 /**< CPU Exception Triggered */
} reset_reason_t;

/* --- 3. Stage 1 / Stage 0 Communication & Identity --- */

/**
 * \def TOOB_MAGIC_HEADER
 * 4-Byte Magic Header für Images, den Stage 0 validiert.
 */
#define TOOB_MAGIC_HEADER 0x544F4F42 /* "TOOB" */

/**
 * @brief Generic Stage 1 Image Header Stub
 * Dieses Struct dient als Einstiegspunkt für Stage 0 Bounds-Checks.
 */
typedef struct {
  uint32_t magic;            /**< TOOB_MAGIC_HEADER für S0 Validierung */
  uint32_t image_size;       /**< Gesamte Payload-Größe für XIP Bounds */
  uint32_t entry_point;      /**< XIP Entry-Vector Offset */
  uint32_t base_fingerprint; /**< 4-Byte SHA256-Hash Prefix für Delta-Bases */
} toob_image_header_t;

/* --- 4. OS-Boundary Structures (libtoob ABI) --- */

/** \def TOOB_STATE_TENTATIVE Boot-Zustand des unbestätigten Trial-Boots */
#define TOOB_STATE_TENTATIVE 0xAAAA5555

/** \def TOOB_STATE_COMMITTED Boot-Zustand des gesichterten, bestätigten Boots
 */
#define TOOB_STATE_COMMITTED 0x55AA55AA

/**
 * @brief Shared Memory Struct (.noinit) für Handoff zwischen Bootloader und OS.
 * GAP-11: Struct Versioning
 * GAP-39: Explizites 8-Byte Alignment zwingend für 64-bit Kernel
 * Kompatibilität.
 */
typedef struct __attribute__((aligned(8))) {
  uint32_t magic;          /**< Always 0x55AA55AA */
  uint32_t struct_version; /**< ABI-Version (z.B. 0x01000000) */
  uint64_t boot_nonce;     /**< Deterministische Anti-Replay Nonce für Verify-Call */
  uint32_t active_slot;        /**< 0 = Slot A, 1 = Slot B */
  uint32_t reset_reason;       /**< Gemappter Grund aus reset_reason_t */
  uint32_t boot_failure_count; /**< Aktueller Stand des Recovery-Counters */
  
  /* Wear-Counters (vorab allokiert um Segfaults auf alten Images zu verhindern) */
  uint32_t ext_health_app_erasures;     /**< Flash-Erasures auf der App-Partition */
  uint32_t ext_health_staging_erasures; /**< Verschleiß des Staging-Bereichs */
  uint32_t ext_health_wal_erasures;     /**< Verschleiß des Ringpuffers */
  uint32_t ext_health_swap_erasures;    /**< Verschleiß der Swap-Sektoren */

  /* Session & Integrity (GAP-F14 / Schicht 4b) */
  uint32_t boot_session_id;    /**< Boot-Session Vektor für OS-Tracking */
  uint32_t crc32_trailer;      /**< CRC-32 Validierung gegen Handoff-RAM Garbage nach WDT-Resets */
  uint8_t  _padding[4];        /**< Padding für striktes 56-Byte Alignment (NASA P10 GAP-39) */
} toob_handoff_t;

/* P10 Size-Safety Asserts auf Handoff-ABI - Bricht bei inkompatiblen
 * Compiler-Packs */
_Static_assert(sizeof(toob_handoff_t) == 56,
               "toob_handoff_t ABI Size Mismatch!");
_Static_assert(sizeof(toob_handoff_t) % 8 == 0,
               "toob_handoff_t Alignment Failure!");

/**
 * @brief Telemetrie & Boot-Diagnostics (gem. toob_telemetry.md)
 * Bildet exakt die 8 CBOR-Felder ab. Wird via libtoob in das OS 
 * projiziert (Zero-Allocation).
 */
typedef struct {
  uint32_t boot_duration_ms;       /**< Dauer des letzten Bootvorgangs */
  uint32_t edge_recovery_events;   /**< Anzahl an Auto-Rollbacks */
  uint32_t hardware_fault_record;  /**< Hard-Fault Register/Flags */
  uint32_t vendor_error;           /**< HAL spezifischer Error Code */
  uint32_t wdt_kicks;              /**< Summe der generierten Watchdog-Kicks */
  uint32_t current_svn;            /**< Doublecheck Fix: SVN an das OS weiterleiten */
  uint8_t  active_key_index;       /**< Genutzter eFuse Key-Slot */
  bool     fallback_occurred;      /**< Wahrheitswert für OS-Panic Auslösung */
  uint8_t  schema_version;         /**< CDDL Review Fix: Broker Abwärtskompatibilität */
  uint8_t  sbom_digest[32];        /**< SHA-256 Digest des aktiven OS-Images */
  uint8_t  _padding[5];            /**< P10 Alignment für den 64-Bit Frame (59 active bytes) */
} toob_boot_diag_t;

/* --- 5. P10 Defense Macros --- */

/**
 * @brief Bounded-Loop Assert.
 * Beendet bei Ausbruch aus definierten O(1)/O(n) State-Limits sofort mit
 * SystemReset.
 */
#define P10_ASSERT(condition)                                                  \
  do {                                                                         \
    if (!(condition)) {                                                        \
      /* In Produktion zwingend ein WDT-Reset via Endlos-Loop oder Panic */    \
      while (1) {                                                              \
      }                                                                        \
    }                                                                          \
  } while (0)

#endif /* TOOB_BOOT_TYPES_H */
