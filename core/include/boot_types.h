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
    BOOT_ERR_FLASH             = 0xE1A1A1A1,  /**< Flash-Operation fehlgeschlagen */
    BOOT_ERR_FLASH_ALIGN       = 0xE2B2B2B2,  /**< Adresse/Länge nicht aligned */
    BOOT_ERR_FLASH_BOUNDS      = 0xE3C3C3C3,  /**< Adresse außerhalb des Flashs */
    BOOT_ERR_CRYPTO            = 0xE4D4D4D4,  /**< Kryptografische Operation fehlgeschlagen */
    BOOT_ERR_VERIFY            = 0xE5E5E5E5,  /**< Signatur/Hash ungültig */
    BOOT_ERR_TIMEOUT           = 0xE6F6F6F6,  /**< Operation hat Zeitlimit überschritten */
    BOOT_ERR_POWER             = 0xE7171717,  /**< Batteriespannung zu niedrig */
    BOOT_ERR_NOT_SUPPORTED     = 0xE8282828,  /**< Feature auf diesem Chip nicht verfügbar */
    BOOT_ERR_INVALID_ARG       = 0xE9393939,  /**< Ungültiger Parameter (NULL, 0-Länge, etc.) */
    BOOT_ERR_STATE             = 0xEA4A4A4A,  /**< Ungültiger Zustand (z.B. init nicht aufgerufen) */
    BOOT_ERR_FLASH_NOT_ERASED  = 0xEB5B5B5B,  /**< Zielsektor wurde vor Write nicht gelöscht */
    BOOT_ERR_COUNTER_EXHAUSTED = 0xEC6C6C6C,  /**< OTP/eFuse Counter am Limit */
    BOOT_ERR_ECC_HARDFAULT     = 0xED7D7D7D,  /**< FATAL: NMI Unkorrigierbarer Bit-Rot (hals.md Z.47) */
    BOOT_ERR_FLASH_HW          = 0xEE8E8E8E,  /**< FATAL: Hardware Flash Controller Error / Sektor-Mismatch */
    
    /* Core State-Machine Errors */
    BOOT_ERR_NOT_FOUND         = 0xF1818181,  /**< Erwartetes Image/Metadata nicht gefunden */
    BOOT_ERR_WDT_TRIGGER       = 0xF2929292,  /**< Watchdog Timeout simuliert/registriert */
    BOOT_ERR_INVALID_STATE     = 0xF3A3A3A3,  /**< State-Machine Fehler (z.B. Delta base_mismatch) */
    BOOT_ERR_WAL_FULL          = 0xF4B4B4B4,  /**< Journal Ring blockiert/voll */
    BOOT_ERR_WAL_LOCKED        = 0xF5C5C5C5,  /**< Transaktion über WAL-Grenzen verboten */
    BOOT_RECOVERY_REQUESTED    = 0xF6D6D6D6,  /**< Manueller/Hardware-Ausgelöster Fallback auf Serial Rescue */
    BOOT_ERR_ABI_MISMATCH      = 0xF7E7E7E7,  /**< HAL ABI-Version eines Structs ist zu alt/inkompatibel */
    BOOT_ERR_DOWNGRADE         = 0xF8F8F8F8   /**< Hybrid SVN Check fehlgeschlagen (Anti-Rollback) */
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
  uint8_t  base_fingerprint[8]; /**< 8-Byte SHA256-Hash Prefix für Delta-Bases (gemäß CDDL) */
} toob_image_header_t;

_Static_assert(sizeof(toob_image_header_t) == 20, "toob_image_header_t ABI Size Mismatch!");

/* --- 4. OS-Boundary Structures (libtoob ABI) --- */

/* Integriert die externe OS-Boundary, um struct-Redundanzen und ABI-Verletzungen zu eliminieren. */
#include "libtoob_types.h"

/* P10 Zero-Dependency Sicherung: Zentraler Translation-Layer Check gegen ABI-Drift der Boundaries */
_Static_assert((uint32_t)BOOT_OK == (uint32_t)TOOB_OK, "BOOT_OK and TOOB_OK must share value");
_Static_assert((int)RESET_REASON_UNKNOWN == (int)TOOB_RESET_UNKNOWN, "ABI Drift: Unknown Reason");
_Static_assert((int)RESET_REASON_POWER_ON == (int)TOOB_RESET_POWER_ON, "ABI Drift: Power On Reason");
_Static_assert((int)RESET_REASON_PIN_RESET == (int)TOOB_RESET_PIN, "ABI Drift: Pin Reset Reason");
_Static_assert((int)RESET_REASON_WATCHDOG == (int)TOOB_RESET_WATCHDOG, "ABI Drift: Watchdog Reason");
_Static_assert((int)RESET_REASON_BROWNOUT == (int)TOOB_RESET_BROWNOUT, "ABI Drift: Brownout Reason");
_Static_assert((int)RESET_REASON_SOFTWARE == (int)TOOB_RESET_SOFTWARE, "ABI Drift: Software Reason");
_Static_assert((int)RESET_REASON_HARD_FAULT == (int)TOOB_RESET_HARD_FAULT, "ABI Drift: Hard Fault Reason");

#endif /* TOOB_BOOT_TYPES_H */
