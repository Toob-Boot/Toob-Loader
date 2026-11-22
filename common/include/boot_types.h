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
 * @brief Portability abstraction for Voltage/Clock Glitch protection
 * Definiert die NOP-Sleds architekturspezifisch. Wird zwingend per CSEL/Branchless
 * ausgewertet.
 */
#if defined(__GNUC__) || defined(__clang__)
  #define BOOT_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;" ::: "memory")
#elif defined(__ICCARM__) /* IAR */
  #define BOOT_GLITCH_DELAY() __asm volatile("nop"); __asm volatile("nop"); __asm volatile("nop" ::: "memory")
#elif defined(__CC_ARM) /* ARM Keil */
  #define BOOT_GLITCH_DELAY() __nop(); __nop(); __nop() /* Compiler Barrier via Intrinsics usually needed here */
#else
  #define BOOT_GLITCH_DELAY() /* Fallback for unknown compilers */
#endif

#ifndef TOOB_IRAM_ATTR
#if defined(__GNUC__) || defined(__clang__)
  #define TOOB_IRAM_ATTR __attribute__((section(".iram1.text")))
#else
  #define TOOB_IRAM_ATTR
#endif
#endif


/**
 * @brief Universal Bootloader Return Type (GAP-06 / MISRA C:2012 R10.1, R10.3)
 * Defined as explicit unsigned 32-bit integer type with U-suffixed high-Hamming-distance
 * constants so values > INT_MAX never trigger signed ISO C enum narrowing.
 */
typedef uint32_t boot_status_t;

#define BOOT_OK                      0x55AA55AAU /**< Clean success (AUTOSAR Anti-Glitch) */

/* HAL Errors (from hals.md) */
#define BOOT_ERR_FLASH               0xE1A1A1A1U /**< Flash-Operation fehlgeschlagen */
#define BOOT_ERR_FLASH_ALIGN         0xE2B2B2B2U /**< Adresse/Laenge nicht aligned */
#define BOOT_ERR_FLASH_BOUNDS        0xE3C3C3C3U /**< Adresse ausserhalb des Flashs */
#define BOOT_ERR_CRYPTO              0xE4D4D4D4U /**< Kryptografische Operation fehlgeschlagen */
#define BOOT_ERR_VERIFY              0xE5E5E5E5U /**< Signatur/Hash ungueltig */
#define BOOT_ERR_TIMEOUT             0xE6F6F6F6U /**< Operation hat Zeitlimit ueberschritten */
#define BOOT_ERR_POWER               0xE7171717U /**< Batteriespannung zu niedrig */
#define BOOT_ERR_NOT_SUPPORTED       0xE8282828U /**< Feature auf diesem Chip nicht verfuegbar */
#define BOOT_ERR_INVALID_ARG         0xE9393939U /**< Ungueltiger Parameter (NULL, 0-Laenge, etc.) */
#define BOOT_ERR_STATE               0xEA4A4A4AU /**< Ungueltiger Zustand (z.B. init nicht aufgerufen) */
#define BOOT_ERR_FLASH_NOT_ERASED    0xEB5B5B5BU /**< Zielsektor wurde vor Write nicht geloescht */
#define BOOT_ERR_COUNTER_EXHAUSTED   0xEC6C6C6CU /**< OTP/eFuse Counter am Limit */
#define BOOT_ERR_DEFER               0xEC7C7C7CU /**< Voruebergehende Vertagung (z.B. Energie/Spannung zu niedrig) */
#define BOOT_ERR_ECC_HARDFAULT       0xED7D7D7DU /**< FATAL: NMI Unkorrigierbarer Bit-Rot (hals.md Z.47) */
#define BOOT_ERR_FLASH_HW            0xEE8E8E8EU /**< FATAL: Hardware Flash Controller Error / Sektor-Mismatch */

/* Core State-Machine Errors */
#define BOOT_ERR_NOT_FOUND           0xF1818181U /**< Erwartetes Image/Metadata nicht gefunden */
#define BOOT_ERR_WDT_TRIGGER         0xF2929292U /**< Watchdog Timeout simuliert/registriert */
#define BOOT_ERR_INVALID_STATE       0xF3A3A3A3U /**< State-Machine Fehler (z.B. Delta base_mismatch) */
#define BOOT_ERR_WAL_FULL            0xF4B4B4B4U /**< Journal Ring blockiert/voll */
#define BOOT_ERR_WAL_LOCKED          0xF5C5C5C5U /**< Transaktion ueber WAL-Grenzen verboten */
#define BOOT_RECOVERY_REQUESTED      0xF6D6D6D6U /**< Manueller/Hardware-Ausgeloester Fallback auf Serial Rescue */
#define BOOT_ERR_ABI_MISMATCH        0xF7E7E7E7U /**< HAL ABI-Version eines Structs ist zu alt/inkompatibel */
#define BOOT_ERR_DOWNGRADE           0xF8F8F8F8U /**< Hybrid SVN Check fehlgeschlagen (Anti-Rollback) */

/* Cloud Command Errors */
#define BOOT_ERR_DEVICE_LOCKED       0xF9090909U
#define BOOT_ERR_CMD_REPLAY          0xFA1A1A1AU
#define BOOT_ERR_CMD_DEVICE_MISMATCH 0xFB2B2B2BU

/* TBM1 Manifest Errors (K2 v2 Fehler-Taxonomie) */
#define BOOT_ERR_MANIFEST_CORRUPT    0xFC3C3C3CU /**< TBM1 CRC32 pre-check failed (staging corrupt) */
#define BOOT_ERR_MANIFEST_VERSION    0xFC4D4D4DU /**< TBM1 version incompatible with this bootloader */
#define BOOT_ERR_MANIFEST_PRODUCT    0xFC5E5E5EU /**< vendor/product/hw_rev mismatch */

/**
 * @brief Fehlerklassen-Taxonomie: Ist der Fehler ein kontrollierter Reject?
 *
 * Rejectable Fehler führen beim Update-Vorgang zum Abbruch des Update-Intents (WAL_INTENT_NONE),
 * anstatt das Gerät in einen harten Panic-Reset zu schicken. Hardware-Fehler dagegen
 * propagieren direkt zum Panic/Recovery-System.
 *
 * WICHTIG: Neue boot_status_t Werte müssen hier einsortiert werden. Default = false (Panic).
 */
static inline bool boot_error_is_rejectable(boot_status_t s) {
  switch (s) {
    case BOOT_ERR_VERIFY:
    case BOOT_ERR_DOWNGRADE:
    case BOOT_ERR_INVALID_ARG:
    case BOOT_ERR_FLASH_BOUNDS:
    case BOOT_ERR_FLASH_ALIGN:
    case BOOT_ERR_INVALID_STATE:
    case BOOT_ERR_NOT_FOUND:
    case BOOT_ERR_NOT_SUPPORTED:
    case BOOT_ERR_DEFER:
    case BOOT_ERR_CMD_REPLAY:
    case BOOT_ERR_CMD_DEVICE_MISMATCH:
    case BOOT_ERR_MANIFEST_CORRUPT:
    case BOOT_ERR_MANIFEST_VERSION:
    case BOOT_ERR_MANIFEST_PRODUCT:
      return true;
    default:
      return false;
  }
}

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

/* --- 2.5 Cloud Command Types --- */

/**
 * @brief Identifiziert den Typ eines signierten Cloud Commands.
 */
typedef enum {
    TOOB_CMD_NOP           = 0x00,
    TOOB_CMD_FORCE_UPDATE  = 0x01,
    TOOB_CMD_KILLSWITCH    = 0x02,
    TOOB_CMD_UNLOCK        = 0x03,
    TOOB_CMD_ROTATE_KEY    = 0x04,
    TOOB_CMD_WIPE          = 0x05,
    TOOB_CMD_REVOKE        = 0x06,
} toob_cloud_cmd_t;

/* --- 3. Stage 1 / Stage 0 Communication & Identity --- */

/**
 * \def TOOB_MAGIC_HEADER
 * 4-Byte Magic Header für Images, den Stage 0 validiert.
 */
#define TOOB_MAGIC_HEADER     0x544F4F42U /* "TOOB" */
#define TOOB_STAGE1_SVN_MAGIC 0x31534254U /* "TBS1" */

/**
 * @brief Generic Stage 1 / App Image Header (20 bytes, ABI-locked).
 * Bytes [12..19] carry base_fingerprint for App images and authenticated
 * (svn_magic, stage1_svn) for signed Stage 1 banks (CRIT-29).
 */
typedef struct {
  uint32_t magic;       /**< TOOB_MAGIC_HEADER for Stage 0 / Stage 1 validation */
  uint32_t image_size;  /**< Payload size for bounds checking */
  uint32_t entry_point; /**< Entry-point address (RAM) or offset (XIP) */
  union {
    uint8_t base_fingerprint[8]; /**< 8-byte SHA-256 prefix for App images */
    struct {
      uint32_t svn_magic;  /**< TOOB_STAGE1_SVN_MAGIC ("TBS1") */
      uint32_t stage1_svn; /**< Authenticated Stage 1 Security Version Number */
    } s1;
  };
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
