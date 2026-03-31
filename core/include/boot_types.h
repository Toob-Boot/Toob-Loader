/**
 * @file boot_types.h
 * @brief Core Toob-Boot Data Types and Status Codes
 *
 * Defines all hardware-agnostic enum states, return codes, and system-boundary
 * diagnostic structures shared between the Bootloader, HAL, and Feature OS
 * (libtoob). Adheres strictly to NASA P10 coding rules (statically verifiable,
 * no floats, strong typing).
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
  BOOT_OK = 0x55AA55AA,       /**< Clean success */
  BOOT_ERR_NOT_FOUND = -1,    /**< Erwartetes Image/Metadata nicht gefunden */
  BOOT_ERR_FLASH = -2,        /**< Physikalischer Fehler auf HAL-Ebene */
  BOOT_ERR_FLASH_ALIGN = -3,  /**< Flash-Payload verletzt Hardware-Alignment */
  BOOT_ERR_FLASH_BOUNDS = -4, /**< Out-Of-Bounds Flash Zugriff blockiert */
  BOOT_ERR_VERIFY = -5, /**< Merkle-Verifikation oder Ed25519 gescheitert */
  BOOT_ERR_WDT_TRIGGER = -6, /**< Watchdog Timeout simuliert/registriert */
  BOOT_ERR_INVALID_STATE =
      -7, /**< State-Machine Fehler (z.B. Delta base_mismatch) */
  BOOT_ERR_WAL_FULL = -8,      /**< Journal Ring blockiert/voll */
  BOOT_ERR_WAL_LOCKED = -9,    /**< Transaktion über WAL-Grenzen verboten */
  BOOT_ERR_NOT_SUPPORTED = -10 /**< Hardware/HAL Feature existiert nicht */
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
  uint64_t
      boot_nonce; /**< Deterministische Anti-Replay Nonce für Verify-Call */
  uint32_t active_slot;        /**< 0 = Slot A, 1 = Slot B */
  uint32_t reset_reason;       /**< Gemappter Grund aus reset_reason_t */
  uint32_t boot_failure_count; /**< Aktueller Stand des Recovery-Counters */
  uint32_t _padding;           /**< Padding für 32-Byte Alignment */
} toob_handoff_t;

/* P10 Size-Safety Asserts auf Handoff-ABI - Bricht bei inkompatiblen
 * Compiler-Packs */
_Static_assert(sizeof(toob_handoff_t) == 32,
               "toob_handoff_t ABI Size Mismatch!");
_Static_assert(sizeof(toob_handoff_t) % 8 == 0,
               "toob_handoff_t Alignment Failure!");

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
