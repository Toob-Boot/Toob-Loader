/**
 * @file boot_hal.h
 * @brief Hardware Abstraction Layer (HAL) Interfaces for Toob-Boot
 *
 * Defines the strict function pointer interfaces (Traits) that any
 * target architecture must implement. This entirely abstracts the physical
 * hardware (Flash, WDT, Crypto, Clocks) from the generic State-Machine Core.
 * Adheres strictly to zero-allocation, strong typing, and ABI versioning.
 *
 * Relevant Specifications:
 * - docs/hals.md (Hardware Abstraction Traits Master Spec)
 * - docs/structure_plan.md (V2 ABI Versioning and Modularization rules)
 * - docs/concept_fusion.md (WDT behavior, Flash OTFDEC, Penalty sleeps)
 * - docs/testing_requirements.md (Link-Time validation, TIMING_SAFETY)
 */

#ifndef TOOB_BOOT_HAL_H
#define TOOB_BOOT_HAL_H

#include "boot_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* --- 1. Flash HAL (Non-Volatile Storage) --- */

#define TOOB_HAL_ABI_V2 0x02000000

/**
 * @brief Flash / NVS Abstraction
 * Handles raw physical reads and writes. Requires OTFDEC capability for
 * verifying envelopes.
 */
typedef struct {
  uint32_t abi_version; /**< MUST be 0x02000000 (V2) */

  boot_status_t (*init)(void);
  /** 
   * @brief Kills DMA, disables OTFDEC, isolates before jump.
   * HAL-Contract: MUSS idempotent und fehlerfrei sein, oder Fehler stumm absorbieren. 
   */
  void (*deinit)(void);

  boot_status_t (*read)(uint32_t addr, void *buf, size_t len);
  boot_status_t (*write)(uint32_t addr, const void *buf, size_t len);
  boot_status_t (*erase_sector)(uint32_t addr);

  boot_status_t (*get_sector_size)(uint32_t addr, size_t *size_out);
  boot_status_t (*set_otfdec_mode)(bool enable);
  uint32_t (*get_last_vendor_error)(void);

  /* Dynamische Fuzzer-Limits (via Manifest-Compiler in chip_config.h injiziert) */
  uint32_t max_sector_size;
  uint32_t total_size;
  uint32_t max_erase_cycles; /* Vendor Limit (e.g. 100000) */
  uint8_t  write_align;
  uint8_t  erased_value;
} flash_hal_t;

/* --- 2. Confirm HAL (Survival State Storage) --- */

/**
 * @brief 2FA Handoff State Storage
 * Handles persistent confirmations via RTC-RAM or specific Backup Registers.
 * Note: set_ok is explicitly removed (GAP-F14/F15, handled by OS via libtoob
 * WAL flush).
 */
typedef struct {
  uint32_t abi_version;

  boot_status_t (*init)(void);
  /**
   * @brief Power down underlying peripheral.
   * HAL-Contract: MUSS idempotent sein. Loescht NICHT den Confirm-State (das macht clear).
   */
  void (*deinit)(void);

  bool (*check_ok)(uint64_t expected_nonce);
  boot_status_t (*clear)(void);
} confirm_hal_t;

/* --- 3. Watchdog HAL (Anti-Lockup) --- */

/**
 * @brief Hardware Watchdog Interface
 * Prevents endless loops. Includes critical section suspension for opaque
 * ROM-erases.
 */
typedef struct {
  uint32_t abi_version;

  /* POLICY (Phase 6): Vendor Ports MÜSSEN den TIMING_SAFETY_FACTOR bei der 
   * internen Register-Allokation auf timeout_ms_required beaufschlagen! */
  boot_status_t (*init)(uint32_t timeout_ms_required);
  /** HAL-Contract: MUSS idempotent und fehlerfrei sein */
  void (*deinit)(void);

  void (*kick)(void);

  /* GAP-02: Safe Prescaler Injection for blocking Erase-ROM Functions */
  void (*suspend_for_critical_section)(void);
  void (*resume)(void);
} wdt_hal_t;

/* --- 4. Crypto HAL (Security Primitives) --- */

/**
 * @brief Cryptographic Core Engine
 * Offloads hashing and Ed25519/PQC signatures, as well as accessing eFuse IDs.
 */
typedef struct {
  uint32_t abi_version;

  boot_status_t (*init)(void);
  /** 
   * @brief Zeroizes all internal buffers/keys.
   * HAL-Contract: MUSS idempotent und fehlerfrei sein. 
   */
  void (*deinit)(void);

  /* Hashing (Merkle) (GAP-C04: Zwang zur Nutzung der crypto_arena) */
  boot_status_t (*hash_init)(void *ctx, size_t ctx_size);
  boot_status_t (*hash_update)(void *ctx, const void *data, size_t len);
  boot_status_t (*hash_finish)(void *ctx, uint8_t *digest, size_t *digest_len);

  /* Envelopes */
  boot_status_t (*verify_ed25519)(
      const uint8_t *message, size_t msg_len,
      const uint8_t *sig, const uint8_t *pubkey);
  boot_status_t (*verify_pqc)(
      const uint8_t *message, size_t msg_len,
      const uint8_t *sig, size_t sig_len,
      const uint8_t *pubkey, size_t pubkey_len);

  /* RNG */
  boot_status_t (*random)(uint8_t *buf, size_t len);

  uint32_t (*get_last_vendor_error)(void);

  /* Hardware Roots (eFuse / OTP) */
  boot_status_t (*read_pubkey)(uint8_t *key, size_t key_len, uint8_t key_index);
  boot_status_t (*read_dslc)(uint8_t *buffer, size_t *len);
  boot_status_t (*read_monotonic_counter)(uint32_t *ctr);
  boot_status_t (*advance_monotonic_counter)(void);

  size_t (*get_hash_ctx_size)(void);
  bool has_hw_acceleration;
} crypto_hal_t;

/* --- 5. Clock HAL (Timing & Resets) --- */

/**
 * @brief Timing Base and Reset Registers
 */
typedef struct {
  uint32_t abi_version;

  boot_status_t (*init)(void);
  /** HAL-Contract: MUSS idempotent und fehlerfrei sein */
  void (*deinit)(void);

  uint32_t (*get_tick_ms)(void);
  void (*delay_ms)(uint32_t ms);

  reset_reason_t (*get_reset_reason)(void);
} clock_hal_t;

/* --- 6. Console HAL (Passive Debug Logging) --- */

/**
 * @brief UART/RTT Logger
 * Strongly recommended to be non-blocking.
 */
typedef struct {
  uint32_t abi_version;

  boot_status_t (*init)(uint32_t baudrate);
  /** HAL-Contract: MUSS idempotent und fehlerfrei sein */
  void (*deinit)(void);

  void (*putchar)(char c);
  boot_status_t (*getchar)(uint8_t *out, uint32_t timeout_ms);
  void (*flush)(void);
} console_hal_t;

/* --- 7. SoC Guard HAL (Multi-Core & Power) --- */

/**
 * @brief Advanced System Control
 * Manages brown-out potentials and sub-processor isolation.
 */
typedef struct {
  uint32_t abi_version;

  boot_status_t (*init)(void);
  void (*deinit)(void);

  uint32_t (*battery_level_mv)(void);
  bool (*can_sustain_update)(void);

  /* Exponential-Penalty-Sleep / Edge-Recovery (hals.md Z.753 erwartet SEC) */
  void (*enter_low_power)(uint32_t wakeup_s);

  /* 
   * HAL-Contract: Diese Funktionen müssen "pre-init-safe" sein, d.h.
   * sicher aufrufbar BEVOR `soc->init()` ausgeführt wurde, da sie von
   * boot_main strukturell am absoluten Anfang zerschmetternd eingesetzt werden.
   */
  void (*assert_secondary_cores_reset)(void);
  void (*flush_bus_matrix)(void);

  /* 
   * Mechanischer Recovery-Pin (Anti-Softbrick) Evaluator (concept_fusion.md Z.117).
   * MUSS von der Hardware mit einer Debounce-Zeit (z.B. >= 500ms) ausgewertet werden!
   */
  bool (*get_recovery_pin_state)(void);

  uint32_t min_battery_mv;
} soc_hal_t;

/* --- Master Platform Container --- */

/**
 * @brief Aggregation of all HAL Pointers.
 * Instantiated natively by the Host/Sandbox or target Vendor startup sequence.
 */
typedef struct {
  const flash_hal_t *flash;     /**< PFLICHT */
  const confirm_hal_t *confirm; /**< PFLICHT */
  const crypto_hal_t *crypto;   /**< PFLICHT */
  const clock_hal_t *clock;     /**< PFLICHT */
  const wdt_hal_t *wdt;         /**< PFLICHT */
  const console_hal_t *console; /**< Optional */
  const soc_hal_t *soc;         /**< Optional */
} boot_platform_t;

/**
 * @brief Vendor-specific Initialization Point.
 * Implemented per-platform in `hal/vendor/chip_platform.c`.
 *
 * P10 MANDATORY CONTRACT (hals.md Abs 0):
 * Die implementierende Architektur MUSS zwingend einen asynchronen
 * `HardFault_Handler` (inkl. `ECC_NMI` Trap) definieren, welcher Flash
 * Bit-Rot Exceptions abfängt und asynchron ein `BOOT_ERR_ECC_HARDFAULT` 
 * auslöst bzw. via Watchdog resettet, um einen Exception-Deadlock zu vermeiden!
 *
 * @return Safely populated Platform struct, or halts/panics on failure.
 */
const boot_platform_t *boot_platform_init(void);

#endif /* TOOB_BOOT_HAL_H */
