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
#include "toob_swap_event_wire.h"
#include "boot_slot_caps.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RTC-Backup Register Slot Allocation */
#define RTC_SLOT_AUTH_ATTEMPTS 0

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

  /* Append-only fields for Energy-aware Admission (K7) */
  uint32_t erase_time_us_max;   /* Worst-case erase time of max_sector_size sector in us, 0=unknown */
  uint32_t write_time_us_page;  /* per write_align-Page in us, 0=unknown */
  boot_status_t (*get_supply_mv)(uint32_t *mv_out);  /* Optional supply voltage readout, NULL if unsupported */
} flash_hal_t;

#include <stddef.h>
_Static_assert(offsetof(flash_hal_t, erased_value) < offsetof(flash_hal_t, erase_time_us_max),
               "ABI Layout Violation: erase_time_us_max must be appended at the end of flash_hal_t");

/**
 * @brief Initializer for flash_hal_t (REG-033).
 * Positional: 6 mandatory function pointers (init..get_sector_size).
 * Data fields and optional fn pointers via trailing designated initializers.
 */
#define TOOB_FLASH_HAL_V2(init_, deinit_, read_, write_,                    \
                          erase_sector_, get_sector_size_, ...)             \
    { .abi_version     = TOOB_HAL_ABI_V2,                                  \
      .init            = (init_),                                          \
      .deinit          = (deinit_),                                        \
      .read            = (read_),                                          \
      .write           = (write_),                                         \
      .erase_sector    = (erase_sector_),                                  \
      .get_sector_size = (get_sector_size_),                                \
      __VA_ARGS__ }

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

  /**
   * @brief Verify RTC Backend Nonce Confirmation
   * HAL-Contract: MUSS die abgelegte Nonce bei einem positiven Match zwingend auf 
   * 0 (oder einen invaliden Wert) ueberschreiben/zeroizen, um Replay-Angriffe gegen 
   * darauffolgende unbestaetigte Boots zu verhindern!
   */
  bool (*check_ok)(uint64_t expected_nonce);
  boot_status_t (*clear)(void);
} confirm_hal_t;

/** @brief Initializer for confirm_hal_t (REG-033). All 4 fields mandatory. */
#define TOOB_CONFIRM_HAL_V2(init_, deinit_, check_ok_, clear_, ...)         \
    { .abi_version = TOOB_HAL_ABI_V2,                                      \
      .init     = (init_),                                                 \
      .deinit   = (deinit_),                                               \
      .check_ok = (check_ok_),                                             \
      .clear    = (clear_),                                                \
      __VA_ARGS__ }

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

/** @brief Initializer for wdt_hal_t (REG-033). All 5 fields mandatory. */
#define TOOB_WDT_HAL_V2(init_, deinit_, kick_, suspend_, resume_, ...)     \
    { .abi_version                  = TOOB_HAL_ABI_V2,                     \
      .init                         = (init_),                             \
      .deinit                       = (deinit_),                           \
      .kick                         = (kick_),                             \
      .suspend_for_critical_section = (suspend_),                          \
      .resume                       = (resume_),                           \
      __VA_ARGS__ }

//* --- 4. Crypto HAL (Security Primitives) --- */

#define TOOB_HAL_ABI_V3 0x03000000

/**
 * @brief Hardware Entropy & TRNG Interface (ABI v3)
 */
typedef struct {
  uint32_t abi_version; /**< MUST be 0x03000000 (V3) */

  boot_status_t (*init)(void);
  void (*deinit)(void);

  /**
   * @brief Generate cryptographic random bytes.
   * HAL-Contract: Must perform NIST SP 800-90B health tests.
   */
  boot_status_t (*random)(uint8_t *buf, size_t len);

  bool is_hardware_trng;
} entropy_hal_t;

#define TOOB_ENTROPY_HAL_V3(init_, deinit_, random_, ...)                    \
    { .abi_version      = TOOB_HAL_ABI_V3,                                  \
      .init             = (init_),                                          \
      .deinit           = (deinit_),                                        \
      .random           = (random_),                                        \
      __VA_ARGS__ }

/**
 * @brief Keystore & OTP Controller Interface (ABI v3)
 */
typedef struct {
  uint32_t abi_version; /**< MUST be 0x03000000 (V3) */

  boot_status_t (*init)(void);
  void (*deinit)(void);

  /* Hardware Key & Identity Accessors */
  boot_status_t (*read_pubkey)(uint8_t *key, size_t key_len, uint8_t key_index);
  boot_status_t (*read_chip_uid)(uint8_t *buf, size_t max_len, size_t *out_len);
  boot_status_t (*read_dslc)(uint8_t *buffer, size_t *len);
  boot_status_t (*write_dslc)(const uint8_t *value, size_t len);

  /* Hardware Monotonic Counter */
  boot_status_t (*read_monotonic_counter)(uint32_t *ctr);
  boot_status_t (*advance_monotonic_counter)(void);

  /* Factory Provisioning & Security Lockdowns */
  boot_status_t (*burn_pubkey)(const uint8_t *key, size_t len, uint8_t index);
  boot_status_t (*set_protection_bits)(uint32_t bitmask);
  boot_status_t (*enable_secure_boot)(void);
  boot_status_t (*enable_flash_encryption)(void);
} keystore_hal_t;

#define TOOB_KEYSTORE_HAL_V3(init_, deinit_, read_pubkey_, read_dslc_, write_dslc_, ...) \
    { .abi_version = TOOB_HAL_ABI_V3,                                      \
      .init        = (init_),                                              \
      .deinit      = (deinit_),                                            \
      .read_pubkey = (read_pubkey_),                                       \
      .read_dslc   = (read_dslc_),                                         \
      .write_dslc  = (write_dslc_),                                        \
      __VA_ARGS__ }

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
  boot_status_t (*verify_signature)(
      const uint8_t *message, size_t msg_len,
      const uint8_t *sig, const uint8_t *pubkey);
  boot_status_t (*verify_pqc)(
      const uint8_t *message, size_t msg_len,
      const uint8_t *sig, size_t sig_len,
      const uint8_t *pubkey, size_t pubkey_len);

  /* RNG */
  /**
   * @brief Generate cryptographic random bytes.
   * HAL-Contract: Die Implementierung MUSS NIST SP 800-90B
   * Repetition Count und Adaptive Proportion Tests intern
   * durchführen. Bei Versagen: BOOT_ERR_CRYPTO zurückgeben.
   */
  boot_status_t (*random)(uint8_t *buf, size_t len);

  uint32_t (*get_last_vendor_error)(void);

  /* Hardware Roots (eFuse / OTP) */
  boot_status_t (*read_pubkey)(uint8_t *key, size_t key_len, uint8_t key_index);
  boot_status_t (*read_chip_uid)(uint8_t *buf, size_t max_len, size_t *out_len);
  boot_status_t (*read_dslc)(uint8_t *buffer, size_t *len);
  boot_status_t (*write_dslc)(const uint8_t *value, size_t len);
  /**
   * @brief Read hardware monotonic counter.
   * HAL-Contract: Die Implementierung MUSS den gelesenen Wert intern
   * durch Komplement-Prüfung (read + read_inverted) validieren und
   * bei Diskrepanz BOOT_ERR_VERIFY zurückgeben.
   */
  boot_status_t (*read_monotonic_counter)(uint32_t *ctr);
  boot_status_t (*advance_monotonic_counter)(void);

  size_t (*get_hash_ctx_size)(void);
  bool has_hw_acceleration;
  bool (*is_pqc_enforced)(void); /* Hardware profile enforces PQC */
  boot_status_t (*verify_signature_ph)(
      const uint8_t *msg_digest,
      const uint8_t *sig, const uint8_t *pubkey);
} crypto_hal_t;

/**
 * @brief Initializer for crypto_hal_t (REG-033).
 * Positional: 8 core primitives (init..get_hash_ctx_size).
 * OTP accessors, PQC, and vendor-error via trailing designated initializers.
 */
#define TOOB_CRYPTO_HAL_V2(init_, deinit_, hash_init_, hash_update_,        \
                           hash_finish_, verify_sig_, random_,              \
                           get_hash_ctx_size_, ...)                         \
    { .abi_version        = TOOB_HAL_ABI_V2,                               \
      .init               = (init_),                                       \
      .deinit             = (deinit_),                                     \
      .hash_init          = (hash_init_),                                  \
      .hash_update        = (hash_update_),                                \
      .hash_finish        = (hash_finish_),                                \
      .verify_signature   = (verify_sig_),                                 \
      .random             = (random_),                                     \
      .get_hash_ctx_size  = (get_hash_ctx_size_),                          \
      __VA_ARGS__ }

#define TOOB_CRYPTO_HAL_V3(init_, deinit_, hash_init_, hash_update_,        \
                           hash_finish_, verify_sig_,                       \
                           get_hash_ctx_size_, ...)                         \
    { .abi_version        = TOOB_HAL_ABI_V3,                               \
      .init               = (init_),                                       \
      .deinit             = (deinit_),                                     \
      .hash_init          = (hash_init_),                                  \
      .hash_update        = (hash_update_),                                \
      .hash_finish        = (hash_finish_),                                \
      .verify_signature   = (verify_sig_),                                 \
      .get_hash_ctx_size  = (get_hash_ctx_size_),                          \
      __VA_ARGS__ }

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

/** @brief Initializer for clock_hal_t (REG-033). All 5 fields mandatory. */
#define TOOB_CLOCK_HAL_V2(init_, deinit_, get_tick_ms_, delay_ms_,          \
                           get_reset_reason_, ...)                           \
    { .abi_version      = TOOB_HAL_ABI_V2,                                 \
      .init             = (init_),                                         \
      .deinit           = (deinit_),                                       \
      .get_tick_ms      = (get_tick_ms_),                                  \
      .delay_ms         = (delay_ms_),                                     \
      .get_reset_reason = (get_reset_reason_),                             \
      __VA_ARGS__ }

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

/** @brief Initializer for console_hal_t (REG-033). All 5 fields mandatory. */
#define TOOB_CONSOLE_HAL_V2(init_, deinit_, putchar_, getchar_, flush_, ...)\
    { .abi_version = TOOB_HAL_ABI_V2,                                      \
      .init    = (init_),                                                  \
      .deinit  = (deinit_),                                                \
      .putchar = (putchar_),                                               \
      .getchar = (getchar_),                                               \
      .flush   = (flush_),                                                 \
      __VA_ARGS__ }

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
  
  /* Cache und Interrupt Isolation für P10 (XIP) und Glitch Traps */
  void (*invalidate_icache)(void);
  void (*disable_interrupts)(void);

  /* 
   * Mechanischer Recovery-Pin (Anti-Softbrick) Evaluator (concept_fusion.md Z.117).
   * MUSS von der Hardware mit einer Debounce-Zeit (z.B. >= 500ms) ausgewertet werden!
   */
  bool (*get_recovery_pin_state)(void);

  /**
   * @brief Power-Cycle-Resiliente RTC-Backup Register.
   * HAL-Contract: Werte MÜSSEN über Brownout/Software-Reset hinweg
   * erhalten bleiben. Bei Hardware ohne RTC-Backup: NULL setzen.
   */
  boot_status_t (*read_rtc_backup)(uint8_t slot, uint32_t *value);
  boot_status_t (*write_rtc_backup)(uint8_t slot, uint32_t value);

  uint32_t min_battery_mv;

  /**
   * @brief Optional swap progress notifier callback.
   * Called by the Core swap loop when progress changes or state transitions.
   * Contract: MUST be non-blocking (< 1ms execution budget) and fail-safe.
   */
  toob_swap_notify_fn swap_notify;
} soc_hal_t;

/**
 * @brief Initializer for soc_hal_t (REG-033).
 * Positional: init, deinit only (the only universal SOC primitives).
 * All other fields vary wildly between targets.
 */
#define TOOB_SOC_HAL_V2(init_, deinit_, ...)                               \
    { .abi_version = TOOB_HAL_ABI_V2,                                      \
      .init   = (init_),                                                   \
      .deinit = (deinit_),                                                 \
      __VA_ARGS__ }

/* --- 8. Provisioning HAL (Factory & Lifecycle) --- */

/**
 * @brief Factory Provisioning and Key-Lock Interface
 * Extracted from crypto_hal_t to enforce separation of concerns and
 * ensure that normal firmware cannot accidentally write eFuses.
 */
typedef struct {
    boot_status_t (*burn_pubkey)(const uint8_t *key, size_t len, uint8_t index);
    boot_status_t (*write_dslc)(uint8_t value);
    boot_status_t (*set_protection_bits)(uint32_t bitmask);
    boot_status_t (*enable_secure_boot)(void);
    boot_status_t (*enable_flash_encryption)(void);
} provisioning_hal_t;

/* --- Master Platform Container --- */

/**
 * @brief Aggregation of all HAL Pointers.
 *
 * HAL-CONTRACT: boot_platform_t ist der EINZIGE zulässige Hardware- und Peripherie-Zugang
 * für den Toob-Boot Core (toobloader/core/) und Stage 0 (toobloader/stage0/).
 * Kein Code außerhalb der HAL-Implementierung (hal/ bzw. test/host/) darf direkt auf
 * MMIO-Register, volatile Hardware-Adressen oder herstellerspezifische SDK-Funktionen zugreifen.
 * Diese Invariante wird durch das Test-Script scripts/check_mmio_isolation.ps1 erzwungen.
 *
 * Instantiated natively by the Host/Sandbox or target Vendor startup sequence.
 */
typedef struct {
  const flash_hal_t *flash;     /**< PFLICHT */
  const confirm_hal_t *confirm; /**< PFLICHT */
  const crypto_hal_t *crypto;   /**< PFLICHT */
  const clock_hal_t *clock;     /**< PFLICHT */
  const wdt_hal_t *wdt;         /**< PFLICHT */
  const console_hal_t *console;           /**< Optional */
  const soc_hal_t *soc;                   /**< Optional */
  const provisioning_hal_t *provisioning; /**< Optional */
  const slot_caps_t *slot_caps;           /**< Optional, added in ST-015 */
  const entropy_hal_t *entropy;           /**< Optional in v2, PFLICHT in v3 */
  const keystore_hal_t *keystore;         /**< Optional in v2, PFLICHT in v3 */
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

/**
 * @brief Architecture-Routing for HardFaults (NMI)
 * HALs MÜSSEN diese Funktion in ihrem HardFault_Handler aufrufen, wenn 
 * ein ECC-Rot detektiert wurde (anstatt ins Leere zu loopen).
 */
extern void toob_ecc_trap(void);

/* --- Crypto HAL Generic Symbols --- */
boot_status_t toob_crypto_hal_init(void);
void toob_crypto_hal_deinit(void);
boot_status_t toob_crypto_hal_hash_init(void *ctx, size_t ctx_size);
boot_status_t toob_crypto_hal_hash_update(void *ctx, const void *data, size_t len);
boot_status_t toob_crypto_hal_hash_finish(void *ctx, uint8_t *digest, size_t *digest_len);
boot_status_t toob_crypto_hal_verify_signature(const uint8_t *message, size_t msg_len, const uint8_t *sig, const uint8_t *pubkey);
boot_status_t toob_crypto_hal_verify_pqc(const uint8_t *message, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);
boot_status_t toob_crypto_hal_verify_signature_ph(const uint8_t *msg_digest, const uint8_t *sig, const uint8_t *pubkey);
size_t toob_crypto_hal_get_hash_ctx_size(void);
bool toob_crypto_hal_is_pqc_enforced(void);

#endif /* TOOB_BOOT_HAL_H */
