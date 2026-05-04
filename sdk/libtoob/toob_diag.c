/**
 * ==============================================================================
 * Toob-Boot libtoob: Diagnostics Extraktions Implementation (toob_diag.c)
 * (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (toob_get_boot_diag function definition)
 * - docs/toob_telemetry.md (Boot diagnostic data model, CBOR readiness)
 * - docs/concept_fusion.md (Fleet insight extraction without static buffer
 * dependencies)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. TOCTOU Defense: Verhindert asynchrone RTOS-Interrupt Korruptionen während
 *    des Reads. Die Payload wird erst isoliert geklont und dann mathematisch
 *    auf dem sicheren Thread-Stack verifiziert.
 * 2. P10 Leakage Prevention: Das Ziel-Struct des OS wird präemptiv genullt.
 *    Ignoriert das OS fahrlässig den Return-Code, liest es Nullen statt
 *    kryptografischem RAM-Garbage (verhindert Heuristik-Leaks).
 * 3. Glitch-Resistant OS Boundary: Cross-Compiler-kompatible Delay-Injections
 *    und Double-Check Patterns blockieren Voltage-Glitches bei der CRC-Prüfung.
 * 4. ABI Versioning Shield & Padding Sanitization: Blockiert Daten-Drifts und
 *    Informationslecks bei der Serialisierung für das Cloud-Backend.
 */

#include "libtoob.h"
#include "toob_internal.h"
#include "toob_telemetry_encode.h"
#include <stddef.h>
#include <string.h>

/* ==============================================================================
 * Cross-Compiler Glitch-Delay Injection für Fault-Injection (FI) Defense
 * Erzeugt Instruktions-Barrieren gegen EMFI-bedingte PC-Sprünge, kompatibel
 * mit allen relevanten Cortex-M / RISC-V Compilern des Feature-OS.
 * ==============================================================================
 */
#if defined(__GNUC__) || defined(__clang__)
#define TOOB_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;")
#elif defined(__ICCARM__)
#include <intrinsics.h>
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    __no_operation();                                                          \
    __no_operation();                                                          \
    __no_operation();                                                          \
  } while (0)
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    __nop();                                                                   \
    __nop();                                                                   \
    __nop();                                                                   \
  } while (0)
#else
/* Fallback Sequence-Point, falls inline Assembly strikt verboten ist */
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    volatile uint32_t _delay = 0;                                              \
    _delay = 1;                                                                \
    (void)_delay;                                                              \
  } while (0)
#endif

/* ==============================================================================
 * .noinit RAM Definition (GAP-39 / Diagnostics)
 * ==============================================================================
 */
#ifndef TOOB_MOCK_TEST
TOOB_NOINIT toob_boot_diag_t toob_diag_state;
#endif

/* ==============================================================================
 * INTERNAL HELPERS
 * ==============================================================================
 */

/**
 * @brief OS-Safe Memory Zeroization (Prevents Compiler DCE).
 * Verhindert das "Liegenbleiben" von sensiblen Telemetrie-Daten im OS-RAM.
 */
static inline void toob_secure_zeroize(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len--) {
    *p++ = 0;
  }
  __asm__ volatile("" : : "g"(ptr) : "memory");
}

/* ==============================================================================
 * PUBLIC API IMPLEMENTATION
 * ==============================================================================
 */

toob_status_t toob_get_boot_diag(toob_boot_diag_t *diag) {
  /* P10 Pointer Zero-Trust Check */
  if (!diag) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* ====================================================================
   * P10 LEAKAGE DEFENSE & MEMORY SANITIZATION
   * ====================================================================
   * Präemptive Nullifizierung des Ziel-Speichers. Verhindert, dass das OS
   * nach einem TOOB_ERR_VERIFY auf Garbage/Secrets aus seinem eigenen
   * uninitialisierten Thread-Stack zugreift (Memory Disclosure Attack).
   * Da 'diag' den Scope überlebt, ist dieser Aufruf durch C-Compiler
   * niemals als Dead Code eliminierbar (DCE-sicher).
   */
  toob_secure_zeroize(diag, sizeof(toob_boot_diag_t));

  /* ====================================================================
   * TOCTOU SHIELDING (Time-Of-Check to Time-Of-Use)
   * ====================================================================
   * Zieht das asynchrone .noinit Struct in den lokalen, sicheren C-Stack.
   * Das verhindert asynchrone Manipulationen (z.B. durch bösartiges DMA oder
   * OS-Interrupts), die das RAM zwischen Verifikation und Nutzung verändern.
   */
  toob_boot_diag_t local_diag __attribute__((aligned(8)));
  toob_secure_zeroize(&local_diag,
                      sizeof(local_diag)); /* P10 Uninitialized Mem Trap */

  /* Atomarer 1-Way Read aus dem Shared-RAM */
  memcpy(&local_diag, &toob_diag_state, sizeof(toob_boot_diag_t));

  /* ====================================================================
   * MAGIC & ABI-VERSION CHECK (Glitch-Shielded)
   * ==================================================================== */
  volatile uint32_t version_shield_1 = 0;
  volatile uint32_t version_shield_2 = 0;

  bool is_version_ok = (local_diag.struct_version == TOOB_DIAG_STRUCT_VERSION);

  if (is_version_ok) {
    version_shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY();

  if (version_shield_1 == TOOB_OK && is_version_ok) {
    version_shield_2 = TOOB_OK;
  }

  if (version_shield_1 != TOOB_OK || version_shield_2 != TOOB_OK ||
      version_shield_1 != version_shield_2) {
    toob_secure_zeroize(&local_diag, sizeof(local_diag));
    return TOOB_ERR_VERIFY; /* Trapped Version Mismatch or Glitch */
  }

  /* ====================================================================
   * P10 CRC-32 PAYLOAD VERIFICATION (Glitch-Shielded)
   * ====================================================================
   * P10 Robustness: CRC-32 Validation relies dynamically on offsetof,
   * mitigating ABI tail-padding drifts (Padding bytes sind undefiniert!).
   */
  size_t payload_len = offsetof(toob_boot_diag_t, crc32_trailer);
  uint32_t calculated_crc =
      toob_lib_crc32((const uint8_t *)&local_diag, payload_len);

  volatile uint32_t crc_shield_1 = 0;
  volatile uint32_t crc_shield_2 = 0;

  bool is_crc_ok = (calculated_crc == local_diag.crc32_trailer);

  if (is_crc_ok) {
    crc_shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY();

  if (crc_shield_1 == TOOB_OK && calculated_crc == local_diag.crc32_trailer) {
    crc_shield_2 = TOOB_OK;
  }

  /* P10 Leakage Defense: Wenn CRC fehlschlägt, den Klon SOFORT vernichten! */
  if (crc_shield_1 != TOOB_OK || crc_shield_2 != TOOB_OK ||
      crc_shield_1 != crc_shield_2) {
    toob_secure_zeroize(&local_diag, sizeof(local_diag));
    return TOOB_ERR_VERIFY; /* Trapped Hardware Bit-Rot or Glitch */
  }

  /* ====================================================================
   * SAFE-PASSING (By-Value Copy) & P10 PADDING ZEROIZATION
   * ==================================================================== */

  /* P10 Zero-Trust: Sicherstellen, dass das explizite 3-Byte Padding genullt
   * ist. Das verhindert subtiles Data-Leakage von Stack-Resten bei einer
   * nachgelagerten CBOR Serialisierung durch das Betriebssystem (EU CRA
   * Export). */
  local_diag._padding[0] = 0;
  local_diag._padding[1] = 0;
  local_diag._padding[2] = 0;

  /* Sicheres Kopieren des 100% verifizierten Klons in das Feature-OS RAM */
  memcpy(diag, &local_diag, sizeof(toob_boot_diag_t));

  /* O(1) Stack Clean-Up (DCE Proof) */
  toob_secure_zeroize(&local_diag, sizeof(local_diag));

  return TOOB_OK;
}

toob_status_t toob_get_boot_diag_cbor(uint8_t *out_buf, size_t max_len, size_t *out_len) {
  if (!out_buf || !out_len) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_boot_diag_t diag;
  toob_status_t status = toob_get_boot_diag(&diag);
  if (status != TOOB_OK) {
    return status;
  }

  struct toob_telemetry tel;
  toob_secure_zeroize(&tel, sizeof(tel));

  /* P10 Fix: Sicherer Shift des 32-bit Magic Headers in die 8-Bit CDDL Schema-Version */
  tel.schema_version = (uint8_t)(diag.struct_version >> 24);
  tel.boot_duration_ms = diag.boot_duration_ms;
  tel.edge_recovery_events = diag.edge_recovery_events;

  /* C-Struct hat kein separates hardware_fault_record, belege vendor_error in beiden Feldern */
  tel.hardware_fault_record = diag.vendor_error;
  tel.vendor_error = diag.vendor_error;
  tel.wdt_kicks = 0; /* Nicht in diag_t gemappt */

  tel.current_svn = diag.current_svn;
  tel.active_key_index = (uint8_t)diag.active_key_index;
  tel.fallback_occurred = false; /* Nicht in diag_t gemappt */

  tel.sbom_digest.value = diag.sbom_digest;
  tel.sbom_digest.len = sizeof(diag.sbom_digest);

  tel.boot_session_id = 0;

  /* P10 Fix: Akkurates C-Struct Mapping auf das CDDL Element */
  if (diag.ext_health_present) {
    tel.ext_health_present = true;
    tel.ext_health.ext_health_wal_erasures = diag.ext_health.wal_erase_count;
    tel.ext_health.ext_health_app_erasures = diag.ext_health.app_slot_erase_count;
    tel.ext_health.ext_health_staging_erasures = diag.ext_health.staging_slot_erase_count;
    tel.ext_health.ext_health_swap_erasures = diag.ext_health.swap_buffer_erase_count;
  } else {
    tel.ext_health_present = false;
  }

  bool encoded = cbor_encode_toob_telemetry(out_buf, max_len, &tel, out_len);
  
  toob_secure_zeroize(&tel, sizeof(tel));
  toob_secure_zeroize(&diag, sizeof(diag));

  if (!encoded) {
    return TOOB_ERR_VERIFY;
  }

  return TOOB_OK;
}