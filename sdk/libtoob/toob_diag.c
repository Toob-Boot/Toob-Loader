/**
 * @file toob_diag.c
 * @brief Boot Diagnostics — telemetry extraction and diag struct management.
 *
 * Extracts toob_boot_diag_t from .noinit shared RAM with TOCTOU defense,
 * CRC-32 validation, and CBOR telemetry encoding for cloud submission.
 */

#include "libtoob.h"
#include "toob_internal.h"
#include "toob_telemetry_encode.h"
#include <stddef.h>
#include <string.h>

/* ==============================================================================
 * .noinit RAM Definition (GAP-39 / Diagnostics)
 * ============================================================================== */
#ifndef TOOB_MOCK_TEST
TOOB_NOINIT toob_boot_diag_t toob_diag_state;
#endif

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
  tel.toob_telemetry_uint0uint = (uint8_t)(diag.struct_version >> 24);
  tel.toob_telemetry_uint1uint = diag.boot_duration_ms;
  tel.toob_telemetry_uint2uint = diag.edge_recovery_events;

  tel.toob_telemetry_uint3uint = diag.hardware_fault_record;
  tel.toob_telemetry_uint4uint = diag.vendor_error;
  tel.toob_telemetry_uint5uint = diag.wdt_kicks;

  tel.toob_telemetry_uint6uint = diag.current_svn;
  tel.toob_telemetry_uint7uint = (uint8_t)diag.active_key_index;

  tel.toob_telemetry_uint8bool = (diag.fallback_occurred != 0);

  tel.toob_telemetry_uint9bstr.value = diag.sbom_digest;
  tel.toob_telemetry_uint9bstr.len = sizeof(diag.sbom_digest);

  tel.toob_telemetry_uint11uint = diag.boot_session_id;

  /* P10 Fix: Akkurates C-Struct Mapping auf das CDDL Element */
  if (diag.ext_health_present) {
    tel.toob_telemetry_ext_health_m_present = true;
    tel.toob_telemetry_ext_health_m.toob_telemetry_ext_health_m.ext_health_uint101uint = diag.ext_health.wal_erase_count;
    tel.toob_telemetry_ext_health_m.toob_telemetry_ext_health_m.ext_health_uint102uint = diag.ext_health.app_slot_erase_count;
    tel.toob_telemetry_ext_health_m.toob_telemetry_ext_health_m.ext_health_uint103uint = diag.ext_health.staging_slot_erase_count;
    tel.toob_telemetry_ext_health_m.toob_telemetry_ext_health_m.ext_health_uint104uint = diag.ext_health.swap_buffer_erase_count;
  } else {
    tel.toob_telemetry_ext_health_m_present = false;
  }

  bool encoded = cbor_encode_toob_telemetry(out_buf, max_len, &tel, out_len);
  
  toob_secure_zeroize(&tel, sizeof(tel));
  toob_secure_zeroize(&diag, sizeof(diag));

  if (!encoded) {
    return TOOB_ERR_VERIFY;
  }

  return TOOB_OK;
}