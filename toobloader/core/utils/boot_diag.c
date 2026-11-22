/*
 * Toob-Boot Core File: boot_diag.c
 * Relevant Spec Files:
 * - docs/toob_telemetry.md (Structured Binary Telemetry, Wear Data, Diag-Struct)
 */

#include "boot_diag.h"
#include "boot_crc32.h"
#include "boot_secure_zeroize.h"
#include "boot_tbm1.h"
#include "boot_types.h"
#include <stddef.h>
#include <string.h>

_Static_assert(TBM1_VERSION_MAJOR == 2 && TBM1_VERSION_MINOR == 1,
               "TBM1 reader version drift in boot_diag");

#if defined(__GNUC__) || defined(__clang__) || defined(__ICCARM__)
#define BOOT_DIAG_ALIGN8 __attribute__((aligned(8)))
#elif defined(_MSC_VER)
#define BOOT_DIAG_ALIGN8 __declspec(align(8))
#else
#define BOOT_DIAG_ALIGN8
#endif

TOOB_NOINIT_VAR(toob_diag_state) BOOT_DIAG_ALIGN8 toob_boot_diag_t toob_diag_state;

void boot_diag_init(void) {
  boot_secure_zeroize(&toob_diag_state, sizeof(toob_boot_diag_t));
  toob_diag_state.struct_version = TOOB_DIAG_STRUCT_VERSION;
  toob_diag_state.reader_major = (uint16_t)TBM1_VERSION_MAJOR;
  toob_diag_state.reader_minor = (uint16_t)TBM1_VERSION_MINOR;
}

void boot_diag_add_verify_time(uint32_t time_ms) {
  if (UINT32_MAX - toob_diag_state.verify_time_ms < time_ms) {
    toob_diag_state.verify_time_ms = UINT32_MAX;
  } else {
    toob_diag_state.verify_time_ms += time_ms;
  }
}

void boot_diag_set_boot_time(uint32_t time_ms) {
  toob_diag_state.boot_duration_ms = time_ms;
}

void boot_diag_set_error(boot_status_t error, uint32_t vendor_fault) {
  toob_diag_state.last_error_code = (uint32_t)error;
  toob_diag_state.vendor_error = vendor_fault;
  toob_diag_state.hardware_fault_record = vendor_fault;
}

void boot_diag_set_system_status(uint32_t wdt_kicks, bool fallback, uint32_t session_id) {
  (void)wdt_kicks; /* UPD-009: Explicitly reserved field in Diag v3 */
  toob_diag_state.wdt_kicks = 0;
  toob_diag_state.fallback_occurred = fallback ? 1U : 0U;
  toob_diag_state.boot_session_id = session_id;
}

void boot_diag_set_security_meta(uint32_t svn, uint32_t key_idx, const uint8_t *sbom_hash,
                                 uint32_t build_number, uint16_t fw_ver_major,
                                 uint16_t fw_ver_minor, uint16_t fw_ver_patch) {
  toob_diag_state.current_svn = svn;
  toob_diag_state.active_key_index = key_idx;
  toob_diag_state.build_number = build_number;
  toob_diag_state.fw_ver_major = fw_ver_major;
  toob_diag_state.fw_ver_minor = fw_ver_minor;
  toob_diag_state.fw_ver_patch = fw_ver_patch;
  boot_secure_zeroize(toob_diag_state._padding_v3, sizeof(toob_diag_state._padding_v3));
  if (sbom_hash) {
    for (size_t i = 0; i < 32U; i++) {
      toob_diag_state.sbom_digest[i] = sbom_hash[i];
    }
  } else {
    boot_secure_zeroize(toob_diag_state.sbom_digest, 32U);
  }
}

void boot_diag_set_recovery_events(uint32_t count) {
  toob_diag_state.edge_recovery_events = count;
}

void boot_diag_set_wear_data(const toob_ext_health_t *wear_stats) {
  if (wear_stats) {
    toob_diag_state.ext_health_present = 1U;
    toob_diag_state.ext_health.wal_erase_count = wear_stats->wal_erase_count;
    toob_diag_state.ext_health.app_slot_erase_count = wear_stats->app_slot_erase_count;
    toob_diag_state.ext_health.staging_slot_erase_count = wear_stats->staging_slot_erase_count;
    toob_diag_state.ext_health.swap_buffer_erase_count = wear_stats->swap_buffer_erase_count;
  }
}

void boot_diag_set_installed_state(uint32_t app_svn, uint32_t stage1_svn, uint32_t build_number) {
  /* Guard: only fill fields that boot_diag_set_security_meta() hasn't
     * already populated from committed TBM1 data during an update boot. */
  if (toob_diag_state.current_svn == 0U) {
    toob_diag_state.current_svn = app_svn;
  }
  if (toob_diag_state.build_number == 0U) {
    toob_diag_state.build_number = build_number;
  }
  toob_diag_state.installed_app_svn = app_svn;
  toob_diag_state.installed_stage1_svn = stage1_svn;
  toob_diag_state.reader_major = (uint16_t)TBM1_VERSION_MAJOR;
  toob_diag_state.reader_minor = (uint16_t)TBM1_VERSION_MINOR;
}

void boot_diag_set_persisted_identity(uint32_t key_idx, uint32_t build_number,
                                      uint16_t fw_ver_major, uint16_t fw_ver_minor,
                                      uint16_t fw_ver_patch, uint32_t monotonic_counter) {
  toob_diag_state.monotonic_counter = monotonic_counter;
  /* Preserve candidate metadata only when an update just committed (outcome == 1). */
  if (toob_diag_state.last_update_outcome != 1U) {
    toob_diag_state.active_key_index = key_idx;
    toob_diag_state.build_number = build_number;
    toob_diag_state.fw_ver_major = fw_ver_major;
    toob_diag_state.fw_ver_minor = fw_ver_minor;
    toob_diag_state.fw_ver_patch = fw_ver_patch;
  }
}

void boot_diag_set_update_result(uint8_t outcome, uint8_t reject_reason) {
  toob_diag_state.last_update_outcome = outcome;
  toob_diag_state.last_update_reject = reject_reason;
}

boot_status_t boot_diag_seal(void) {
  toob_boot_diag_t local_diag BOOT_DIAG_ALIGN8;
  memcpy(&local_diag, &toob_diag_state, sizeof(toob_boot_diag_t));

  /* P10 Defense: Ensure internal alignment padding cannot leak stack/RAM fragments */
  boot_secure_zeroize(local_diag._padding_v3, sizeof(local_diag._padding_v3));
  boot_secure_zeroize(local_diag._padding, sizeof(local_diag._padding));
  boot_secure_zeroize(local_diag._padding_end, sizeof(local_diag._padding_end));

  size_t payload_len = offsetof(toob_boot_diag_t, crc32_trailer);
  uint32_t expected_crc = compute_boot_crc32((const uint8_t *)&local_diag, payload_len);
  local_diag.crc32_trailer = expected_crc;

  memcpy(&toob_diag_state, &local_diag, sizeof(toob_boot_diag_t));
  boot_secure_zeroize(&local_diag, sizeof(local_diag));

  /* TDR1-07: Read-back CRC-32 verification over .noinit RAM (matches handoff TOCTOU gate) */
  uint32_t ram_crc = compute_boot_crc32((const uint8_t *)&toob_diag_state, payload_len);
  if (ram_crc != expected_crc || toob_diag_state.crc32_trailer != expected_crc) {
    return BOOT_ERR_VERIFY;
  }
  return BOOT_OK;
}
