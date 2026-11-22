/**
 * @file toob_diag.c
 * @brief Boot Diagnostics — telemetry extraction and TDR1 wire serialization.
 *
 * Extracts toob_boot_diag_t from .noinit shared RAM with TOCTOU defense,
 * glitch-hardened double-read CRC-32 validation, and deterministic Little-Endian
 * TDR1 binary wire encoding for cloud check-in submission.
 */

#include "libtoob.h"
#include "toob_internal.h"
#include <stddef.h>
#include <string.h>

/* ==============================================================================
 * .noinit RAM Definition (GAP-39 / CRIT-26)
 * ============================================================================== */
#ifndef TOOB_MOCK_TEST
TOOB_NOINIT_VAR(toob_diag_state) toob_boot_diag_t toob_diag_state;
#endif

static void _volatile_snapshot_diag(toob_boot_diag_t *dst) {
  const volatile uint8_t *src =
      (const volatile uint8_t *)&toob_diag_state;
  uint8_t *out = (uint8_t *)dst;
  for (size_t i = 0U; i < sizeof(toob_boot_diag_t); i++) {
    out[i] = src[i];
  }
}

static bool _verify_diag_snapshot(const toob_boot_diag_t *d) {
  if (d->struct_version != TOOB_DIAG_STRUCT_VERSION) {
    return false;
  }
  size_t payload_len = offsetof(toob_boot_diag_t, crc32_trailer);
  uint32_t calc_crc = toob_lib_crc32((const uint8_t *)d, payload_len);
  return (calc_crc == d->crc32_trailer);
}

/* ==============================================================================
 * PUBLIC API IMPLEMENTATION
 * ============================================================================== */

toob_status_t toob_get_boot_diag(toob_boot_diag_t *diag) {
  if (!diag) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Snapshot 1 directly into caller buffer + single stack local_diag_2 (-136B stack, TDR1-07).
   * On any validation or glitch cross-check mismatch, diag is zeroized before return. */
  toob_boot_diag_t local_diag_2 __attribute__((aligned(8)));
  toob_secure_zeroize(diag, sizeof(toob_boot_diag_t));
  toob_secure_zeroize(&local_diag_2, sizeof(local_diag_2));

  _volatile_snapshot_diag(diag);

  volatile uint32_t shield_1 = 0U;
  volatile uint32_t shield_2 = 0U;

  if (_verify_diag_snapshot(diag)) {
    shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY();

  _volatile_snapshot_diag(&local_diag_2);

  if (shield_1 == TOOB_OK && _verify_diag_snapshot(&local_diag_2) &&
      toob_ct_memcmp_glitch_safe((const uint8_t *)diag,
                                 (const uint8_t *)&local_diag_2,
                                 offsetof(toob_boot_diag_t, _padding_end)) == TOOB_OK) {
    shield_2 = TOOB_OK;
  }

  toob_secure_zeroize(&local_diag_2, sizeof(local_diag_2));

  if (shield_1 != TOOB_OK || shield_2 != TOOB_OK || shield_1 != shield_2) {
    toob_secure_zeroize(diag, sizeof(toob_boot_diag_t));
    return TOOB_ERR_VERIFY;
  }

  /* MED-24: Sanitize ALL padding regions before exposing to caller RAM. */
  memset(diag->_padding_v3, 0, sizeof(diag->_padding_v3));
  memset(diag->_padding, 0, sizeof(diag->_padding));
  memset(diag->_padding_end, 0, sizeof(diag->_padding_end));
  return TOOB_OK;
}

toob_status_t toob_get_boot_diag_wire_seq(uint8_t *out_buf,
                                          size_t max_len,
                                          uint64_t checkin_seq,
                                          size_t *out_len) {
  if (out_len != NULL) {
    *out_len = 0U;
  }
  if (!out_buf || !out_len || max_len < TOOB_TDR1_MIN_FRAME_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_boot_diag_t diag __attribute__((aligned(8)));
  toob_status_t status = toob_get_boot_diag(&diag);
  if (status != TOOB_OK) {
    toob_secure_zeroize(&diag, sizeof(diag));
    return status;
  }

  /* TDR1-05 / TDR1-06: Fail closed if .noinit handoff is corrupted or out of domain. */
  toob_handoff_t handoff __attribute__((aligned(8)));
  status = toob_get_handoff(&handoff);
  if (status != TOOB_OK) {
    toob_secure_zeroize(&diag, sizeof(diag));
    toob_secure_zeroize(&handoff, sizeof(handoff));
    return status;
  }

  bool part_ok = (handoff.booted_partition == (uint32_t)TOOB_PARTITION_APP ||
                  handoff.booted_partition == (uint32_t)TOOB_PARTITION_RECOVERY);
  bool domain_ok = part_ok &&
                   (handoff.active_slot <= 1U) &&
                   (handoff.reset_reason <= TOOB_TDR1_MAX_RESET_REASON) &&
                   (diag.active_key_index <= 0xFFFFU) &&
                   (diag.last_update_outcome <= TOOB_TDR1_MAX_OUTCOME);
  if (!domain_ok) {
    toob_secure_zeroize(&diag, sizeof(diag));
    toob_secure_zeroize(&handoff, sizeof(handoff));
    return TOOB_ERR_VERIFY;
  }

  bool has_ext = (diag.ext_health_present != 0U);
  size_t total_len = has_ext ? TOOB_TDR1_MAX_SIZE : TOOB_TDR1_MIN_FRAME_SIZE;
  if (max_len < total_len) {
    toob_secure_zeroize(&diag, sizeof(diag));
    toob_secure_zeroize(&handoff, sizeof(handoff));
    return TOOB_ERR_INVALID_ARG;
  }

  uint8_t wire_part = (handoff.booted_partition == (uint32_t)TOOB_PARTITION_RECOVERY)
                          ? TOOB_TDR1_PARTITION_RECOVERY
                          : TOOB_TDR1_PARTITION_APP;
  uint8_t wire_boot_state = (handoff.magic == TOOB_STATE_TENTATIVE)
                                ? TOOB_TDR1_BOOT_STATE_TENTATIVE
                                : TOOB_TDR1_BOOT_STATE_COMMITTED;
  uint16_t flags = has_ext ? TOOB_TDR1_FLAG_EXT_HEALTH : 0U;

  memset(out_buf, 0, total_len);
  toob_wire_put_le32(&out_buf[0], TOOB_TDR1_MAGIC);
  out_buf[4] = TOOB_TDR1_VERSION;
  out_buf[5] = wire_part;
  toob_wire_put_le16(&out_buf[6], flags);
  toob_wire_put_le16(&out_buf[8], TOOB_TDR1_HDR_SIZE);
  out_buf[10] = (uint8_t)(diag.struct_version >> 24U);
  out_buf[11] = wire_boot_state;
  out_buf[12] = handoff.active_slot;
  out_buf[13] = (uint8_t)handoff.reset_reason;
  out_buf[14] = (diag.fallback_occurred != 0U) ? 1U : 0U;
  out_buf[15] = (handoff.wipe_requested != 0U) ? 1U : 0U;
  out_buf[16] = diag.last_update_outcome;
  out_buf[17] = diag.last_update_reject;
  toob_wire_put_le16(&out_buf[18], (uint16_t)diag.active_key_index);
  toob_wire_put_le16(&out_buf[20], diag.reader_major);
  toob_wire_put_le16(&out_buf[22], diag.reader_minor);
  toob_wire_put_le16(&out_buf[24], diag.fw_ver_major);
  toob_wire_put_le16(&out_buf[26], diag.fw_ver_minor);
  toob_wire_put_le16(&out_buf[28], diag.fw_ver_patch);
  toob_wire_put_le16(&out_buf[30], 0U);
  toob_wire_put_le64(&out_buf[32], checkin_seq);
  toob_wire_put_le32(&out_buf[40], diag.current_svn);
  toob_wire_put_le32(&out_buf[44], diag.build_number);
  toob_wire_put_le32(&out_buf[48], diag.installed_app_svn);
  toob_wire_put_le32(&out_buf[52], diag.installed_stage1_svn);
  toob_wire_put_le32(&out_buf[56], diag.monotonic_counter);
  toob_wire_put_le32(&out_buf[60], diag.boot_duration_ms);
  toob_wire_put_le32(&out_buf[64], diag.verify_time_ms);
  toob_wire_put_le32(&out_buf[68], diag.last_error_code);
  toob_wire_put_le32(&out_buf[72], diag.vendor_error);
  toob_wire_put_le32(&out_buf[76], diag.hardware_fault_record);
  toob_wire_put_le32(&out_buf[80], diag.edge_recovery_events);
  toob_wire_put_le32(&out_buf[84], handoff.boot_failure_count);
  toob_wire_put_le32(&out_buf[88], handoff.net_search_accum_ms);
  toob_wire_put_le32(&out_buf[92], diag.wdt_kicks);
  memcpy(&out_buf[96], diag.sbom_digest, sizeof(diag.sbom_digest));
  toob_wire_put_le32(&out_buf[128], diag.boot_session_id);

  if (has_ext) {
    toob_wire_put_le32(&out_buf[132], diag.ext_health.wal_erase_count);
    toob_wire_put_le32(&out_buf[136], diag.ext_health.app_slot_erase_count);
    toob_wire_put_le32(&out_buf[140], diag.ext_health.staging_slot_erase_count);
    toob_wire_put_le32(&out_buf[144], diag.ext_health.swap_buffer_erase_count);
  }

  toob_secure_zeroize(&diag, sizeof(diag));
  toob_secure_zeroize(&handoff, sizeof(handoff));

  size_t crc_off = total_len - TOOB_TDR1_CRC_TRAILER_SIZE;
  uint32_t crc = toob_lib_crc32(out_buf, crc_off);
  toob_wire_put_le32(&out_buf[crc_off], crc);

  *out_len = total_len;
  return TOOB_OK;
}

toob_status_t toob_get_boot_diag_wire(uint8_t *out_buf, size_t max_len, size_t *out_len) {
  return toob_get_boot_diag_wire_seq(out_buf, max_len, 0ULL, out_len);
}
