/**
 * @file boot_diag.h
 * @brief Boot Diagnostics and Telemetry Accumulation
 *
 * This module is responsible for accumulating boot metadata (timings, errors,
 * security revisions, wear data) into the `.noinit` shared memory section
 * `toob_diag_state`. This ensures that the Feature-OS (via libtoob) can extract
 * the CBOR telemetry package for fleet management.
 */

#ifndef TOOB_BOOT_DIAG_H
#define TOOB_BOOT_DIAG_H

#include "boot_types.h"

/**
 * @brief Zeroizes the diagnostic state to prevent information leakage from
 * previous boot cycles, and initializes the ABI struct version.
 */
void boot_diag_init(void);

/**
 * @brief Accumulates the cryptographic verification timing. Can be called
 * multiple times (e.g., across multi-image verification).
 * @param time_ms The time taken for verification in milliseconds.
 */
void boot_diag_add_verify_time(uint32_t time_ms);

/**
 * @brief Sets the total boot duration immediately before the OS handoff.
 * @param time_ms Total boot time in milliseconds.
 */
void boot_diag_set_boot_time(uint32_t time_ms);

/**
 * @brief Records the last error state and an optional vendor-specific code.
 * @param error The generic bootloader error (e.g., BOOT_ERR_WDT_TRIGGER).
 * @param vendor_fault The HAL/vendor-specific flash/hardware error code.
 */
void boot_diag_set_error(boot_status_t error, uint32_t vendor_fault);

/**
 * @brief Transfers security and identity metadata from the TBM1 manifest.
 * @param svn The Current Security Version Number.
 * @param key_idx The eFuse Epoch Index of the active key.
 * @param sbom_hash The 32-byte SHA-256 digest of the SBOM.
 * @param build_number CI build number.
 * @param fw_ver_major Semantic version major.
 * @param fw_ver_minor Semantic version minor.
 * @param fw_ver_patch Semantic version patch.
 */
void boot_diag_set_security_meta(uint32_t svn, uint32_t key_idx, const uint8_t *sbom_hash,
                                 uint32_t build_number, uint16_t fw_ver_major,
                                 uint16_t fw_ver_minor, uint16_t fw_ver_patch);

/**
 * @brief Sets the amount of encountered edge recovery attempts.
 * @param count The current boot_failure_count from the WAL/TMR.
 */
void boot_diag_set_recovery_events(uint32_t count);

/**
 * @brief Sets the platform system telemetry status (watchdog kicks, fallback mode, session ID).
 * @param wdt_kicks Total watchdog kicks in this boot cycle.
 * @param fallback 1 if fallback/recovery OS is booted, 0 otherwise.
 * @param session_id Monotonic boot session ID from journal.
 */
void boot_diag_set_system_status(uint32_t wdt_kicks, bool fallback, uint32_t session_id);

/**
 * @brief Records the sliding window flash wear leveling counters.
 * @param wear_stats Pointer to the extracted wear statistics.
 */
void boot_diag_set_wear_data(const toob_ext_health_t *wear_stats);

/**
 * @brief Populates SVN fields from the TMR on every boot path (UPD-001).
 *
 * On an update boot, boot_diag_set_security_meta() has already written the
 * richer TBM1 data (svn, build, fw_ver, sbom). This setter acts as a
 * cold-start safety net: it only writes fields that are still zero, so
 * authoritative TBM1 values are never downgraded.
 *
 * @param app_svn      Current app SVN from TMR.
 * @param stage1_svn   Current Stage-1 SVN from TMR.
 * @param build_number CI build number (0 if unavailable from TMR).
 */
void boot_diag_set_installed_state(uint32_t app_svn, uint32_t stage1_svn,
                                   uint32_t build_number);

/**
 * @brief Sets the outcome and fine-grained reject reason of the last update (UPD-007).
 * @param outcome 0=none, 1=applied, 2=rejected, 3=reverted, 4=deferred.
 * @param reject_reason Fine-grained tbm1_reject_t error cause.
 */
void boot_diag_set_update_result(uint8_t outcome, uint8_t reject_reason);

/**
 * @brief Calculates the CRC-32 trailer and mathematically seals the payload.
 * Must be the last call before jumping to the Feature-OS.
 */
void boot_diag_seal(void);

#endif /* TOOB_BOOT_DIAG_H */
