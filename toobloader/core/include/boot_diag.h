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
 * @brief Transfers security and identity metadata from the SUIT manifest.
 * @param svn The Current Security Version Number.
 * @param key_idx The eFuse Epoch Index of the active key.
 * @param sbom_hash The 32-byte SHA-256 digest of the SBOM.
 */
void boot_diag_set_security_meta(uint32_t svn, uint32_t key_idx, const uint8_t *sbom_hash);

/**
 * @brief Sets the amount of encountered edge recovery attempts.
 * @param count The current boot_failure_count from the WAL/TMR.
 */
void boot_diag_set_recovery_events(uint32_t count);

/**
 * @brief Records the sliding window flash wear leveling counters.
 * @param wear_stats Pointer to the extracted wear statistics.
 */
void boot_diag_set_wear_data(const toob_ext_health_t *wear_stats);

/**
 * @brief Calculates the CRC-32 trailer and mathematically seals the payload.
 * Must be the last call before jumping to the Feature-OS.
 */
void boot_diag_seal(void);

#endif /* TOOB_BOOT_DIAG_H */
