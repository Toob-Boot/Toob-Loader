#ifndef BOOT_ROLLBACK_H
#define BOOT_ROLLBACK_H

/*
 * Toob-Boot Core Header: boot_rollback.h
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md (OS Recovery nach Fehlversuch)
 * - docs/testing_requirements.md
 * - docs/libtoob_api.md
 */

#include "boot_types.h"
#include "boot_hal.h"
#include "boot_journal.h"

/**
 * @brief Hybrid SVN Verification.
 *        Evaluates if the requested manifest SVN respects the persistent limits.
 */
boot_status_t boot_rollback_verify_svn(const boot_platform_t *platform, uint32_t manifest_svn, bool is_recovery_os);

/**
 * @brief Evaluates the Crash-Cascade state based on M-JOURNAL Boot Failure Counter.
 *        Decides whether to boot Slot A (Normal), the Recovery_OS, invoke M-PANIC Rescue, or Exponential Backoff.
 */
boot_status_t boot_rollback_evaluate_os(const boot_platform_t *platform, const wal_tmr_payload_t *tmr, bool *boot_recovery_os_out);

/**
 * @brief Executes the physical reverse in-place overwrite.
 *        Used when an update immediately crashes after a TXN_COMMIT. Orchestrates `boot_swap_apply()` backwards.
 */
boot_status_t boot_rollback_trigger_revert(const boot_platform_t *platform);

#endif /* BOOT_ROLLBACK_H */
