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
 * @brief Target selection for SVN anti-rollback verification.
 */
typedef enum {
    ROLLBACK_TARGET_APP      = 0,
    ROLLBACK_TARGET_RECOVERY = 1,
    ROLLBACK_TARGET_STAGE1   = 2
} rollback_target_t;

/**
 * @brief Hybrid SVN Verification.
 *        Evaluates if the requested manifest SVN respects the persistent limits.
 *        Dual-layer: WAL TMR (soft floor, A1 defense) AND eFuse Epoch (hard floor, A2 defense).
 */
boot_status_t boot_rollback_verify_svn(const boot_platform_t *platform, uint32_t manifest_svn, rollback_target_t target);

/**
 * @brief Evaluates the Crash-Cascade state based on M-JOURNAL Boot Failure Counter.
 *        Decides whether to boot Slot A (Normal), the Recovery_OS, invoke M-PANIC Rescue, or Exponential Backoff.
 */
boot_status_t boot_rollback_evaluate_os(const boot_platform_t *platform, const wal_tmr_payload_t *tmr, bool *boot_recovery_os_out);

/**
 * @brief Executes the physical reverse in-place overwrite.
 *        Used when an update immediately crashes after a TXN_COMMIT. Orchestrates `boot_swap_apply()` backwards.
 */
boot_status_t boot_rollback_trigger_revert(const boot_platform_t *platform,
                                           uint8_t *arena, size_t arena_len);

#include "boot_effect.h"

boot_status_t boot_rollback_plan_chunk(const boot_platform_t *platform,
                                       uint32_t current_offset, uint32_t block_size,
                                       uint32_t crc_src,
                                       flash_effect_t *out_fx, size_t cap, size_t *n_out);

#endif /* BOOT_ROLLBACK_H */
