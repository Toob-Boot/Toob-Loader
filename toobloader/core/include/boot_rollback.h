#ifndef BOOT_ROLLBACK_H
#define BOOT_ROLLBACK_H

/*
 * Toob-Boot Core Header: boot_rollback.h
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md (OS Recovery nach Fehlversuch)
 * - docs/testing_requirements.md
 * - docs/libtoob_api.md
 */

#include "boot_effect.h"
#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_types.h"

/**
 * @brief Target selection for SVN anti-rollback verification.
 */
typedef enum {
  ROLLBACK_TARGET_APP = 0,
  ROLLBACK_TARGET_RECOVERY = 1,
  ROLLBACK_TARGET_STAGE1 = 2
} rollback_target_t;

/**
 * @brief Descriptor for 1-way rollback chunk effect planning (LOW-08).
 */
typedef struct {
  uint32_t current_offset;
  uint32_t block_size;
  uint32_t crc_src;
} boot_rollback_chunk_desc_t;

/**
 * @brief Hybrid SVN Verification.
 */
boot_status_t boot_rollback_verify_svn(const boot_platform_t *platform, uint32_t manifest_svn,
                                       rollback_target_t target);

/**
 * @brief Evaluates the Crash-Cascade state based on M-JOURNAL Boot Failure Counter.
 */
boot_status_t boot_rollback_evaluate_os(const boot_platform_t *platform,
                                        const wal_tmr_payload_t *tmr, bool *boot_recovery_os_out);

/**
 * @brief Executes the physical reverse in-place overwrite.
 */
boot_status_t boot_rollback_trigger_revert(const boot_platform_t *platform, uint8_t *arena,
                                           size_t arena_len);

boot_status_t boot_rollback_plan_chunk(const boot_platform_t *platform,
                                       const boot_rollback_chunk_desc_t *desc,
                                       flash_effect_t *out_fx, size_t cap, size_t *n_out);

#endif /* BOOT_ROLLBACK_H */
