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

/**
 * @brief Evaluates the current Rollback state and Boot Failure Counter.
 *        Decides whether to boot Slot A, the Recovery_OS, or invoke Panic mode.
 *
 * TODO: Add boot_status_t boot_rollback_evaluate_cascade(const boot_platform_t *platform);
 */

/**
 * @brief Executes the rollback operation (e.g., swapping fallback slot to main slot).
 *
 * TODO: Add boot_status_t boot_rollback_execute(const boot_platform_t *platform, uint32_t fallback_slot_addr);
 */

#endif /* BOOT_ROLLBACK_H */
