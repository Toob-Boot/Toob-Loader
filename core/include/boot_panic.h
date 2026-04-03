#ifndef BOOT_PANIC_H
#define BOOT_PANIC_H

/*
 * Toob-Boot Core Header: boot_panic.h
 * Relevant Spec-Dateien:
 * - docs/stage_1_5_spec.md (Serial Rescue & SOS Mode)
 * - docs/testing_requirements.md
 */

#include "boot_hal.h"

// TODO: Enforce Stage 1.5 Rescue API signatures and COBS state machine context decoupling as aligned with concept_fusion.md


/**
 * @brief Atomically stops execution, attempts Serial Rescue (COBS)
 *        or enters SOS flashing loop if no console is present.
 *        Never returns.
 * 
 * @param platform Hardware HAL abstraction
 * @param reason   Reason for panic
 */
_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason);

#endif /* BOOT_PANIC_H */
