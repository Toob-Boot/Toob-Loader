#ifndef BOOT_PROVISIONING_H
#define BOOT_PROVISIONING_H

/**
 * @file boot_provisioning.h
 * @brief Factory Provisioning UART Loop (DSLC == 0x00 Only)
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/plan.md Phase 8 (Provisioning-HAL + CLI-Integration)
 * - docs/stuff.md Section 6.2 (DSLC-Gated Provisioning in Stage 1)
 *
 * ARCHITECTURE:
 * Entered when boot_main.c detects an unprovisioned device (DSLC == 0x00).
 * Listens on UART for COBS-framed Provisioning-Commands from the toob-cli.
 * Does NOT return — terminates with a WDT-induced hardware reset after the
 * provisioning sequence completes.
 */

#include "boot_hal.h"

/**
 * @brief Factory Provisioning UART Loop.
 *
 * Activates only when DSLC == 0x00 (DEVELOPMENT state).
 * Receives provisioning commands (key burn, DSLC advance, protection bits)
 * over COBS-framed UART and dispatches them to the provisioning HAL.
 *
 * @param platform Fully initialized platform (provisioning + console HAL required).
 */
_Noreturn void boot_provisioning_run(const boot_platform_t *platform);

#endif /* BOOT_PROVISIONING_H */
