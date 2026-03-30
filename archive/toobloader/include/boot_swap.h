/**
 * @file boot_swap.h
 * @brief Power-Fail-Safe OTA Overwrite Engine
 *
 * Exposes the update logic for the bootloader automaton.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#ifndef BOOTLOADER_BOOT_SWAP_H
#define BOOTLOADER_BOOT_SWAP_H

#include "boot_config.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @osv component: Bootloader.OTA
 * @brief Evaluates and processes any pending OTA overwrite.
 *
 * If state->ota_update_pending == 1, systematically erases Slot A and
 * copies Slot B to Slot A in power-fail-safe chunks, updating TMR progress.
 *
 * @param[in,out] state Pointer to the TMR state sector
 * @return 0 on success, negative error code on failure.
 */
int32_t boot_swap_process_update(boot_state_sector_t *state);

/**
 * @osv component: Bootloader.OTA
 * @brief Attempts to roll back Slot A to the backup stored in Slot B.
 *
 * Automatically deciphers the backup using the deterministic Backup Nonce.
 * Resets boot failure metrics upon success to allow the device to heal.
 *
 * @param[in,out] state Pointer to the TMR state sector
 * @return 0 on success, negative error code on failure.
 */
int32_t boot_swap_revert_update(boot_state_sector_t *state);

#ifdef __cplusplus
}
#endif

#endif /* BOOTLOADER_BOOT_SWAP_H */
