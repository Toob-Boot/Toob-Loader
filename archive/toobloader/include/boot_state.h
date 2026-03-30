/**
 * @file boot_state.h
 * @brief Bootloader State Management & Triple Modular Redundancy (TMR)
 *
 * Provides $O(1)$ redundant storage and self-healing for critical bootloader
 * state (active slot, crash counters) to defend against SEUs and wearout.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#ifndef BOOTLOADER_BOOT_STATE_H
#define BOOTLOADER_BOOT_STATE_H

#include "boot_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @osv component: Bootloader.State
 * @brief Reads the TMR boot state from flash, resolving discrepancies.
 *
 * Reads 3 redundant sectors. If a sector is corrupted (CRC mismatch or SEU
 * bit-flip), the majority (2-out-of-3) wins. The corrupted sector is
 * automatically healed transparently.
 *
 * @param[out] state Pointer to the resolved valid state.
 * @return 0 on success (perfect or healed), -1 if unrecoverable (>=2 errors).
 */
int32_t boot_state_read_tmr(boot_state_sector_t *state);

/**
 * @osv component: Bootloader.State
 * @brief Writes the provided boot state sequentially to all 3 TMR sectors.
 *
 * @param[in] state Pointer to the state to persist.
 * @return 0 on success, negative error code on HAL failure.
 */
int32_t boot_state_write_tmr(boot_state_sector_t *state);

/**
 * @osv component: Bootloader.State
 * @brief Utility wrapper to atomically increment the crash/boot counter.
 */
void boot_state_increment_failures(boot_state_sector_t *state);

#ifdef __cplusplus
}
#endif

#endif /* BOOTLOADER_BOOT_STATE_H */
