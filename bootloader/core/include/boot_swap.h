#ifndef BOOT_SWAP_H
#define BOOT_SWAP_H

/*
 * Toob-Boot Core Header: boot_swap.h
 * Relevant Spec-Dateien:
 * - docs/toobfuzzer_integration.md (Fuzzing-Aware Block Tausch, Limitierungen)
 * - docs/testing_requirements.md (Brownout Recovery)
 */

#include "boot_types.h"
#include "boot_hal.h"
#ifdef TOOB_MOCK_TEST
#include "boot_config_mock.h"
#endif


/**
 * @brief Enum to selectively track erase counters in the TMR payload.
 */
typedef enum {
    BOOT_DEST_SLOT_APP = 0,
    BOOT_DEST_SLOT_STAGING = 1
} boot_dest_slot_t;

/**
 * @brief Apply a swap or copy operation from src_base to dest_base.
 *        This function safely orchestrates the in-place overwrite using a swap buffer.
 *
 * @note  Atomic Fallback is coordinated externally by the WAL_INTENT_TXN_COMMIT intent 
 *        inside boot_state.c. This function is physically destructive mid-flight and 
 *        must be guarded by transactions.
 *        Swap size is heavily restricted by the monolithic buffer (max sector size limit).
 *
 * @param platform  Hardware HAL abstraction
 * @param src_base  Source address
 * @param dest_base Destination address
 * @param length    Total length to swap (derived dynamically from Envelope)
 * @param dest_slot Which slot is written to (for TMR wear counters).
 * @return boot_status_t BOOT_OK on success, error otherwise.
 */
#include "boot_journal.h"

boot_status_t boot_swap_apply(const boot_platform_t *platform, uint32_t src_base, uint32_t dest_base, uint32_t length, boot_dest_slot_t dest_slot, wal_entry_payload_t *open_txn);
boot_status_t boot_swap_erase_safe(const boot_platform_t *platform, uint32_t addr, size_t len);

#endif /* BOOT_SWAP_H */
