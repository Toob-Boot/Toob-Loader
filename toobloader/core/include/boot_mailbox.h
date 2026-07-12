/**
 * @file boot_mailbox.h
 * @brief Core-side Mailbox consumer API.
 *
 * Implements the consumption of pending requests written by the OS.
 */

#ifndef BOOT_MAILBOX_H
#define BOOT_MAILBOX_H

#include "boot_hal.h"
#include "boot_types.h"
#include "boot_journal.h"
#include "toob_mailbox.h"

/**
 * @brief Checks if the mailbox contains a new request and folds it into the WAL.
 *
 * Reads both Double-Slots from flash, validates their CRC + magic,
 * and processes the request with the highest valid seq if seq > last_consumed_seq.
 * On success, appends the corresponding intent to the Core's WAL and updates the TMR.
 *
 * @param platform Hardware/platform function pointers.
 * @param open_txn Output to be populated with the reconstructed or newly appended txn state.
 * @param current_tmr The current TMR state to be read/updated.
 * @return BOOT_OK on success (or if no new request exists).
 *         BOOT_ERR_NOT_FOUND if the mailbox is empty or has no new requests.
 *         Other BOOT_ERR_* codes on flash/integrity failures.
 */
boot_status_t boot_mailbox_fold_in(const boot_platform_t *platform,
                                   wal_entry_payload_t *open_txn,
                                   wal_tmr_payload_t *current_tmr);

#endif /* BOOT_MAILBOX_H */
