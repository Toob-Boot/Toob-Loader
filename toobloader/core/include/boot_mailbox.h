/**
 * @file boot_mailbox.h
 * @brief Core-side OS->Core mailbox reader + WAL fold-in.
 *
 * Counterpart to the OS-side writer (libtoob toob_mailbox.c). At boot, reads the
 * two-sector A/B mailbox, and if it carries a not-yet-consumed request, folds it
 * into the rich WAL (the Core is the sole WAL author and holds the device key,
 * so it seals CRC + chain tags that the OS cannot).
 *
 * Idempotency: a monotonic watermark `last_mbx_request_id` in the TMR; a record
 * is applied only when `seq > last_mbx_request_id`.
 */

#ifndef BOOT_MAILBOX_H
#define BOOT_MAILBOX_H

#include "boot_hal.h" /* boot_platform_t, boot_status_t, BOOT_OK */
#include "toob_mailbox_wire.h"

/**
 * @brief Consume the OS->Core mailbox and fold a pending request into the WAL.
 *
 * Call once early in the boot path, BEFORE boot_journal_reconstruct_txn, so the
 * folded intent is visible to normal WAL evaluation. Safe to call every boot: it
 * writes nothing when the mailbox is empty or already consumed.
 *
 * @return BOOT_OK on success (including the no-op cases); a flash/journal error
 *         code if reading the mailbox or updating the WAL/TMR fails.
 */
boot_status_t boot_mailbox_consume(const boot_platform_t *platform);

#endif /* BOOT_MAILBOX_H */