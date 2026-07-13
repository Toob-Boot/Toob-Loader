/**
 * @file toob_mailbox.h
 * @brief OS -> Core Mailbox SDK writer interface (C17).
 *
 * Implements the OS-side API to send update registration, confirmation, and
 * recovery resolution requests to the Core bootloader.
 *
 * Sharing contract: all wire structure and enum definitions are defined in
 * toob_mailbox_wire.h to prevent structure layout and static assertion drift.
 */

#ifndef TOOB_MAILBOX_H
#define TOOB_MAILBOX_H

#include "libtoob_types.h" /* toob_status_t */
#include "toob_mailbox_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===== OS-side writers (implemented in toob_mailbox.c) ===== */
toob_status_t toob_mailbox_set_update(uint32_t manifest_flash_addr);
toob_status_t toob_mailbox_set_confirm(uint64_t nonce);
toob_status_t toob_mailbox_set_recovery_resolved(void);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_MAILBOX_H */
