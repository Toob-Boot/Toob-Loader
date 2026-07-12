/**
 * @file boot_mailbox.c
 * @brief Core-side Mailbox consumer implementation.
 */

#include "generated_boot_config.h"
#include "boot_mailbox.h"
#include "boot_crc32.h"
#include "boot_secure_zeroize.h"
#include "boot_journal.h"
#include <string.h>

/** Helper to validate a slot and extract its contents. */
static bool read_and_validate_slot(const boot_platform_t *platform,
                                   uint32_t slot_idx,
                                   toob_mailbox_t *out) {
    uint32_t addr = CHIP_MAILBOX_ABS_ADDR + slot_idx * sizeof(toob_mailbox_t);
    boot_secure_zeroize(out, sizeof(*out));

    if (platform->flash->read(addr, (uint8_t *)out, sizeof(*out)) != BOOT_OK) {
        return false;
    }

    if (out->magic != TOOB_MAILBOX_MAGIC || out->version != TOOB_MAILBOX_VERSION) {
        return false;
    }

    uint32_t expected_crc = compute_boot_crc32((const uint8_t *)out, offsetof(toob_mailbox_t, crc32));
    return expected_crc == out->crc32;
}

boot_status_t boot_mailbox_fold_in(const boot_platform_t *platform,
                                   wal_entry_payload_t *open_txn,
                                   wal_tmr_payload_t *current_tmr) {
    if (!platform || !platform->flash || !open_txn || !current_tmr) {
        return BOOT_ERR_INVALID_ARG;
    }

    toob_mailbox_t best_slot;
    boot_secure_zeroize(&best_slot, sizeof(best_slot));
    bool found_valid = false;
    uint32_t best_seq = 0;

    /* Scan both slots to find the valid slot with the highest sequence number. */
    for (uint32_t i = 0; i < TOOB_MAILBOX_SLOTS; i++) {
        toob_mailbox_t temp;
        if (read_and_validate_slot(platform, i, &temp)) {
            if (!found_valid || temp.seq > best_seq) {
                best_slot = temp;
                best_seq = temp.seq;
                found_valid = true;
            }
        }
        boot_secure_zeroize(&temp, sizeof(temp));
    }

    if (!found_valid) {
        boot_secure_zeroize(&best_slot, sizeof(best_slot));
        return BOOT_ERR_NOT_FOUND;
    }

    /* Check if the request is fresh (seq > last_consumed_mailbox_seq). */
    if (best_seq <= current_tmr->last_consumed_mailbox_seq) {
        boot_secure_zeroize(&best_slot, sizeof(best_slot));
        return BOOT_ERR_NOT_FOUND;
    }

    /* Map request type to Core WAL intent. */
    wal_intent_t mapped_intent = WAL_INTENT_NONE;
    switch (best_slot.request) {
        case TOOB_REQ_UPDATE_PENDING:
            mapped_intent = WAL_INTENT_UPDATE_PENDING;
            break;
        case TOOB_REQ_CONFIRM:
            mapped_intent = WAL_INTENT_CONFIRM_COMMIT;
            break;
        case TOOB_REQ_RECOVERY_RESOLVED:
            mapped_intent = WAL_INTENT_RECOVERY_RESOLVED;
            break;
        default:
            /* Ignore unrecognized request types. */
            boot_secure_zeroize(&best_slot, sizeof(best_slot));
            return BOOT_ERR_NOT_FOUND;
    }

    /* Construct Core WAL entry. */
    wal_entry_payload_t entry;
    boot_secure_zeroize(&entry, sizeof(entry));
    entry.magic = WAL_ENTRY_MAGIC;
    entry.intent = mapped_intent;

    if (mapped_intent == WAL_INTENT_UPDATE_PENDING) {
        entry.offset = best_slot.tbm1_addr;
    } else if (mapped_intent == WAL_INTENT_CONFIRM_COMMIT) {
        entry.expected_nonce = best_slot.nonce;
    }

    /* Write to the Core's WAL. */
    boot_status_t status = boot_journal_append(platform, &entry);
    if (status != BOOT_OK) {
        boot_secure_zeroize(&best_slot, sizeof(best_slot));
        boot_secure_zeroize(&entry, sizeof(entry));
        return status;
    }

    /* Update the output open_txn so the boot pipeline uses it. */
    *open_txn = entry;

    /* Update last_consumed_mailbox_seq in the TMR payload. */
    current_tmr->last_consumed_mailbox_seq = best_seq;
    status = boot_journal_update_tmr(platform, current_tmr);

    boot_secure_zeroize(&best_slot, sizeof(best_slot));
    boot_secure_zeroize(&entry, sizeof(entry));
    return status;
}
