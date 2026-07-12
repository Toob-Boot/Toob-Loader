/**
 * @file toob_mailbox.c
 * @brief OS-side Mailbox Writer — replaces toob_wal_naive.c.
 *
 * Writes a single request record to a dedicated Flash sector.
 * The sector is erased, then the new record is written to slot 0.
 * If the write is torn (brownout), the CRC will fail and the Core
 * ignores the record — the OS simply retries on next run.
 */

#include "toob_mailbox.h"
#include "libtoob.h"
#include "libtoob_config_sandbox.h"
#include "toob_internal.h"
#include <stddef.h>
#include <string.h>

/**
 * @brief Write a mailbox request.
 *
 * Reads existing slots to determine the next seq, erases the sector,
 * writes the new record to slot 0 with seq = max_seen + 1.
 * CRC covers [0 .. offsetof(crc32)).
 */
static toob_status_t mailbox_put(toob_req_t req, uint32_t tbm1_addr, uint64_t nonce) {
    /* Determine the next sequence number from any surviving slot. */
    uint32_t best_seq = 0;
    for (uint32_t i = 0; i < TOOB_MAILBOX_SLOTS; i++) {
        toob_mailbox_t slot;
        toob_secure_zeroize(&slot, sizeof(slot));
        uint32_t addr = CHIP_MAILBOX_ABS_ADDR + i * sizeof(toob_mailbox_t);

        if (toob_os_flash_read(addr, (uint8_t *)&slot, sizeof(slot)) == TOOB_OK &&
            slot.magic == TOOB_MAILBOX_MAGIC) {
            uint32_t exp = toob_lib_crc32((const uint8_t *)&slot, offsetof(toob_mailbox_t, crc32));
            if (exp == slot.crc32 && slot.seq > best_seq)
                best_seq = slot.seq;
        }
        toob_secure_zeroize(&slot, sizeof(slot));
    }

    /* Build the new record. */
    toob_mailbox_t m;
    toob_secure_zeroize(&m, sizeof(m));
    m.magic     = TOOB_MAILBOX_MAGIC;
    m.version   = TOOB_MAILBOX_VERSION;
    m.request   = (uint16_t)req;
    m.seq       = best_seq + 1;
    m.tbm1_addr = tbm1_addr;
    m.nonce     = nonce;
    m.crc32     = toob_lib_crc32((const uint8_t *)&m, offsetof(toob_mailbox_t, crc32));

    /* Erase the sector (wipes both slots — this is intentional). */
    toob_status_t status = toob_os_flash_erase(CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE);
    if (status != TOOB_OK) {
        toob_secure_zeroize(&m, sizeof(m));
        return status;
    }

    /* Write new record to slot 0. */
    status = toob_os_flash_write(CHIP_MAILBOX_ABS_ADDR, (const uint8_t *)&m, sizeof(m));
    if (status != TOOB_OK) {
        toob_secure_zeroize(&m, sizeof(m));
        return status;
    }

    /* Read-back verify. */
    toob_mailbox_t verify;
    toob_secure_zeroize(&verify, sizeof(verify));
    status = toob_os_flash_read(CHIP_MAILBOX_ABS_ADDR, (uint8_t *)&verify, sizeof(verify));

    if (status == TOOB_OK &&
        toob_ct_memcmp_glitch_safe((const uint8_t *)&m,
                                    (const uint8_t *)&verify,
                                    sizeof(m)) == TOOB_OK) {
        status = TOOB_OK;
    } else {
        status = TOOB_ERR_FLASH_HW;
    }

    toob_secure_zeroize(&m, sizeof(m));
    toob_secure_zeroize(&verify, sizeof(verify));
    return status;
}

/* ===== Public API (called from toob_update.c / toob_confirm.c) ===== */

toob_status_t toob_mailbox_set_update(uint32_t manifest_flash_addr) {
    return mailbox_put(TOOB_REQ_UPDATE_PENDING, manifest_flash_addr, 0);
}

toob_status_t toob_mailbox_set_confirm(uint64_t nonce) {
    return mailbox_put(TOOB_REQ_CONFIRM, 0, nonce);
}

toob_status_t toob_mailbox_set_recovery_resolved(void) {
    return mailbox_put(TOOB_REQ_RECOVERY_RESOLVED, 0, 0);
}
