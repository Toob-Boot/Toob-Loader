/*
 * CBMC Memory-Safety, Envelope/CRC Parsing & State-Transition Proof
 * for boot_mailbox.c (OS-to-Core Double-Slot Mailbox Consumer).
 *
 * Verifies:
 *   - Unconstrained symbolic A/B mailbox flash records (magic, version,
 *     reserved bits, bitmask flags, 64-bit nonce, CRC-32).
 *   - Monotonic watermark idempotency gate (seq > tmr.last_mbx_request_id).
 *   - Stale-confirm defense (CONFIRM_COMMIT emitted iff nonce != 0 and matches
 *     active tentative boot nonce).
 *   - Deterministic cumulative bitflag fold-in order into WAL intents
 *     (RECOVERY_RESOLVED -> CONFIRM_COMMIT -> UPDATE_PENDING).
 */

#include "cbmc_common.h"
#include "boot_journal.h"
#include "boot_mailbox.h"

static uint8_t           g_mbx_slots[TOOB_MAILBOX_SLOTS][sizeof(toob_mailbox_t)];
static wal_tmr_payload_t g_initial_tmr;
static bool              g_tmr_read_ok;
static bool              g_existing_locked;
static unsigned          g_append_count;
static uint32_t          g_last_intent_stage;
static bool              g_tmr_updated;

static boot_status_t mbx_flash_read(uint32_t addr, void *buf, size_t len) {
    __CPROVER_assert(len == 0U || (buf != NULL && __CPROVER_w_ok(buf, len)),
                     "mailbox flash read buffer must be writable");
    __CPROVER_assert(cbmc_subrange_of(addr, len, CHIP_MAILBOX_ABS_ADDR,
                                      CHIP_MAILBOX_SIZE),
                     "boot_mailbox_consume only reads inside CHIP_MAILBOX");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    if (addr == CHIP_MAILBOX_ABS_ADDR && len == sizeof(toob_mailbox_t)) {
        memcpy(buf, g_mbx_slots[0], sizeof(toob_mailbox_t));
        return BOOT_OK;
    }
    if (addr == (CHIP_MAILBOX_ABS_ADDR + CHIP_MAILBOX_SLOT_SIZE) &&
        len == sizeof(toob_mailbox_t)) {
        memcpy(buf, g_mbx_slots[1], sizeof(toob_mailbox_t));
        return BOOT_OK;
    }
    cbmc_havoc_bytes((uint8_t *)buf, len);
    return BOOT_OK;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr) {
    __CPROVER_assert(platform != NULL && out_tmr != NULL &&
                         __CPROVER_w_ok(out_tmr, sizeof(*out_tmr)),
                     "boot_journal_get_tmr out_tmr must be writable");
    if (!g_tmr_read_ok) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_tmr = g_initial_tmr;
    return BOOT_OK;
}

boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform,
                                           wal_entry_payload_t *out_state,
                                           uint32_t *out_net_accum,
                                           uint32_t *out_resume_offset) {
    __CPROVER_assert(platform != NULL && out_state != NULL &&
                         __CPROVER_w_ok(out_state, sizeof(*out_state)),
                     "boot_journal_reconstruct_txn out_state must be writable");
    __CPROVER_assert(out_net_accum == NULL && out_resume_offset == NULL,
                     "boot_mailbox_consume passes NULL optional accumulators");
    if (nondet_bool()) {
        g_existing_locked = false;
        return BOOT_ERR_NOT_FOUND;
    }
    CBMC_HAVOC_OBJECT(*out_state);
    g_existing_locked = (out_state->intent == (uint32_t)WAL_INTENT_DEVICE_LOCKED);
    return BOOT_OK;
}

boot_status_t boot_journal_reconstruct_aux_heal(const boot_platform_t *platform,
                                                wal_entry_payload_t *out_heal,
                                                bool *out_found) {
    __CPROVER_assert(platform != NULL && out_heal != NULL && out_found != NULL &&
                         __CPROVER_w_ok(out_heal, sizeof(*out_heal)) &&
                         __CPROVER_w_ok(out_found, sizeof(*out_found)),
                     "boot_journal_reconstruct_aux_heal outputs must be writable");
    if (nondet_bool()) {
        *out_found = false;
        return BOOT_ERR_FLASH_HW;
    }
    *out_found = nondet_bool();
    if (*out_found) {
        CBMC_HAVOC_OBJECT(*out_heal);
    }
    return BOOT_OK;
}

boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry) {
    __CPROVER_assert(platform != NULL && new_entry != NULL &&
                         __CPROVER_r_ok(new_entry, sizeof(*new_entry)),
                     "boot_journal_append entry must be readable");
    __CPROVER_assert(!g_existing_locked,
                     "HIGH-31: WAL_INTENT_DEVICE_LOCKED must block all unauthenticated mailbox WAL appends");
    __CPROVER_assert(!g_tmr_updated,
                     "WAL append must happen strictly before TMR watermark bump");
    __CPROVER_assert(new_entry->magic == WAL_ENTRY_MAGIC,
                     "mailbox WAL entry must carry WAL_ENTRY_MAGIC");

    uint32_t stage = 0U;
    if (new_entry->intent == (uint32_t)WAL_INTENT_RECOVERY_RESOLVED) {
        stage = 1U;
    } else if (new_entry->intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT) {
        stage = 2U;
        uint64_t active_nonce =
            ((uint64_t)g_initial_tmr.active_nonce_hi << 32U) |
            (uint64_t)g_initial_tmr.active_nonce_lo;
        __CPROVER_assert(active_nonce != 0ULL &&
                             new_entry->expected_nonce == active_nonce,
                         "CONFIRM_COMMIT requires non-zero matching active nonce");
    } else if (new_entry->intent == (uint32_t)WAL_INTENT_UPDATE_PENDING) {
        stage = 3U;
    } else {
        __CPROVER_assert(false, "unexpected WAL intent emitted by boot_mailbox");
    }

    __CPROVER_assert(stage > g_last_intent_stage,
                     "cumulative mailbox intents must follow strict stage order");
    g_last_intent_stage = stage;
    g_append_count++;

    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
    __CPROVER_assert(platform != NULL && new_tmr != NULL &&
                         __CPROVER_r_ok(new_tmr, sizeof(*new_tmr)),
                     "boot_journal_update_tmr new_tmr must be readable");
    __CPROVER_assert(new_tmr->last_mbx_request_id >
                         g_initial_tmr.last_mbx_request_id,
                     "TMR mailbox watermark must advance strictly monotonically");
    g_tmr_updated = true;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

int main(void) {
    CBMC_HAVOC_OBJECT(g_mbx_slots);
    CBMC_HAVOC_OBJECT(g_initial_tmr);
    g_tmr_read_ok       = nondet_bool();
    g_existing_locked   = false;
    g_append_count      = 0U;
    g_last_intent_stage = 0U;
    g_tmr_updated       = false;

    __CPROVER_assert(boot_mailbox_consume(NULL) == BOOT_ERR_INVALID_ARG,
                     "NULL platform must be rejected");

    flash_hal_t flash_hal = {
        .read             = mbx_flash_read,
        .write            = NULL,
        .erase_sector     = NULL,
        .get_sector_size  = cbmc_flash_get_sector_size,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .max_erase_cycles = 100000U,
        .erased_value     = 0xFFU,
    };

    boot_platform_t platform = {
        .flash = &flash_hal,
        .wdt   = &g_cbmc_wdt_hal,
    };

    boot_status_t st = boot_mailbox_consume(&platform);
    __CPROVER_assert(g_append_count <= 3U,
                     "at most 3 cumulative WAL intents emitted per mailbox consume");
    if (!g_tmr_read_ok && g_append_count > 0U) {
        __CPROVER_assert(false, "failed TMR read must block WAL appends");
    }
    if (g_existing_locked) {
        __CPROVER_assert(g_append_count == 0U,
                         "HIGH-31: locked device drops mailbox intents with zero WAL appends");
    }
    (void)st;
    return 0;
}
