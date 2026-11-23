#include "fuzz_common.h"

#include "boot_cobs.h"
#include "boot_crc32.h"
#include "boot_journal.h"
#include "boot_mailbox.h"

#define FUZZ_COBS_MAX_BUF 4096U

static uint8_t s_cobs_inplace[FUZZ_COBS_MAX_BUF];
static uint8_t s_cobs_recv_buf[128];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    fuzz_platform_reset(0x434F4253ULL ^ (uint64_t)size);
    const boot_platform_t *plat = fuzz_platform_get();

    /* 1. Direct in-place COBS decode + anti-leakage trailing zeroization invariant. */
    size_t copy_len = (size > FUZZ_COBS_MAX_BUF) ? FUZZ_COBS_MAX_BUF : size;
    if (copy_len > 0U) {
        memcpy(s_cobs_inplace, data, copy_len);
    }
    size_t decoded_len = 0U;
    boot_status_t dec_st = boot_cobs_decode_in_place(s_cobs_inplace, copy_len, &decoded_len);
    if (dec_st == BOOT_OK) {
        if (decoded_len > copy_len) {
            abort();
        }
        for (size_t i = decoded_len; i < copy_len; i++) {
            if (s_cobs_inplace[i] != 0x00U) {
                abort();
            }
        }
    }

    /* 2. Streaming UART COBS frame receive + >128B overflow drain recovery. */
    if (copy_len > 0U) {
        fuzz_uart_set_rx(data, copy_len, true);
        g_fuzz_trap_active = 1;
        if (setjmp(g_fuzz_trap_jmp) == 0) {
            for (uint32_t frames = 0U; frames < 8U && fuzz_uart_rx_remaining() > 0U; frames++) {
                size_t raw_len = 0U;
                if (boot_cobs_recv_frame(plat, s_cobs_recv_buf, sizeof(s_cobs_recv_buf),
                                         &raw_len) == BOOT_OK) {
                    size_t inner_len = 0U;
                    (void)boot_cobs_decode_in_place(s_cobs_recv_buf, raw_len, &inner_len);
                }
            }
        }
        g_fuzz_trap_active = 0;
        fuzz_uart_set_rx(NULL, 0U, false);
    }

    /* 3. OS->Core two-sector A/B Mailbox scan + RFC-1982 wrap + WAL fold-in. */
    fuzz_keystore_set_dslc(0x01U);
    fuzz_keystore_set_monotonic(0U);
    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        if (boot_journal_init(plat) == BOOT_OK) {
            wal_tmr_payload_t tmr;
            if (boot_journal_get_tmr(plat, &tmr) == BOOT_OK) {
                /* Exercise RFC-1982 boundary watermarks (0, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF). */
                static const uint32_t boundary_seqs[4] = {
                    0U, 0x7FFFFFFFU, 0xFFFFFFFEU, 0xFFFFFFFFU
                };
                uint32_t sel = (copy_len > 0U) ? (uint32_t)(data[0] & 3U) : 0U;
                tmr.last_mbx_request_id = boundary_seqs[sel];
                tmr.active_nonce_lo = 0x11223344U;
                tmr.active_nonce_hi = 0x55667788U;
                (void)boot_journal_update_tmr(plat, &tmr);
            }

            fuzz_flash_fill_erased(CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE);
            if (copy_len > 0U) {
                size_t half = copy_len / 2U;
                size_t s0_len = (half > sizeof(toob_mailbox_t)) ? sizeof(toob_mailbox_t) : half;
                size_t s1_rem = copy_len - half;
                size_t s1_len = (s1_rem > sizeof(toob_mailbox_t)) ? sizeof(toob_mailbox_t) : s1_rem;
                if (s0_len > 0U) {
                    fuzz_flash_write_raw(CHIP_MAILBOX_ABS_ADDR, data, s0_len);
                }
                if (s1_len > 0U) {
                    fuzz_flash_write_raw(CHIP_MAILBOX_ABS_ADDR + CHIP_MAILBOX_SLOT_SIZE,
                                         &data[half], s1_len);
                }
            }

            (void)boot_mailbox_consume(plat);

            wal_entry_payload_t txn;
            (void)boot_journal_reconstruct_txn(plat, &txn, NULL, NULL);
        }
    }
    g_fuzz_trap_active = 0;

    boot_journal_zeroize_secrets();
    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("cobs_mailbox")
