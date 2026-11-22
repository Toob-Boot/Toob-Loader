/*
 * CBMC Memory-Safety, Bit-Reader, Window/Lookahead & Alignment Proof
 * for boot_decomp.c + heatshrink_decoder.c + boot_stream_writer_t.
 *
 * Verifies:
 *   1. Direct Heatshrink LZSS decoder state machine (sink / poll / finish)
 *      against unconstrained symbolic bitstreams (tag bits, literal bytes,
 *      8-bit sliding window indices, and 4-bit lookahead backreferences).
 *   2. End-to-end boot_decomp_apply streaming pipeline into flash via
 *      boot_stream_writer_t, including brownout checkpoint resume, flash
 *      write alignment, and Stage 0 immutable-boot firewall protection.
 */

#include "cbmc_common.h"
#include "boot_decomp.h"
#include "boot_journal.h"
#include "boot_slot_transport.h"
#include "heatshrink_decoder.h"

#define DECOMP_PROOF_MAX_COMP_BYTES 2U
#define DECOMP_PROOF_MAX_OUT_BYTES  24U
#define DECOMP_PROOF_ARENA_BYTES    1152U

static boot_status_t decomp_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "flash read destination buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "flash read must stay within physical flash");
    if (len == 0U) {
        return BOOT_OK;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    uint8_t *dst = (uint8_t *)buf;
    dst[0] = nondet_uint8_t();
    return BOOT_OK;
}

static boot_status_t decomp_flash_write(uint32_t addr, const void *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);
    __CPROVER_assert(cbmc_subrange_of(addr, len, CHIP_APP_SLOT_ABS_ADDR,
                                      CHIP_APP_SLOT_SIZE),
                     "boot_decomp_apply writes strictly inside target App Slot");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t decomp_flash_erase_sector(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);
    __CPROVER_assert(cbmc_subrange_of(addr, CHIP_FLASH_MAX_SECTOR_SIZE,
                                      CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE),
                     "boot_decomp_apply erases strictly inside target App Slot");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry) {
    __CPROVER_assert(platform != NULL && new_entry != NULL &&
                         __CPROVER_r_ok(new_entry, sizeof(*new_entry)),
                     "boot_journal_append requires readable wal_entry_payload_t");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

void prove_heatshrink_bitreader_and_window_bounds(void) {
    heatshrink_decoder hsd;
    heatshrink_decoder_reset(&hsd);

    uint8_t in_buf[DECOMP_PROOF_MAX_COMP_BYTES];
    CBMC_HAVOC_OBJECT(in_buf);
    size_t in_size = nondet_size_t();
    __CPROVER_assume(in_size <= sizeof(in_buf));

    size_t sunk = 0U;
    HSD_sink_res sres = heatshrink_decoder_sink(&hsd, in_buf, in_size, &sunk);
    if (in_size > 0U) {
        __CPROVER_assert(sres == HSDR_SINK_OK && sunk <= in_size,
                         "heatshrink_decoder_sink bounds sunk <= in_size");
    }

    uint8_t out_buf[2];
    size_t out_cap = nondet_size_t();
    __CPROVER_assume(out_cap >= 1U && out_cap <= sizeof(out_buf));

    for (unsigned step = 0U; step < 2U; step++) {
        size_t polled = 0U;
        HSD_poll_res pres = heatshrink_decoder_poll(&hsd, out_buf, out_cap, &polled);
        __CPROVER_assert(polled <= out_cap,
                         "heatshrink_decoder_poll never writes past out_cap");
        if (pres == HSDR_POLL_EMPTY) {
            break;
        }
    }

    HSD_finish_res fres = heatshrink_decoder_finish(&hsd);
    __CPROVER_assert(fres == HSDR_FINISH_DONE || fres == HSDR_FINISH_MORE,
                     "heatshrink_decoder_finish returns valid enum");
}

void prove_boot_decomp_streaming_pipeline(void) {
    flash_hal_t flash_hal = {
        .init             = NULL,
        .deinit           = NULL,
        .read             = decomp_flash_read,
        .write            = decomp_flash_write,
        .erase_sector     = decomp_flash_erase_sector,
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

    uint8_t arena[DECOMP_PROOF_ARENA_BYTES] __attribute__((aligned(8)));
    wal_entry_payload_t open_txn;
    CBMC_HAVOC_OBJECT(open_txn);

    /* Argument & bounds guard verification */
    __CPROVER_assert(boot_decomp_apply(&platform, CHIP_STAGING_SLOT_ABS_ADDR, 4U,
                                       CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE,
                                       0U, &open_txn, arena, sizeof(arena)) ==
                         BOOT_ERR_FLASH_BOUNDS,
                     "Zero expected_installed_size must be rejected");
    __CPROVER_assert(boot_decomp_apply(&platform, CHIP_STAGING_SLOT_ABS_ADDR, 4U,
                                       CHIP_APP_SLOT_ABS_ADDR, 16U,
                                       32U, &open_txn, arena, sizeof(arena)) ==
                         BOOT_ERR_FLASH_BOUNDS,
                     "Oversized expected_installed_size must be rejected");

    size_t src_size = nondet_size_t();
    __CPROVER_assume(src_size <= DECOMP_PROOF_MAX_COMP_BYTES);

    uint32_t expected_size = nondet_uint32_t();
    __CPROVER_assume(expected_size >= 1U && expected_size <= DECOMP_PROOF_MAX_OUT_BYTES);

    /* Bound checkpoint resume scan to <= 1 sector so loop unwinding is exact */
    if (open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] == TOOB_PHASE_STREAM_WRITE) {
        __CPROVER_assume(open_txn.delta_chunk_id <= CHIP_FLASH_MAX_SECTOR_SIZE);
    }

    boot_status_t st = boot_decomp_apply(
        &platform, CHIP_STAGING_SLOT_ABS_ADDR, src_size,
        CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE,
        expected_size, &open_txn, arena, sizeof(arena));

    if (st == BOOT_OK) {
        __CPROVER_assert(open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] == 0U &&
                             open_txn.delta_chunk_id == 0U,
                         "Successful decompression clears stream-write WAL phase");
    }
}

int main(void) {
    if (nondet_bool()) {
        prove_heatshrink_bitreader_and_window_bounds();
    } else {
        prove_boot_decomp_streaming_pipeline();
    }
    return 0;
}
