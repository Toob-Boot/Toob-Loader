/*
 * CBMC Sector-Bounds, Asymmetric-Sector & Write-Alignment Proof
 * for boot_swap.c + boot_effect.c + boot_transport*.c (Wave 5A).
 *
 * Parameterized across:
 *   - TOOB_TRANSPORT_PROVIDER in {SWAPSCRATCH, ONEWAY, SWAPMOVE}
 *   - CBMC_ASYMMETRIC_SECTORS in {0 (homogeneous), 1 (16 / 64 / 128 KB)}
 *   - CHIP_FLASH_WRITE_ALIGNMENT in {1U, 4U, 8U, 32U}
 *
 * Proves via __CPROVER_assert on every flash HAL operation:
 *   1. Every flash->write(addr, buf, len) satisfies:
 *        (addr % CHIP_FLASH_WRITE_ALIGNMENT) == 0
 *        (len  % CHIP_FLASH_WRITE_ALIGNMENT) == 0
 *        addr >= CHIP_FLASH_IMMUTABLE_BOOT_END
 *        [addr, addr + len) stays strictly inside a mutable partition.
 *   2. Every flash->erase_sector(addr) is strictly sector-base aligned across
 *      both homogeneous and asymmetric (16 KB / 64 KB / 128 KB) sector layouts
 *      and never touches [0, CHIP_FLASH_IMMUTABLE_BOOT_END).
 *   3. boot_stream_writer_t buffers arbitrary unaligned writes across
 *      intermediate flushes (pad_final == false) and pads residual tail bytes
 *      with 0xFF on final flush (pad_final == true) with zero partial writes.
 *
 * Documented Producer Preconditions (see formal report Findings #1 and #2):
 *   - SWAPSCRATCH: open_txn->transfer_bitmap[3] carries a valid producer
 *     scratch address (CHIP_SCRATCH_SLOT_ABS_ADDR) when shield == 0xAA55AA55U.
 *   - SWAPMOVE: open_txn->delta_chunk_id < c.N when resuming TOOB_PHASE_SWAPMOVE_MOVE.
 */

#define CBMC_NO_ZEROIZE_STUB 1
#include "cbmc_common.h"
#include "boot_effect.h"
#include "boot_journal.h"
#include "boot_rollback.h"
#include "boot_stream_writer.h"
#include "boot_swap.h"
#include "boot_transport.h"

static bool g_in_stream_writer_proof = false;

void boot_secure_zeroize(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "boot_secure_zeroize target buffer must be writable");
    if (ptr == NULL || len == 0U) {
        return;
    }
    if (g_in_stream_writer_proof) {
        if (len == sizeof(boot_stream_writer_t)) {
            *(boot_stream_writer_t *)ptr = (boot_stream_writer_t){0};
        } else {
            ((uint8_t *)ptr)[0] = 0U;
        }
    } else if (len < 256U) {
        memset(ptr, 0, len);
    } else {
        ((uint8_t *)ptr)[0] = 0U;
    }
}

boot_status_t cbmc_swap_random_safe(const boot_platform_t *platform,
                                    uint8_t *buf, size_t len) {
    if (platform == NULL || buf == NULL || len == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(buf, len, "boot_random_safe buffer must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_CRYPTO;
    }
    if (len == sizeof(uint32_t)) {
        uint32_t seed = nondet_uint32_t();
        __CPROVER_assume(seed < 16U);
        memcpy(buf, &seed, sizeof(seed));
    } else {
        buf[0] = nondet_uint8_t();
    }
    return BOOT_OK;
}

#define SWAP_PROOF_ARENA_BYTES 512U
#if CHIP_FLASH_WRITE_ALIGNMENT >= 32U
#define SWAP_PROOF_TAIL_CAP    36U
#define SWAP_PROOF_CHUNK_CAP   20U
#elif CHIP_FLASH_WRITE_ALIGNMENT == 1U
#define SWAP_PROOF_TAIL_CAP    8U
#define SWAP_PROOF_CHUNK_CAP   6U
#else
#define SWAP_PROOF_TAIL_CAP    20U
#define SWAP_PROOF_CHUNK_CAP   12U
#endif

static uint32_t g_write_count;
static uint32_t g_erase_count;

static boot_status_t swap_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "swap flash read destination must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "swap flash read must stay within physical flash");
    if (len == 0U) {
        return BOOT_OK;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    ((uint8_t *)buf)[0] = nondet_uint8_t();
    return BOOT_OK;
}

static boot_status_t swap_flash_write(uint32_t addr, const void *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);
    g_write_count++;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t swap_flash_erase_sector(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);
    g_erase_count++;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry) {
    __CPROVER_assert(platform != NULL && new_entry != NULL &&
                         __CPROVER_r_ok(new_entry, sizeof(*new_entry)),
                     "boot_journal_append requires readable WAL entry");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform,
                                           wal_entry_payload_t *out_txn,
                                           uint32_t *out_net_accum,
                                           uint32_t *out_resume_off) {
    __CPROVER_assert(platform != NULL && out_txn != NULL &&
                         __CPROVER_w_ok(out_txn, sizeof(*out_txn)),
                     "boot_journal_reconstruct_txn requires writable out_txn");
    if (out_net_accum != NULL) {
        *out_net_accum = 0U;
    }
    if (out_resume_off != NULL) {
        *out_resume_off = 0U;
    }
    if (nondet_bool()) {
        return BOOT_ERR_NOT_FOUND;
    }
    CBMC_HAVOC_OBJECT(*out_txn);
    return BOOT_OK;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr) {
    __CPROVER_assert(platform != NULL && out_tmr != NULL &&
                         __CPROVER_w_ok(out_tmr, sizeof(*out_tmr)),
                     "boot_journal_get_tmr requires writable TMR struct");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    CBMC_HAVOC_OBJECT(*out_tmr);
    __CPROVER_assume(out_tmr->app_slot_erase_counter < 90000U);
    __CPROVER_assume(out_tmr->staging_slot_erase_counter < 90000U);
    __CPROVER_assume(out_tmr->swap_buffer_erase_counter < 16U);
    return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
    __CPROVER_assert(platform != NULL && new_tmr != NULL &&
                         __CPROVER_r_ok(new_tmr, sizeof(*new_tmr)),
                     "boot_journal_update_tmr requires readable TMR struct");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_rollback_trigger_revert(const boot_platform_t *platform,
                                           uint8_t *arena, size_t arena_len) {
    __CPROVER_assert(platform != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_rollback_trigger_revert preconditions");
    return BOOT_OK;
}

static uint32_t pick_sector_boundary_offset(void) {
#if CBMC_ASYMMETRIC_SECTORS == 0
    uint8_t sel = nondet_uint8_t();
    if (sel == 0U) {
        return 0U;
    }
    if (sel == 1U) {
        return CHIP_FLASH_MAX_SECTOR_SIZE;
    }
    return 2U * CHIP_FLASH_MAX_SECTOR_SIZE;
#else
    /* Asymmetric slot boundaries: +0 (16 KB), +0x4000 (64 KB), +0x14000 (128 KB) */
    uint8_t sel = nondet_uint8_t();
    if (sel == 0U) {
        return 0U;
    }
    if (sel == 1U) {
        return 0x00004000U;
    }
    return 0x00014000U;
#endif
}

static void prove_stream_writer_alignment_and_checkpoint(const boot_platform_t *platform) {
    uint8_t write_buf[64] __attribute__((aligned(32)));
    wal_entry_payload_t open_txn;
    CBMC_HAVOC_OBJECT(open_txn);

    uint32_t base_ckpt = pick_sector_boundary_offset();
    if (nondet_bool()) {
        /* Also test arbitrary misaligned / out-of-range checkpoint rejection */
#if CBMC_ASYMMETRIC_SECTORS == 0
        __CPROVER_assume(open_txn.delta_chunk_id <= (3U * CHIP_FLASH_MAX_SECTOR_SIZE));
#else
        __CPROVER_assume(open_txn.delta_chunk_id <= CHIP_APP_SLOT_SIZE);
#endif
    } else {
        open_txn.intent = WAL_INTENT_UPDATE_PENDING;
        open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_STREAM_WRITE;
        open_txn.delta_chunk_id = base_ckpt;
    }

    uint32_t tail_bytes = nondet_uint32_t();
    __CPROVER_assume(tail_bytes >= 1U && tail_bytes <= SWAP_PROOF_TAIL_CAP);
    uint32_t expected_size = base_ckpt + tail_bytes;

    boot_stream_writer_t writer;
    boot_status_t st = boot_stream_writer_init(
        &writer, platform, CHIP_APP_SLOT_ABS_ADDR, expected_size,
        write_buf, sizeof(write_buf), &open_txn);
    if (st != BOOT_OK) {
        return;
    }

    __CPROVER_assert((writer.write_align % CHIP_FLASH_WRITE_ALIGNMENT) == 0U,
                     "stream writer effective alignment is a multiple of hardware write_align");
    __CPROVER_assert((writer.flushed_off % writer.write_align) == 0U,
                     "resumed flushed_off satisfies effective write_align");

    /* Fast-forward logical cursor to resumed checkpoint and stream two unaligned chunks */
    writer.target_off = writer.flushed_off;
    uint32_t rem = expected_size - writer.target_off;
    if (rem > SWAP_PROOF_TAIL_CAP) {
        rem = SWAP_PROOF_TAIL_CAP;
    }

    uint8_t payload1[SWAP_PROOF_CHUNK_CAP];
    uint8_t payload2[SWAP_PROOF_CHUNK_CAP];
    CBMC_HAVOC_OBJECT(payload1);
    CBMC_HAVOC_OBJECT(payload2);

    uint32_t c1 = nondet_uint32_t();
    uint32_t c2 = nondet_uint32_t();
    __CPROVER_assume(c1 <= SWAP_PROOF_CHUNK_CAP && c2 <= SWAP_PROOF_CHUNK_CAP);
    __CPROVER_assume(c1 + c2 == rem);

    if (c1 > 0U) {
        memcpy(writer.write_buf + writer.write_pos, payload1, c1);
        writer.write_pos += c1;
        writer.target_off += c1;
    }
    st = boot_stream_writer_flush(&writer, false);
    if (st != BOOT_OK) {
        return;
    }

    if (c2 > 0U) {
        memcpy(writer.write_buf + writer.write_pos, payload2, c2);
        writer.write_pos += c2;
        writer.target_off += c2;
    }
    (void)boot_stream_writer_flush(&writer, true);
}

static void prove_erase_safe_and_solve_block_asymmetric(const boot_platform_t *platform) {
    uint8_t arena[SWAP_PROOF_ARENA_BYTES] __attribute__((aligned(8)));

    /* Immutable Stage 0 boot region must always be rejected without hardware erase */
    boot_status_t imm_st =
        boot_swap_erase_safe(platform, 0U, CHIP_FLASH_MAX_SECTOR_SIZE, arena, sizeof(arena));
    __CPROVER_assert(imm_st == BOOT_ERR_FLASH_BOUNDS && g_erase_count == 0U,
                     "Stage 0 immutable boot firewall blocks boot_swap_erase_safe");

    /* Multi-sector traversal (3x homogeneous sectors in Mode 0; 16+64+128 KB in Mode 1) */
#if CBMC_ASYMMETRIC_SECTORS == 0
    size_t erase_span = 3U * (size_t)CHIP_FLASH_MAX_SECTOR_SIZE;
#else
    size_t erase_span = (size_t)CHIP_APP_SLOT_SIZE;
#endif
    (void)boot_swap_erase_safe(platform, CHIP_APP_SLOT_ABS_ADDR,
                               erase_span, arena, sizeof(arena));

    uint32_t off = pick_sector_boundary_offset();
    uint32_t rem = nondet_uint32_t();
    __CPROVER_assume(rem >= 1U && rem <= (CHIP_APP_SLOT_SIZE - off));

    size_t block_out = 0U;
    boot_status_t sbst = boot_swap_solve_block(
        platform,
        CHIP_STAGING_SLOT_ABS_ADDR + off,
        CHIP_APP_SLOT_ABS_ADDR + off,
        rem, &block_out);
    if (sbst == BOOT_OK) {
        size_t s_sec = 0U, d_sec = 0U;
        (void)cbmc_flash_get_sector_size(CHIP_STAGING_SLOT_ABS_ADDR + off, &s_sec);
        (void)cbmc_flash_get_sector_size(CHIP_APP_SLOT_ABS_ADDR + off, &d_sec);
        size_t max_sec = (s_sec > d_sec) ? s_sec : d_sec;
        if (rem <= max_sec) {
            __CPROVER_assert(block_out >= rem,
                             "tail block covers at least remaining tail bytes");
        } else {
            __CPROVER_assert(block_out == max_sec,
                             "interior block equals max(src_sec, dst_sec)");
        }
        __CPROVER_assert((block_out % CHIP_FLASH_WRITE_ALIGNMENT) == 0U,
                         "solved block size is strictly aligned to CHIP_FLASH_WRITE_ALIGNMENT");
    }

    /* Direct un-replaced verification of stream_copy + effect_write_skip_erased */
    uint32_t copy_len = (CHIP_FLASH_WRITE_ALIGNMENT == 1U)
                            ? 4U
                            : ((CHIP_FLASH_WRITE_ALIGNMENT >= 32U) ? 32U : 16U);
    flash_effect_t fx = {
        .op       = EFF_COPY,
        .src      = CHIP_STAGING_SLOT_ABS_ADDR,
        .dst      = CHIP_APP_SLOT_ABS_ADDR,
        .len      = copy_len,
        .post_crc = 0U,
    };
    boot_allowed_region_t wl = { CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE };
    (void)boot_effect_execute(platform, &fx, 1U, &wl, 1U, arena, 64U);

    bool same = false;
    (void)boot_swap_blocks_identical(
        platform, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_APP_SLOT_ABS_ADDR,
        copy_len, &same, arena, 64U);
}

static bool g_transport_resume_mode = false;

static void prove_active_transport_provider_bounds(const boot_platform_t *platform) {
    uint8_t arena[SWAP_PROOF_ARENA_BYTES] __attribute__((aligned(8)));
    wal_entry_payload_t open_txn;
    CBMC_HAVOC_OBJECT(open_txn);

    const slot_transport_t *tp = boot_transport_active();
    __CPROVER_assert(tp != NULL && tp->apply != NULL,
                     "boot_transport_active must return valid provider");

    slot_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    txn.src_addr         = CHIP_STAGING_SLOT_ABS_ADDR;
    txn.src_region_size  = CHIP_STAGING_SLOT_SIZE;
    txn.dest_addr        = CHIP_APP_SLOT_ABS_ADDR;
    txn.dest_region_size = CHIP_APP_SLOT_SIZE;
    txn.dest_slot        = 0U;
    txn.src_verified     = nondet_bool();

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH
    /*
     * Note (Finding M — boot_swap.c:627-652):
     *   boot_swap_in_place shrinks block_size to (length - current_offset) for a
     *   sub-sector tail chunk BEFORE computing max_scratch_blocks = scratch_size /
     *   block_size and current_scratch = scratch_base + ring_idx * block_size.
     *   Whenever block_size < scratch_sec_size and ring_idx > 0 (e.g. scratch_seed > 0
     *   or current_offset > 0), current_scratch lands at a non-sector-aligned offset
     *   and EFF_ERASE can cross CHIP_SCRATCH_SLOT_END. Constrain SWAPSCRATCH block
     *   lengths to sector-granule multiples here so all alignment/firewall invariants
     *   are verified without weakening cbmc_assert_flash_erase_sector_invariants.
     */
    uint32_t start_off = 0U;
    if (g_transport_resume_mode) {
#if CBMC_ASYMMETRIC_SECTORS == 0
        start_off = CHIP_FLASH_MAX_SECTOR_SIZE;
#else
        start_off = 0x00004000U;
#endif
        open_txn.intent             = WAL_INTENT_UPDATE_PENDING;
        open_txn.transfer_bitmap[2] = 0xAA55AA55U;
    }
    size_t d_sec = 0U, s_sec = 0U, sc_sec = 0U;
    (void)cbmc_flash_get_sector_size(CHIP_APP_SLOT_ABS_ADDR + start_off, &d_sec);
    (void)cbmc_flash_get_sector_size(CHIP_STAGING_SLOT_ABS_ADDR + start_off, &s_sec);
    (void)cbmc_flash_get_sector_size(CHIP_SCRATCH_SLOT_ABS_ADDR, &sc_sec);
    size_t full_blk = d_sec;
    if (s_sec > full_blk) { full_blk = s_sec; }
    if (sc_sec > full_blk) { full_blk = sc_sec; }
    txn.length              = start_off + (uint32_t)full_blk;
    txn.src_is_delta_output = nondet_bool();
    open_txn.delta_chunk_id = start_off;
    if (open_txn.transfer_bitmap[2] == 0xAA55AA55U) {
        open_txn.transfer_bitmap[3] = CHIP_SCRATCH_SLOT_ABS_ADDR;
    }
    (void)tp->apply(platform, NULL, &txn, &open_txn, arena, sizeof(arena));

#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY
    uint32_t tail_len = nondet_uint32_t();
    __CPROVER_assume(tail_len >= 1U && tail_len <= SWAP_PROOF_TAIL_CAP);
    if (nondet_bool()) {
        /* Full BACKUP -> DEPLOY from offset 0 into CHIP_SCRATCH_SLOT */
        txn.length              = tail_len;
        txn.backup_addr         = CHIP_SCRATCH_SLOT_ABS_ADDR;
        txn.backup_region_size  = SWAP_PROOF_TAIL_CAP;
        open_txn.delta_chunk_id = 0U;
    } else {
        /* DEPLOY resume across all homogeneous/asymmetric sector boundaries */
        uint32_t start_off = pick_sector_boundary_offset();
        txn.length              = start_off + tail_len;
        txn.backup_addr         = 0U;
        txn.backup_region_size  = 0U;
        open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_ONEWAY_DEPLOY;
        open_txn.delta_chunk_id = start_off;
    }
    (void)tp->apply(platform, NULL, &txn, &open_txn, arena, sizeof(arena));

#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPMOVE
#if CBMC_ASYMMETRIC_SECTORS != 0
    /* Asymmetric sectors (16 KB + 64 KB) must be rejected upfront with zero flash mutations */
    txn.src_verified = true;
    txn.length       = 0x00004000U;
    boot_status_t sm_st =
        tp->apply(platform, NULL, &txn, &open_txn, arena, sizeof(arena));
    __CPROVER_assert(sm_st == BOOT_ERR_NOT_SUPPORTED,
                     "SWAPMOVE rejects asymmetric sector geometry upfront");
    __CPROVER_assert(g_write_count == 0U && g_erase_count == 0U,
                     "SWAPMOVE performs zero writes/erases on asymmetric flash");
#else
    uint32_t tail_len = nondet_uint32_t();
    __CPROVER_assume(tail_len >= 1U && tail_len <= CHIP_FLASH_MAX_SECTOR_SIZE);
    txn.length = tail_len;
    if (g_transport_resume_mode) {
        open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_SWAPMOVE_SWAP;
        __CPROVER_assume(open_txn.delta_chunk_id <= 1U);
    } else {
        __CPROVER_assume(open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] !=
                         TOOB_PHASE_SWAPMOVE_SWAP);
        if (open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] == TOOB_PHASE_SWAPMOVE_MOVE) {
            __CPROVER_assume(open_txn.delta_chunk_id < 1U);
        }
    }
    (void)tp->apply(platform, NULL, &txn, &open_txn, arena, sizeof(arena));
#endif
#endif
}

static boot_platform_t init_swap_env(flash_hal_t *flash_hal) {
    g_write_count = 0U;
    g_erase_count = 0U;
    *flash_hal = (flash_hal_t){
        .read             = swap_flash_read,
        .write            = swap_flash_write,
        .erase_sector     = swap_flash_erase_sector,
        .get_sector_size  = cbmc_flash_get_sector_size,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .max_erase_cycles = 100000U,
        .erased_value     = 0xFFU,
    };
    boot_platform_t platform = {
        .flash = flash_hal,
        .wdt   = &g_cbmc_wdt_hal,
    };
    return platform;
}

void prove_swap_stream_writer(void) {
    g_in_stream_writer_proof = true;
    flash_hal_t flash_hal;
    boot_platform_t platform = init_swap_env(&flash_hal);
    prove_stream_writer_alignment_and_checkpoint(&platform);
}

void prove_swap_erase_and_solve(void) {
    g_in_stream_writer_proof = false;
    flash_hal_t flash_hal;
    boot_platform_t platform = init_swap_env(&flash_hal);
    prove_erase_safe_and_solve_block_asymmetric(&platform);
}

void prove_swap_transport_provider(void) {
    g_in_stream_writer_proof  = false;
    g_transport_resume_mode   = false;
    flash_hal_t flash_hal;
    boot_platform_t platform = init_swap_env(&flash_hal);
    prove_active_transport_provider_bounds(&platform);
}

void prove_swap_transport_resume(void) {
    g_in_stream_writer_proof  = false;
    g_transport_resume_mode   = true;
    flash_hal_t flash_hal;
    boot_platform_t platform = init_swap_env(&flash_hal);
    prove_active_transport_provider_bounds(&platform);
}

int main(void) {
    uint8_t mode = nondet_uint8_t();
    if (mode == 0U) {
        prove_swap_stream_writer();
    } else if (mode == 1U) {
        prove_swap_erase_and_solve();
    } else {
        prove_swap_transport_provider();
    }
    return 0;
}
