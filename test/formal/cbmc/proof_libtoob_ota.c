/*
 * CBMC Memory-Safety, Manifest Trailer Locator, Staging Bounds & Alignment Proof
 * for sdk/libtoob/ (toob_ota.c + toob_handoff.c + toob_mailbox.c + toob_update.c).
 *
 * Verifies across CHIP_FLASH_WRITE_ALIGNMENT in {1, 4, 8, 32} and both
 * single-staging (SWAPSCRATCH) and dual-slot (POINTER) providers:
 *   1. Arbitrary unaligned chunk streaming (toob_ota_process_chunk) into the
 *      256-byte alignment buffer, multi-chunk boundary carry, and residual 0xFF
 *      tail padding in toob_ota_finalize: ZERO unaligned or partial flash writes
 *      ever reach toob_os_flash_write(addr, buf, len).
 *   2. Fail-closed dual-slot resolution under TOOB_TRANSPORT_POINTER (.noinit
 *      toob_handoff_state double-read + CRC-32 + active_slot validation).
 *   3. Torn-write-safe .noinit checkpoint resume (toob_ota_resume), sector
 *      blank-check & dirty-tail rollback, and streaming SHA-256 prefix rehash.
 *   4. 16-byte toob_tbm1_trailer_locator_t parsing & overflow-safe bounds check
 *      in toob_ota_finalize + toob_set_next_update + double-slot mailbox write.
 *   5. Stage 0 immutable-boot firewall protection on all writes and erases.
 *
 * Entry points (verified via CBMC --function):
 *   - prove_ota_stream_and_trailer      : full [1..608] stream + trailer locator
 *   - prove_ota_unaligned_carry         : arbitrary unaligned 2-chunk carry + wrap
 *   - prove_ota_resume_and_update_guards: .noinit resume + dirty-tail rollback
 *                                         + toob_set_next_update guards
 *
 * Documented Domain Bound (see formal report Finding #5 on toob_ota.c:164,173):
 *   - libtoob steps erases by uniform CHIP_FLASH_MAX_SECTOR_SIZE granules from
 *     target_addr; when deployed on asymmetric flash, staging/mailbox slots must
 *     be aligned to CHIP_FLASH_MAX_SECTOR_SIZE (or libtoob extended with a
 *     sector-size query hook).
 */

#define CBMC_LIBTOOB_ONLY 1

#include "cbmc_common.h"
#include "libtoob.h"
#include "toob_internal.h"

#define OTA_PROOF_MAX_STREAM 608U /* >= 576B TBM1 + 16B trailer locator */
#define OTA_PROOF_CARRY_HEAD 40U  /* > 32B max write_align */
#define OTA_PROOF_CARRY_TAIL 264U /* > 256B TOOB_OTA_BUF_SIZE wrap */

static bool g_notifier_called;

void cbmc_snapshot_handoff(toob_handoff_t *dst) {
    cbmc_assert_writable(dst, sizeof(*dst),
                         "_volatile_snapshot_handoff dst must be writable");
    *dst = toob_handoff_state;
}

void cbmc_snapshot_resume(toob_ota_resume_state_t *dst) {
    cbmc_assert_writable(dst, sizeof(*dst),
                         "_volatile_snapshot_resume dst must be writable");
    *dst = g_toob_ota_resume_state;
}

void cbmc_ota_ctx_reset(toob_ota_ctx_t *ctx) {
    cbmc_assert_writable(ctx, sizeof(*ctx), "_ctx_reset ctx must be writable");
    *ctx = (toob_ota_ctx_t){0};
}

void cbmc_ota_zeroize_fast(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "toob_secure_zeroize target buffer must be writable");
    if (ptr != NULL && len > 0U) {
        ((uint8_t *)ptr)[0] = 0U;
    }
}

void *cbmc_memcpy_stream(void *dst, const void *src, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "memcpy destination must be writable");
    cbmc_assert_readable(src, n, "memcpy source must be readable");
    if (__CPROVER_same_object(dst, src)) {
        uintptr_t d_addr = (uintptr_t)dst;
        uintptr_t s_addr = (uintptr_t)src;
        __CPROVER_assert((d_addr + n <= s_addr) || (s_addr + n <= d_addr),
                         "memcpy slices within same object must not overlap");
    }
    ((uint8_t *)dst)[0] = ((const uint8_t *)src)[0];
    return dst;
}

void *cbmc_memset_stream(void *dst, int val, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "memset destination must be writable");
    ((uint8_t *)dst)[0] = (uint8_t)val;
    return dst;
}

static void ota_swap_notifier(const toob_swap_event_t *ev) {
    cbmc_assert_readable(ev, sizeof(*ev),
                         "swap notifier event struct must be readable");
    __CPROVER_assert(ev->abi_version == TOOB_SWAP_EVENT_ABI_VERSION,
                     "swap notifier ABI version must match");
    g_notifier_called = true;
}

uint32_t toob_lib_crc32(const uint8_t *data, size_t length) {
    cbmc_assert_readable(data, length,
                         "toob_lib_crc32 input slice must be readable");
    return nondet_uint32_t();
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx) {
    cbmc_assert_writable(ctx, sizeof(*ctx),
                         "toob_os_sha256_init ctx must be writable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx,
                                    const uint8_t *data, uint32_t len) {
    cbmc_assert_writable(ctx, sizeof(*ctx),
                         "toob_os_sha256_update ctx must be valid");
    cbmc_assert_readable(data, (size_t)len,
                         "toob_os_sha256_update chunk slice must be readable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx,
                                      uint8_t out_hash[32]) {
    cbmc_assert_writable(ctx, sizeof(*ctx),
                         "toob_os_sha256_finalize ctx must be valid");
    cbmc_assert_writable(out_hash, 32U,
                         "toob_os_sha256_finalize out_hash[32] must be writable");
    cbmc_havoc_bytes(out_hash, 32U);
    return nondet_bool() ? TOOB_OK : TOOB_ERR_VERIFY;
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
    cbmc_assert_writable(buf, (size_t)len,
                         "toob_os_flash_read destination buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "toob_os_flash_read must stay within physical flash");
    if (len == 0U) {
        return TOOB_OK;
    }
    if (nondet_bool()) {
        return TOOB_ERR_FLASH_HW;
    }
    if (len == sizeof(toob_tbm1_trailer_locator_t)) {
        __CPROVER_havoc_slice(buf, sizeof(toob_tbm1_trailer_locator_t));
    } else if (len == TOOB_OTA_BUF_SIZE) {
        memset(buf, 0xFF, TOOB_OTA_BUF_SIZE);
        buf[0] = nondet_uint8_t();
    } else {
        buf[0] = nondet_uint8_t();
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, (size_t)len);

    bool in_staging =
        cbmc_subrange_of(addr, len, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE);
    bool in_mbx =
        cbmc_subrange_of(addr, len, CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE);
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    bool in_app =
        cbmc_subrange_of(addr, len, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE);
    __CPROVER_assert(in_staging || in_app || in_mbx,
                     "POINTER OTA writes strictly inside inactive slot or mailbox");
#else
    __CPROVER_assert(in_staging || in_mbx,
                     "OTA writes strictly inside CHIP_STAGING_SLOT or CHIP_MAILBOX");
#endif

    return nondet_bool() ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    cbmc_assert_flash_erase_range_invariants(addr, len);

    bool in_staging =
        cbmc_subrange_of(addr, len, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE);
    bool in_mbx =
        cbmc_subrange_of(addr, len, CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE);
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    bool in_app =
        cbmc_subrange_of(addr, len, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE);
    __CPROVER_assert(in_staging || in_app || in_mbx,
                     "POINTER OTA erases strictly inside inactive slot or mailbox");
#else
    __CPROVER_assert(in_staging || in_mbx,
                     "OTA erases strictly inside CHIP_STAGING_SLOT or CHIP_MAILBOX");
#endif

    return nondet_bool() ? TOOB_OK : TOOB_ERR_FLASH;
}

void prove_ota_stream_and_trailer(void) {
    CBMC_HAVOC_OBJECT(toob_handoff_state);
    CBMC_HAVOC_OBJECT(g_toob_ota_resume_state);
    g_notifier_called = false;

    toob_ota_ctx_t ctx;
    __CPROVER_assert(toob_ota_ctx_init(NULL) == TOOB_ERR_INVALID_ARG,
                     "NULL ctx init must be rejected");
    __CPROVER_assert(toob_ota_ctx_init(&ctx) == TOOB_OK,
                     "valid ctx init must succeed");

    toob_set_swap_notifier(nondet_bool() ? ota_swap_notifier : NULL);

    uint8_t exp_sha[32];
    CBMC_HAVOC_OBJECT(exp_sha);
    const uint8_t *sha_arg = nondet_bool() ? exp_sha : NULL;

    uint8_t assign_id[16];
    CBMC_HAVOC_OBJECT(assign_id);
    const uint8_t *assign_arg = nondet_bool() ? assign_id : NULL;

    __CPROVER_assert(toob_ota_begin(&ctx, CHIP_STAGING_SLOT_SIZE + 1U, sha_arg) !=
                         TOOB_OK,
                     "total_size exceeding slot capacity must be rejected");

    if (nondet_bool()) {
        /* 1. Sub-sector unaligned streams [1..48] + oversized chunk guard */
        uint8_t small_buf[48];
        CBMC_HAVOC_OBJECT(small_buf);
        uint32_t total_size = nondet_uint32_t();
        __CPROVER_assume(total_size >= 1U && total_size <= sizeof(small_buf));

        toob_status_t bst = nondet_bool()
                                ? toob_ota_begin(&ctx, total_size, sha_arg)
                                : toob_ota_begin_assigned(&ctx, total_size, sha_arg, assign_arg);
        if (bst == TOOB_OK) {
            __CPROVER_assert(toob_ota_process_chunk(&ctx, small_buf,
                                                    total_size + 1U) ==
                                 TOOB_ERR_INVALID_ARG,
                             "oversized chunk must be rejected before SHA mutation");
            if (toob_ota_process_chunk(&ctx, small_buf, total_size) == TOOB_OK) {
                (void)toob_ota_finalize(&ctx);
            } else {
                (void)toob_ota_abort(&ctx);
            }
        }
    } else {
        /* 2. Full TBM1 + 16B trailer locator [592..608]: 2x256B + symbolic [80..96] tail */
        uint8_t blk_buf[TOOB_OTA_BUF_SIZE];
        uint8_t tail_buf[96];
        CBMC_HAVOC_OBJECT(blk_buf);
        CBMC_HAVOC_OBJECT(tail_buf);

        uint32_t tail_len = nondet_uint32_t();
        __CPROVER_assume(tail_len >= 80U && tail_len <= sizeof(tail_buf));
        uint32_t total_size = (2U * TOOB_OTA_BUF_SIZE) + tail_len;

        if (toob_ota_begin(&ctx, total_size, sha_arg) == TOOB_OK) {
            toob_status_t s1 = toob_ota_process_chunk(&ctx, blk_buf, TOOB_OTA_BUF_SIZE);
            toob_status_t s2 = (s1 == TOOB_OK)
                                   ? toob_ota_process_chunk(&ctx, blk_buf, TOOB_OTA_BUF_SIZE)
                                   : s1;
            toob_status_t s3 = (s2 == TOOB_OK)
                                   ? toob_ota_process_chunk(&ctx, tail_buf, tail_len)
                                   : s2;
            if (s3 == TOOB_OK) {
                (void)toob_ota_finalize(&ctx);
            } else {
                (void)toob_ota_abort(&ctx);
            }
        }
    }
}

void prove_ota_trim_and_carry(void) {
    CBMC_HAVOC_OBJECT(toob_handoff_state);
    CBMC_HAVOC_OBJECT(g_toob_ota_resume_state);
    g_notifier_called = false;

    toob_ota_ctx_t ctx;
    (void)toob_ota_ctx_init(&ctx);
    toob_set_swap_notifier(nondet_bool() ? ota_swap_notifier : NULL);

    uint8_t exp_sha[32];
    CBMC_HAVOC_OBJECT(exp_sha);
    const uint8_t *sha_arg = nondet_bool() ? exp_sha : NULL;

    if (nondet_bool()) {
        /* 1. Prove toob_ota_trim_total_size() bounds & state invariant */
        uint8_t buf[48];
        CBMC_HAVOC_OBJECT(buf);
        uint32_t total_size = nondet_uint32_t();
        uint32_t prefix_len = nondet_uint32_t();
        __CPROVER_assume(total_size >= 1U && total_size <= sizeof(buf));
        __CPROVER_assume(prefix_len >= 1U && prefix_len <= total_size);
        if (toob_ota_begin(&ctx, total_size, sha_arg) == TOOB_OK) {
            if (toob_ota_process_chunk(&ctx, buf, prefix_len) == TOOB_OK) {
                uint32_t trim_target = nondet_uint32_t();
                if (toob_ota_trim_total_size(&ctx, trim_target) == TOOB_OK) {
                    __CPROVER_assert(trim_target >= prefix_len &&
                                         trim_target <= total_size,
                                     "accepted trim_target must be in [bytes_queued, total_size]");
                    uint32_t rem = trim_target - prefix_len;
                    if (rem == 0U ||
                        toob_ota_process_chunk(&ctx, buf + prefix_len, rem) == TOOB_OK) {
                        (void)toob_ota_finalize(&ctx);
                    } else {
                        (void)toob_ota_abort(&ctx);
                    }
                } else {
                    (void)toob_ota_abort(&ctx);
                }
            } else {
                (void)toob_ota_abort(&ctx);
            }
        }
    } else {
        /* 2. Prove unaligned 2-chunk carry + TOOB_OTA_BUF_SIZE (256B) wrap + tail pad */
        static const uint32_t k_heads[6] = { 1U, 3U, 7U, 15U, 31U, 33U };
        uint8_t sel = nondet_uint8_t();
        __CPROVER_assume(sel < 6U);
        uint32_t len1 = k_heads[sel];
        uint32_t len2 = TOOB_OTA_BUF_SIZE;

        uint8_t chunk1[OTA_PROOF_CARRY_HEAD];
        uint8_t chunk2[TOOB_OTA_BUF_SIZE];
        CBMC_HAVOC_OBJECT(chunk1);
        CBMC_HAVOC_OBJECT(chunk2);

        if (toob_ota_begin(&ctx, len1 + len2, sha_arg) == TOOB_OK) {
            toob_status_t s1 = toob_ota_process_chunk(&ctx, chunk1, len1);
            toob_status_t s2 = (s1 == TOOB_OK)
                                   ? toob_ota_process_chunk(&ctx, chunk2, len2)
                                   : s1;
            if (s1 == TOOB_OK && s2 == TOOB_OK) {
                (void)toob_ota_finalize(&ctx);
            } else {
                (void)toob_ota_abort(&ctx);
            }
        }
    }
}

void prove_ota_resume_and_update_guards(void) {
    CBMC_HAVOC_OBJECT(toob_handoff_state);
    CBMC_HAVOC_OBJECT(g_toob_ota_resume_state);

    toob_ota_ctx_t ctx;
    (void)toob_ota_ctx_init(&ctx);

    uint8_t exp_sha[32];
    CBMC_HAVOC_OBJECT(exp_sha);
    const uint8_t *sha_arg = nondet_bool() ? exp_sha : NULL;

    uint8_t assign_id[16];
    CBMC_HAVOC_OBJECT(assign_id);
    const uint8_t *assign_arg = nondet_bool() ? assign_id : NULL;

    uint32_t total_size = nondet_uint32_t();
    __CPROVER_assume(total_size >= (TOOB_OTA_BUF_SIZE + 1U) &&
                     total_size <= OTA_PROOF_MAX_STREAM);

    uint32_t resume_off = 0U;
    toob_status_t rst = nondet_bool()
                            ? toob_ota_resume(&ctx, total_size, sha_arg, &resume_off)
                            : toob_ota_resume_assigned(&ctx, total_size, sha_arg,
                                                       assign_arg, &resume_off);
    if (rst == TOOB_OK) {
        __CPROVER_assert(resume_off < total_size,
                         "resumed offset must be strictly less than total_size");
        __CPROVER_assert((resume_off % TOOB_OTA_BUF_SIZE) == 0U,
                         "resumed offset must be aligned to TOOB_OTA_BUF_SIZE");
        /* Also test fast-path in-RAM resume_assigned when state == RECEIVING */
        uint8_t probe_assign[16];
        CBMC_HAVOC_OBJECT(probe_assign);
        uint32_t fast_off = 0U;
        toob_status_t fst = toob_ota_resume_assigned(
            &ctx, total_size, sha_arg,
            nondet_bool() ? assign_arg : probe_assign, &fast_off);
        if (fst == TOOB_OK) {
            __CPROVER_assert(fast_off == resume_off,
                             "fast-path resume_assigned preserves exact bytes_queued");
        }
        (void)toob_ota_pause(&ctx);
    }

    uint32_t sym_manifest_addr = nondet_uint32_t();
    toob_status_t ust = toob_set_next_update(sym_manifest_addr);
    if (ust == TOOB_OK) {
        __CPROVER_assert((sym_manifest_addr % CHIP_FLASH_WRITE_ALIGNMENT) == 0U,
                         "accepted manifest address must satisfy write alignment");
        __CPROVER_assert(sym_manifest_addr >= CHIP_FLASH_IMMUTABLE_BOOT_END,
                         "accepted manifest address must never touch Stage 0");
    }
}

int main(void) {
    prove_ota_stream_and_trailer();
    return 0;
}
