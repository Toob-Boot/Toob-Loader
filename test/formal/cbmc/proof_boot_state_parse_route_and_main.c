/*
 * FV-07: CBMC Production boot_state.c (NO TOOB_MOCK_TEST) & boot_main.c Proof
 *
 * Targets:
 *   - toobloader/core/boot_state.c (compiled WITHOUT TOOB_MOCK_TEST)
 *   - toobloader/core/boot_main.c
 *   - toobloader/core/boot_tbm1.c
 *   - toobloader/core/utils/boot_diag.c
 *   - toobloader/core/utils/boot_identity.c
 *   - toobloader/core/boot_platform_bringup.c
 *   - toobloader/core/boot_transport.c
 *   - toobloader/core/utils/boot_crc32.c
 *
 * Proves:
 *   1. stage_parse (Head-TBM1 & sector-aligned Trailer-TBM1 auto-discovery +
 *      real tbm1_precheck / tbm1_validate) and stage_route across Raw,
 *      Heatshrink Decomp, TDS1 Delta, and Multi-Image Stage-1/Netcore bundles.
 *   2. Non-aliasing crypto_arena slicing in stage_apply_raw, stage_apply_decomp,
 *      and stage_apply_delta: chunk_hashes slice and streaming scratch/decomp/delta
 *      slice are strictly disjoint and within crypto_arena[BOOT_CRYPTO_ARENA_SIZE].
 *   3. WAL_TMR_VERSION_8 pending/ratified identity lifecycle (TDR1-02) and
 *      TDR1-03 commit-point discipline (candidate metadata / outcome==1 never
 *      published to toob_diag_state when swap or commit fails).
 *   4. Cloud-command & lock-gate invariants including HIGH-32 (FORCE_UPDATE
 *      dropped when WAL_INTENT_DEVICE_LOCKED; locked boot traps to boot_panic).
 *   5. boot_main.c HAL ABI V2/V3 gate, max_erase_cycles >= 4 guard, reverse-order
 *      init_cleanup deinit cascade, HIGH-29 XIP bounds + 128B VTOR alignment
 *      (0x7FU), boot_diag_seal() + toob_handoff_state sealing, and arena zeroize.
 *
 * Note (Finding F — boot_state.c:1806):
 *   In evaluate_transition() ACT_CRASH_ACCUM, current_tmr->recovery_failure_counter++
 *   lacks a UINT32_MAX saturation guard; TMR mock bounds recovery_failure_counter < UINT32_MAX.
 */

#define CBMC_NO_BOOT_PANIC_STUB
#include "cbmc_common.h"

#include "boot_cloud_cmd.h"
#include "boot_decomp.h"
#include "boot_delta.h"
#include "boot_diag.h"
#include "boot_effect.h"
#include "boot_identity.h"
#include "boot_journal.h"
#include "boot_mailbox.h"
#include "boot_main.h"
#include "boot_merkle.h"
#include "boot_multiimage.h"
#include "boot_platform_bringup.h"
#include "boot_proof.h"
#include "boot_provisioning.h"
#include "boot_rollback.h"
#include "boot_slot_caps.h"
#include "boot_state.h"
#include "boot_swap.h"
#include "boot_tbm1.h"
#include "boot_transport.h"
#include "boot_verify.h"

extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];
extern TOOB_NOINIT_VAR(toob_handoff_state) toob_handoff_t toob_handoff_state;

static wal_tmr_payload_t   g_tmr_state;
static wal_entry_payload_t g_txn_state;
static bool                g_tmr_updated;
static bool                g_transport_failed;
static bool                g_main_fast_mode;
static boot_status_t       g_last_panic_reason;
static uint32_t            g_init_order_depth;

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    (void)platform;
    g_last_panic_reason = reason;
    __CPROVER_assert(reason != BOOT_OK, "boot_panic must never be invoked with BOOT_OK");
    __CPROVER_assume(false);
    while (true) {
    }
}

/* ==========================================================================
 * Sound Leaf-Engine Contracts (Concrete engines proven in dedicated harnesses)
 * ========================================================================== */

static bool ptr_in_arena(const void *p, size_t len) {
    uintptr_t base = (uintptr_t)crypto_arena;
    uintptr_t end  = base + (uintptr_t)BOOT_CRYPTO_ARENA_SIZE;
    uintptr_t addr = (uintptr_t)p;
    return (addr >= base) && (len <= BOOT_CRYPTO_ARENA_SIZE) &&
           (addr <= end - len);
}

static bool slices_disjoint(const void *a, size_t a_len,
                            const void *b, size_t b_len) {
    if (a_len == 0U || b_len == 0U) {
        return true;
    }
    uintptr_t a0 = (uintptr_t)a;
    uintptr_t a1 = a0 + (uintptr_t)a_len;
    uintptr_t b0 = (uintptr_t)b;
    uintptr_t b1 = b0 + (uintptr_t)b_len;
    return (a1 <= b0) || (b1 <= a0);
}

boot_status_t boot_journal_init(const boot_platform_t *platform) {
    __CPROVER_assert(platform != NULL, "boot_journal_init requires platform");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

void boot_journal_set_tmr_defer(bool defer) {
    (void)defer;
}

boot_status_t boot_journal_flush_tmr(const boot_platform_t *platform) {
    __CPROVER_assert(platform != NULL, "boot_journal_flush_tmr requires platform");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr) {
    __CPROVER_assert(platform != NULL && out_tmr != NULL &&
                         __CPROVER_w_ok(out_tmr, sizeof(*out_tmr)),
                     "boot_journal_get_tmr preconditions");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_tmr = g_tmr_state;
    return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
    __CPROVER_assert(platform != NULL && new_tmr != NULL &&
                         __CPROVER_r_ok(new_tmr, sizeof(*new_tmr)),
                     "boot_journal_update_tmr preconditions");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    g_tmr_state   = *new_tmr;
    g_tmr_updated = true;
    return BOOT_OK;
}

boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry) {
    __CPROVER_assert(platform != NULL && new_entry != NULL &&
                         __CPROVER_r_ok(new_entry, sizeof(*new_entry)),
                     "boot_journal_append preconditions");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    g_txn_state = *new_entry;
    return BOOT_OK;
}

boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform,
                                           wal_entry_payload_t *out_state,
                                           uint32_t *out_net_accum,
                                           uint32_t *out_resume_offset) {
    __CPROVER_assert(platform != NULL && out_state != NULL &&
                         __CPROVER_w_ok(out_state, sizeof(*out_state)),
                     "boot_journal_reconstruct_txn preconditions");
    if (out_net_accum != NULL) {
        *out_net_accum = nondet_uint32_t();
    }
    if (out_resume_offset != NULL) {
        *out_resume_offset = nondet_uint32_t();
    }
    uint8_t mode = nondet_uint8_t();
    if (mode == 0U) {
        return BOOT_ERR_FLASH_HW;
    }
    if (mode == 1U && g_txn_state.intent != WAL_INTENT_DEVICE_LOCKED) {
        return BOOT_ERR_STATE;
    }
    *out_state = g_txn_state;
    if (g_main_fast_mode && out_state->intent == WAL_INTENT_UPDATE_PENDING) {
        out_state->intent = WAL_INTENT_TXN_COMMIT;
    }
    return BOOT_OK;
}

boot_status_t boot_journal_reconstruct_aux_heal(const boot_platform_t *platform,
                                                wal_entry_payload_t *out_heal,
                                                bool *out_found) {
    __CPROVER_assert(platform != NULL && out_heal != NULL && out_found != NULL &&
                         __CPROVER_w_ok(out_heal, sizeof(*out_heal)) &&
                         __CPROVER_w_ok(out_found, sizeof(*out_found)),
                     "boot_journal_reconstruct_aux_heal preconditions");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_found = nondet_bool();
    if (*out_found) {
        CBMC_HAVOC_OBJECT(*out_heal);
    } else {
        memset(out_heal, 0, sizeof(*out_heal));
    }
    return BOOT_OK;
}

boot_status_t boot_mailbox_consume(const boot_platform_t *platform) {
    __CPROVER_assert(platform != NULL, "boot_mailbox_consume requires platform");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static bool            g_force_cloud_cmd;
static bool            g_skip_unlocked_force_update;
static toob_cloud_cmd_t g_forced_cmd;

boot_status_t boot_cloud_cmd_evaluate_flash(const boot_platform_t *platform,
                                            uint8_t *arena,
                                            toob_cloud_cmd_t *out_cmd) {
    __CPROVER_assert(platform != NULL && arena != NULL && out_cmd != NULL,
                     "boot_cloud_cmd_evaluate_flash non-null preconditions");
    __CPROVER_assert(ptr_in_arena(arena, 512U),
                     "boot_cloud_cmd_evaluate_flash arena must reside in crypto_arena");
    if (g_force_cloud_cmd) {
        *out_cmd = g_forced_cmd;
        return BOOT_OK;
    }
    if (g_main_fast_mode || nondet_bool()) {
        return BOOT_ERR_NOT_FOUND;
    }
    uint8_t c = nondet_uint8_t();
    __CPROVER_assume(c <= (uint8_t)TOOB_CMD_WIPE);
    if (g_skip_unlocked_force_update) {
        __CPROVER_assume(c != (uint8_t)TOOB_CMD_FORCE_UPDATE);
    }
    *out_cmd = (toob_cloud_cmd_t)c;
    return BOOT_OK;
}

boot_status_t boot_verify_manifest_envelope(const boot_platform_t *platform,
                                            const boot_verify_envelope_t *env,
                                            uint8_t *arena,
                                            size_t arena_len) {
    __CPROVER_assert(platform != NULL && env != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_verify_manifest_envelope preconditions");
    cbmc_assert_readable(env->signature_ed25519, 64U,
                         "Ed25519 signature slice in TBM1 arena must be readable");
    __CPROVER_assert(env->manifest_size >= TBM1_FIXED_LEN,
                     "signed manifest length covers at least TBM1_FIXED_LEN");
#if TOOB_PQC_ENABLED
    if (env->pqc_hybrid_active) {
        cbmc_assert_readable(env->signature_pqc, env->signature_pqc_len,
                             "PQC signature slice must be readable");
        cbmc_assert_readable(env->pubkey_pqc, env->pubkey_pqc_len,
                             "PQC pubkey slice must be readable");
    }
#endif
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

boot_status_t boot_rollback_verify_svn(const boot_platform_t *platform,
                                       uint32_t manifest_svn,
                                       rollback_target_t target) {
    (void)manifest_svn;
    __CPROVER_assert(platform != NULL, "boot_rollback_verify_svn requires platform");
    __CPROVER_assert(target == ROLLBACK_TARGET_APP ||
                         target == ROLLBACK_TARGET_RECOVERY ||
                         target == ROLLBACK_TARGET_STAGE1,
                     "boot_rollback_verify_svn target must be valid");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_DOWNGRADE;
}

boot_status_t boot_rollback_evaluate_os(const boot_platform_t *platform,
                                        const wal_tmr_payload_t *tmr,
                                        bool *boot_recovery_os_out) {
    __CPROVER_assert(platform != NULL && tmr != NULL && boot_recovery_os_out != NULL &&
                         __CPROVER_w_ok(boot_recovery_os_out, sizeof(*boot_recovery_os_out)),
                     "boot_rollback_evaluate_os preconditions");
    if (tmr->boot_failure_counter <= BOOT_CONFIG_MAX_RETRIES) {
        *boot_recovery_os_out = false;
        return BOOT_OK;
    }
    if (tmr->recovery_failure_counter <= BOOT_CONFIG_MAX_RECOVERY_RETRIES) {
        *boot_recovery_os_out = true;
        return BOOT_OK;
    }
    boot_panic(platform, BOOT_RECOVERY_REQUESTED);
    return BOOT_ERR_INVALID_STATE;
}

boot_status_t boot_decomp_apply(const boot_platform_t *platform,
                                uint32_t src_addr,
                                uint32_t comp_size,
                                uint32_t dst_addr,
                                uint32_t dst_slot_size,
                                uint32_t expected_uncomp_size,
                                wal_entry_payload_t *open_txn,
                                uint8_t *arena,
                                size_t arena_len) {
    __CPROVER_assert(platform != NULL && open_txn != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_decomp_apply arena must be writable");
    __CPROVER_assert(ptr_in_arena(arena, arena_len),
                     "decomp_arena must lie strictly within crypto_arena");
    __CPROVER_assert(expected_uncomp_size > sizeof(toob_image_header_t) &&
                         expected_uncomp_size <= dst_slot_size,
                     "decomp expected_uncomp_size must fit stream_dest_size");
    __CPROVER_assert(cbmc_range_in_mutable_partition(src_addr, comp_size) &&
                         cbmc_range_in_mutable_partition(dst_addr, expected_uncomp_size),
                     "decomp source and destination must reside in mutable slots");
    /* Scrub decomp_arena to catch any illicit aliasing with preserved hash_arena */
    if (arena_len > 0U) {
        arena[0] = 0xA5U;
        arena[arena_len - 1U] = 0x5AU;
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

boot_status_t boot_delta_apply(const boot_platform_t *platform,
                               uint32_t delta_flash_addr,
                               uint32_t delta_size,
                               uint32_t target_flash_addr,
                               uint32_t target_slot_size,
                               uint32_t base_flash_addr,
                               uint32_t base_image_size,
                               wal_entry_payload_t *open_txn,
                               uint8_t *arena,
                               size_t arena_len) {
    __CPROVER_assert(platform != NULL && open_txn != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_delta_apply arena must be writable");
    __CPROVER_assert(ptr_in_arena(arena, arena_len),
                     "delta_arena must lie strictly within crypto_arena");
    __CPROVER_assert(cbmc_range_in_mutable_partition(delta_flash_addr, delta_size) &&
                         cbmc_range_in_mutable_partition(target_flash_addr, target_slot_size),
                     "delta source and destination must reside in mutable slots");
    if (base_image_size > 0U) {
        __CPROVER_assert(cbmc_range_in_mutable_partition(base_flash_addr, base_image_size),
                         "delta base image must reside in a valid bootable slot");
    }
    if (arena_len > 0U) {
        arena[0] = 0x3CU;
        arena[arena_len - 1U] = 0xC3U;
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

boot_status_t boot_merkle_verify_stream(const boot_platform_t *platform,
                                        uint32_t image_flash_addr,
                                        uint32_t image_size,
                                        uint32_t chunk_size,
                                        const uint8_t *chunk_hashes,
                                        size_t chunk_hashes_len,
                                        uint32_t num_chunks,
                                        uint8_t *scratch,
                                        size_t scratch_len) {
    (void)chunk_size;
    (void)num_chunks;
    __CPROVER_assert(platform != NULL && chunk_hashes != NULL && scratch != NULL,
                     "boot_merkle_verify_stream non-null pointers");
    cbmc_assert_readable(chunk_hashes, chunk_hashes_len,
                         "chunk_hashes slice in crypto_arena must be readable");
    cbmc_assert_writable(scratch, scratch_len,
                         "scratch slice in crypto_arena must be writable");
    __CPROVER_assert(ptr_in_arena(chunk_hashes, chunk_hashes_len) &&
                         ptr_in_arena(scratch, scratch_len),
                     "both chunk_hashes and scratch slices must stay inside crypto_arena");
    __CPROVER_assert(slices_disjoint(chunk_hashes, chunk_hashes_len, scratch, scratch_len),
                     "crypto_arena chunk_hashes and scratch slices must NEVER overlap");
    __CPROVER_assert(cbmc_range_in_mutable_partition(image_flash_addr, image_size),
                     "Merkle verified image must lie inside a mutable flash partition");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

boot_status_t boot_effect_admit_or_defer(const boot_platform_t *platform,
                                         const wal_tmr_payload_t *tmr,
                                         uint32_t image_size,
                                         const boot_component_t *components,
                                         size_t num_components,
                                         bool requires_swap) {
    (void)requires_swap;
    __CPROVER_assert(platform != NULL && tmr != NULL,
                     "boot_effect_admit_or_defer requires platform and tmr");
    __CPROVER_assert(image_size <= CHIP_APP_SLOT_SIZE,
                     "stage_route bounds image_size <= CHIP_APP_SLOT_SIZE before admission");
    if (num_components > 0U) {
        cbmc_assert_readable(components, num_components * sizeof(boot_component_t),
                             "components array must be readable");
    }
    uint8_t r = nondet_uint8_t();
    if (r == 0U) {
        return BOOT_ERR_DEFER;
    }
    if (r == 1U) {
        return BOOT_ERR_COUNTER_EXHAUSTED;
    }
    return BOOT_OK;
}

boot_status_t boot_multiimage_apply(const boot_platform_t *platform,
                                    uint32_t staging_base,
                                    const boot_component_t *components,
                                    uint32_t num_components,
                                    const boot_allowed_region_t *whitelist,
                                    uint32_t num_regions,
                                    wal_entry_payload_t *open_txn,
                                    uint8_t *arena,
                                    size_t arena_len) {
    (void)staging_base;
    __CPROVER_assert(platform != NULL && components != NULL && whitelist != NULL &&
                         open_txn != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_multiimage_apply preconditions");
    __CPROVER_assert(num_components <= 3U && num_regions == 4U,
                     "stage_swap passes bounded secondary component list");
    for (uint32_t i = 0U; i < num_components; i++) {
        __CPROVER_assert(components[i].component_id >= 1U &&
                             components[i].component_id < 32U,
                         "CRIT-30: secondary component_id fits in transfer_bitmap[0]");
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

boot_status_t boot_swap_erase_safe(const boot_platform_t *platform,
                                   uint32_t start_addr,
                                   size_t length,
                                   uint8_t *arena,
                                   size_t arena_len) {
    __CPROVER_assert(platform != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_swap_erase_safe arena preconditions");
    __CPROVER_assert(cbmc_range_in_mutable_partition(start_addr, length),
                     "boot_swap_erase_safe target must be mutable");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_delay_with_wdt(const boot_platform_t *platform, uint32_t ms) {
    (void)ms;
    __CPROVER_assert(platform != NULL, "boot_delay_with_wdt requires platform");
    return BOOT_OK;
}

_Noreturn void boot_provisioning_run(const boot_platform_t *platform,
                                     uint8_t *arena,
                                     size_t arena_len) {
    __CPROVER_assert(platform != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_provisioning_run preconditions");
    __CPROVER_assume(false);
    while (true) {
    }
}

static boot_status_t fv07_transport_apply(const boot_platform_t *platform,
                                          const slot_caps_t *caps,
                                          slot_txn_t *txn,
                                          wal_entry_payload_t *open_txn,
                                          uint8_t *arena,
                                          size_t arena_len) {
    __CPROVER_assert(platform != NULL && caps != NULL && txn != NULL &&
                         open_txn != NULL && arena != NULL &&
                         __CPROVER_w_ok(arena, arena_len),
                     "transport->apply pointer and arena preconditions");
    __CPROVER_assert(txn->src_verified,
                     "stage_swap must never invoke transport->apply with unverified image");
    __CPROVER_assert(txn->length > sizeof(toob_image_header_t) &&
                         txn->length <= txn->dest_region_size,
                     "transport->apply length must fit destination slot");
    if (nondet_bool()) {
        g_transport_failed = true;
        return BOOT_ERR_FLASH_HW;
    }
    return BOOT_OK;
}

static boot_status_t fv07_transport_rollback(const boot_platform_t *platform,
                                             const slot_caps_t *caps,
                                             slot_txn_t *txn,
                                             uint8_t *arena,
                                             size_t arena_len) {
    __CPROVER_assert(platform != NULL && caps != NULL && txn != NULL &&
                         arena != NULL && __CPROVER_w_ok(arena, arena_len),
                     "transport->rollback preconditions");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
const slot_transport_t g_toob_transport_pointer = {
    .name     = "pointer",
    .tier     = 0,
    .id       = TOOB_TRANSPORT_ID_POINTER,
    .apply    = fv07_transport_apply,
    .rollback = fv07_transport_rollback,
};
#else
const slot_transport_t g_toob_transport_swapscratch = {
    .name     = "swapscratch",
    .tier     = 4,
    .id       = TOOB_TRANSPORT_ID_SWAPSCRATCH,
    .apply    = fv07_transport_apply,
    .rollback = fv07_transport_rollback,
};
#endif

/* ==========================================================================
 * Mock HAL Callbacks for boot_state.c & boot_main.c
 * ========================================================================== */

static boot_status_t fv07_flash_init(void) {
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    g_init_order_depth++;
    return BOOT_OK;
}

static void fv07_flash_deinit(void) {
    __CPROVER_assert(g_init_order_depth > 0U, "flash->deinit only called after flash->init");
    g_init_order_depth--;
}

static boot_status_t fv07_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "fv07 flash read buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "fv07 flash read must stay within physical flash");
    if (len == 0U) {
        return BOOT_OK;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    if (len <= 64U) {
        cbmc_havoc_bytes((uint8_t *)buf, len);
    } else if (len >= 512U) {
        /* Symbolic 512B TBM1 envelope window inside crypto_arena (constant slice width) */
        if (__CPROVER_POINTER_OFFSET(buf) == 0 &&
            len == __CPROVER_OBJECT_SIZE(buf) && len == 2048U) {
            memset(buf, 0, 2048U);
        }
        __CPROVER_havoc_slice(buf, 512U);
        const tbm1_header_t *hdr = (const tbm1_header_t *)buf;
        if (hdr->magic == TBM1_MAGIC) {
            __CPROVER_assume(hdr->total_len <= 512U || hdr->total_len > len);
            __CPROVER_assume(hdr->image_count <= 2U || hdr->image_count > TBM1_MAX_IMAGES);
        }
    } else {
        cbmc_havoc_bytes((uint8_t *)buf, len);
    }
    return BOOT_OK;
}

static boot_status_t fv07_flash_erase_sector(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv07_clock_init(void) {
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}
static void fv07_clock_deinit(void) {}
static uint32_t fv07_get_tick_ms(void) { return nondet_uint32_t(); }
static reset_reason_t fv07_get_reset_reason(void) {
    uint8_t r = nondet_uint8_t();
    __CPROVER_assume(r <= (uint8_t)RESET_REASON_HARD_FAULT);
    return (reset_reason_t)r;
}

static boot_status_t fv07_wdt_init(uint32_t timeout_ms) {
    (void)timeout_ms;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}
static void fv07_wdt_deinit(void) {}

static boot_status_t fv07_crypto_init(void) {
    return nondet_bool() ? BOOT_OK : BOOT_ERR_CRYPTO;
}
static void fv07_crypto_deinit(void) {}
static size_t fv07_get_hash_ctx_size(void) { return 64U; }

static boot_status_t fv07_confirm_init(void) {
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}
static void fv07_confirm_deinit(void) {}
static bool fv07_confirm_check_ok(uint64_t expected_nonce) {
    (void)expected_nonce;
    return nondet_bool();
}

static boot_status_t fv07_entropy_random(uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "entropy random buffer must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_CRYPTO;
    }
    if (len > 0U) {
        cbmc_havoc_bytes(buf, len);
    }
    return BOOT_OK;
}

static boot_status_t fv07_read_dslc(uint8_t *buf, size_t *len) {
    __CPROVER_assert(buf != NULL && len != NULL && *len >= 1U &&
                         __CPROVER_w_ok(buf, *len),
                     "read_dslc buffer preconditions");
    if (nondet_bool()) {
        return BOOT_ERR_NOT_SUPPORTED;
    }
    cbmc_havoc_bytes(buf, *len);
    return BOOT_OK;
}

static boot_status_t fv07_write_dslc(const uint8_t *buf, size_t len) {
    cbmc_assert_readable(buf, len, "write_dslc buffer must be readable");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv07_read_chip_uid(uint8_t *uid_out, size_t max_len,
                                        size_t *actual_len) {
    cbmc_assert_writable(uid_out, max_len, "read_chip_uid buffer must be writable");
    __CPROVER_assert(actual_len != NULL && __CPROVER_w_ok(actual_len, sizeof(*actual_len)),
                     "read_chip_uid actual_len must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_NOT_FOUND;
    }
    *actual_len = 16U;
    __CPROVER_havoc_slice(uid_out, 16U);
    return BOOT_OK;
}

static boot_status_t fv07_read_pubkey(uint8_t *key_out, size_t buf_len,
                                      uint8_t key_index) {
    (void)key_index;
    cbmc_assert_writable(key_out, buf_len, "read_pubkey buffer must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_NOT_FOUND;
    }
    cbmc_havoc_bytes(key_out, buf_len);
    return BOOT_OK;
}

static boot_status_t fv07_read_monotonic_counter(uint32_t *out_ctr) {
    __CPROVER_assert(out_ctr != NULL && __CPROVER_w_ok(out_ctr, sizeof(*out_ctr)),
                     "read_monotonic_counter out_ctr must be writable");
    *out_ctr = nondet_uint32_t();
    return nondet_bool() ? BOOT_OK : BOOT_ERR_NOT_SUPPORTED;
}

static boot_status_t fv07_soc_init(void) {
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}
static void fv07_soc_deinit(void) {}
static void fv07_assert_sec_reset(void) {}
static void fv07_flush_bus(void) {}
static void fv07_inv_icache(void) {}
static bool fv07_get_rec_pin(void) { return nondet_bool(); }
static boot_status_t fv07_lockdown(void) {
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_platform_t make_fv07_platform(clock_hal_t *clock,
                                          flash_hal_t *flash,
                                          wdt_hal_t *wdt,
                                          crypto_hal_t *crypto,
                                          entropy_hal_t *entropy,
                                          keystore_hal_t *ks,
                                          confirm_hal_t *confirm,
                                          soc_hal_t *soc) {
    *clock = (clock_hal_t){
        .abi_version      = TOOB_HAL_ABI_V2,
        .init             = fv07_clock_init,
        .deinit           = fv07_clock_deinit,
        .get_tick_ms      = fv07_get_tick_ms,
        .get_reset_reason = fv07_get_reset_reason,
    };
    *flash = (flash_hal_t){
        .abi_version      = TOOB_HAL_ABI_V2,
        .init             = fv07_flash_init,
        .deinit           = fv07_flash_deinit,
        .read             = fv07_flash_read,
        .erase_sector     = fv07_flash_erase_sector,
        .get_sector_size  = cbmc_flash_get_sector_size,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .max_erase_cycles = 100000U,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .erased_value     = CHIP_FLASH_ERASED_BYTE,
    };
    *wdt = (wdt_hal_t){
        .abi_version                  = TOOB_HAL_ABI_V2,
        .init                         = fv07_wdt_init,
        .deinit                       = fv07_wdt_deinit,
        .kick                         = cbmc_wdt_kick,
        .suspend_for_critical_section = cbmc_wdt_suspend,
        .resume                       = cbmc_wdt_resume,
    };
    *crypto = (crypto_hal_t){
        .abi_version       = TOOB_HAL_ABI_V3,
        .init              = fv07_crypto_init,
        .deinit            = fv07_crypto_deinit,
        .verify_signature  = cbmc_ed25519_verify_sig,
        .hash_init         = cbmc_hash_init,
        .hash_update       = cbmc_hash_update,
        .hash_finish       = cbmc_hash_finish,
        .get_hash_ctx_size = fv07_get_hash_ctx_size,
    };
    *entropy = (entropy_hal_t){
        .abi_version = TOOB_HAL_ABI_V3,
        .random      = fv07_entropy_random,
    };
    *ks = (keystore_hal_t){
        .abi_version            = TOOB_HAL_ABI_V3,
        .read_dslc              = fv07_read_dslc,
        .write_dslc             = fv07_write_dslc,
        .read_chip_uid          = fv07_read_chip_uid,
        .read_pubkey            = fv07_read_pubkey,
        .read_monotonic_counter = fv07_read_monotonic_counter,
    };
    *confirm = (confirm_hal_t){
        .abi_version = TOOB_HAL_ABI_V2,
        .init        = fv07_confirm_init,
        .deinit      = fv07_confirm_deinit,
        .check_ok    = fv07_confirm_check_ok,
    };
    *soc = (soc_hal_t){
        .abi_version                  = TOOB_HAL_ABI_V2,
        .init                         = fv07_soc_init,
        .deinit                       = fv07_soc_deinit,
        .assert_secondary_cores_reset = fv07_assert_sec_reset,
        .flush_bus_matrix             = fv07_flush_bus,
        .invalidate_icache            = fv07_inv_icache,
        .get_recovery_pin_state       = fv07_get_rec_pin,
        .lockdown_before_handoff      = fv07_lockdown,
    };
    boot_platform_t plat = {
        .clock    = clock,
        .flash    = flash,
        .wdt      = wdt,
        .crypto   = crypto,
        .entropy  = entropy,
        .keystore = ks,
        .confirm  = confirm,
        .soc      = soc,
    };
    return plat;
}

/* ==========================================================================
 * Entrypoint 1: Real TBM1 Update Pipeline + Arena Non-Aliasing + TDR1-02/03
 * ========================================================================== */
void prove_boot_state_update_pipeline(void) {
    g_main_fast_mode            = false;
    g_force_cloud_cmd           = false;
    g_skip_unlocked_force_update = false;
    g_transport_failed = false;
    g_tmr_updated      = false;
    boot_diag_init();

    CBMC_HAVOC_OBJECT(g_tmr_state);
    __CPROVER_assume(g_tmr_state.recovery_failure_counter < UINT32_MAX);
    __CPROVER_assume(g_tmr_state.boot_failure_counter < UINT32_MAX);

    CBMC_HAVOC_OBJECT(g_txn_state);
    g_txn_state.intent = WAL_INTENT_UPDATE_PENDING;
    if (nondet_bool()) {
        g_txn_state.offset = CHIP_STAGING_SLOT_ABS_ADDR;
    }

    clock_hal_t clock;
    flash_hal_t flash;
    wdt_hal_t wdt;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    confirm_hal_t confirm;
    soc_hal_t soc;
    boot_platform_t platform = make_fv07_platform(
        &clock, &flash, &wdt, &crypto, &entropy, &ks, &confirm, &soc);

    uint32_t seal_key[4];
    CBMC_HAVOC_OBJECT(seal_key);
    boot_target_config_t target = {0};

    boot_status_t st = boot_state_run(
        &platform, &target, seal_key, crypto_arena, sizeof(crypto_arena));

    /* TDR1-03: Candidate metadata / APPLIED (1) never set if transport failed */
    if (g_transport_failed) {
        __CPROVER_assert(toob_diag_state.last_update_outcome != 1U,
                         "TDR1-03: failed swap/commit never reports APPLIED in boot_diag");
    }

    if (st == BOOT_OK && g_txn_state.intent == WAL_INTENT_TXN_COMMIT) {
        __CPROVER_assert(target.is_tentative_boot,
                         "newly committed update requires tentative confirmation");
        __CPROVER_assert(target.generated_nonce != 0ULL,
                         "tentative boot generates a non-zero 64-bit boot_nonce");
    }
}

/* ==========================================================================
 * Entrypoint 2: Confirm Promotion (TDR1-02), Rollback, Cloud Cmd & HIGH-32
 * ========================================================================== */
void prove_boot_state_confirm_rollback_and_cloud(void) {
    g_main_fast_mode  = false;
    g_transport_failed = false;
    g_tmr_updated     = false;
    boot_diag_init();

    CBMC_HAVOC_OBJECT(g_tmr_state);
    __CPROVER_assume(g_tmr_state.recovery_failure_counter < UINT32_MAX);
    __CPROVER_assume(g_tmr_state.boot_failure_counter < UINT32_MAX);

    CBMC_HAVOC_OBJECT(g_txn_state);
    __CPROVER_assume(g_txn_state.intent != WAL_INTENT_UPDATE_PENDING);

    bool test_locked_force_update = nondet_bool();
    if (test_locked_force_update) {
        g_txn_state.intent           = WAL_INTENT_DEVICE_LOCKED;
        g_force_cloud_cmd            = true;
        g_skip_unlocked_force_update = false;
        g_forced_cmd                 = TOOB_CMD_FORCE_UPDATE;
    } else {
        g_force_cloud_cmd            = false;
        g_skip_unlocked_force_update = true;
    }

    uint32_t orig_pend_build = g_tmr_state.pending_build_number;
    uint8_t  orig_pend_key   = g_tmr_state.pending_key_index;

    clock_hal_t clock;
    flash_hal_t flash;
    wdt_hal_t wdt;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    confirm_hal_t confirm;
    soc_hal_t soc;
    boot_platform_t platform = make_fv07_platform(
        &clock, &flash, &wdt, &crypto, &entropy, &ks, &confirm, &soc);

    uint32_t seal_key[4];
    CBMC_HAVOC_OBJECT(seal_key);
    boot_target_config_t target = {0};

    boot_status_t st = boot_state_run(
        &platform, &target, seal_key, crypto_arena, sizeof(crypto_arena));

    if (test_locked_force_update) {
        /* HIGH-32: Locked device must drop FORCE_UPDATE and trap into boot_panic;
         * only an early HAL error prior to Step 2.7 may return, never BOOT_OK! */
        __CPROVER_assert(st != BOOT_OK &&
                             g_txn_state.intent != WAL_INTENT_UPDATE_PENDING,
                         "HIGH-32: locked device drops FORCE_UPDATE and never boots OS");
    }

    if (st == BOOT_OK && target.rollback_occurred) {
        __CPROVER_assert(g_tmr_state.pending_key_index == 0U &&
                             g_tmr_state.pending_build_number == 0U,
                         "TDR1-02: rollback clears tentative pending_* identity fields");
    }
    (void)orig_pend_build;
    (void)orig_pend_key;
}

/* ==========================================================================
 * Entrypoint 3: boot_main Lifecycle, ABI Gate, HIGH-29 VTOR & Sealed Handoff
 * ========================================================================== */
boot_status_t cbmc_fv07_boot_state_contract(const boot_platform_t *platform,
                                            boot_target_config_t *target_out,
                                            const uint32_t seal_key[4],
                                            uint8_t *arena,
                                            size_t arena_len) {
    __CPROVER_assert(platform != NULL && target_out != NULL &&
                         seal_key != NULL && arena != NULL &&
                         __CPROVER_w_ok(target_out, sizeof(*target_out)) &&
                         __CPROVER_r_ok(seal_key, 16U) &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_state_run preconditions");
    if (nondet_bool()) {
        return BOOT_ERR_VERIFY;
    }
    CBMC_HAVOC_OBJECT(*target_out);
    if (nondet_bool()) {
        boot_proof_seal(&target_out->proof, seal_key);
    }
    return BOOT_OK;
}

void prove_boot_main_lifecycle_and_handoff(void) {
    g_main_fast_mode   = true;
    g_force_cloud_cmd  = false;
    g_init_order_depth = 0U;
    boot_platform_mark_down();

    CBMC_HAVOC_OBJECT(g_tmr_state);
    __CPROVER_assume(g_tmr_state.recovery_failure_counter < UINT32_MAX);
    __CPROVER_assume(g_tmr_state.boot_failure_counter < UINT32_MAX);
    CBMC_HAVOC_OBJECT(g_txn_state);

    clock_hal_t clock;
    flash_hal_t flash;
    wdt_hal_t wdt;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    confirm_hal_t confirm;
    soc_hal_t soc;
    boot_platform_t platform = make_fv07_platform(
        &clock, &flash, &wdt, &crypto, &entropy, &ks, &confirm, &soc);

    /* Symbolically inject ABI mismatches and low erase-cycle configurations */
    if (nondet_bool()) {
        crypto.abi_version = nondet_uint32_t();
    }
    if (nondet_bool()) {
        flash.max_erase_cycles = nondet_uint32_t();
    }

    uint32_t seal_key[4];
    CBMC_HAVOC_OBJECT(seal_key);
    boot_target_config_t target;

    boot_status_t st = boot_main(&platform, &target, seal_key);

    if (crypto.abi_version != TOOB_HAL_ABI_V3) {
        __CPROVER_assert(st == BOOT_ERR_ABI_MISMATCH,
                         "ABI version mismatch rejected before hardware init");
    } else if (flash.max_erase_cycles < 4U) {
        __CPROVER_assert(st == BOOT_ERR_INVALID_ARG,
                         "max_erase_cycles < 4 rejected by boot_main");
    }

    __CPROVER_assert(g_init_order_depth == 0U,
                     "every initialized flash HAL instance is cleanly deinitialized");

    if (st == BOOT_OK) {
        uint32_t abs_entry = target.proof.image_addr + target.proof.entry_point;
        __CPROVER_assert((abs_entry & 0x7FU) == 0U,
                         "HIGH-29: Cortex-M VTOR entry point is 128-byte aligned");
        __CPROVER_assert(target.proof.entry_point >= sizeof(toob_image_header_t) &&
                             target.proof.entry_point < target.proof.image_size,
                         "HIGH-29: OS entry point lies strictly within authenticated image");
        __CPROVER_assert(toob_handoff_state.struct_version == TOOB_HANDOFF_STRUCT_VERSION,
                         ".noinit handoff struct_version sealed");
        __CPROVER_assert(toob_diag_state.struct_version == TOOB_DIAG_STRUCT_VERSION,
                         ".noinit boot_diag struct_version sealed");
        size_t i = nondet_size_t();
        __CPROVER_assume(i < 32U);
        __CPROVER_assert(crypto_arena[i] == 0U,
                         "crypto_arena prefix zeroized prior to OS handoff");
    }
}
