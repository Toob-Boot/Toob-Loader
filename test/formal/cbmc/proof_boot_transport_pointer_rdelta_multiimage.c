/*
 * FV-06: CBMC Pointer Transport, Oneway Reverse-Delta, Rollback & Multi-Image Proof
 *
 * Targets:
 *   Config A (-DTOOB_TRANSPORT_PROVIDER=TOOB_TRANSPORT_POINTER -DTOOB_FEATURE_MULTIIMAGE=1):
 *     - toobloader/core/boot_transport_pointer.c
 *     - toobloader/core/boot_transport.c
 *     - toobloader/core/boot_rollback.c
 *     - toobloader/core/boot_multiimage.c
 *     - toobloader/core/boot_swap.c + boot_effect.c + utils/boot_crc32.c
 *   Config B (-DTOOB_TRANSPORT_PROVIDER=TOOB_TRANSPORT_ONEWAY
 *             -DTOOB_ONEWAY_BACKUP_MODE=TOOB_ONEWAY_BACKUP_REVERSE_DELTA
 *             -DTOOB_FEATURE_DELTA=1):
 *     - toobloader/core/boot_transport_oneway.c
 *     - toobloader/core/boot_transport.c
 *     - toobloader/core/boot_tbm1.c
 *     - toobloader/core/boot_swap.c + boot_effect.c + utils/boot_crc32.c
 *
 * Proves:
 *   1. TOOB_TRANSPORT_POINTER: pointer_apply (both zero-copy and Scratch->Slot
 *      copy when src_is_delta_output), pointer_rollback, boot_transport_resolve_active,
 *      and boot_transport_reassert across BANK_SWAP, XIP_REMAP (PERSISTENT & VOLATILE),
 *      RELOCATABLE, and FIXED models.
 *   2. boot_rollback.c: boot_rollback_verify_svn (APP, RECOVERY, STAGE1 + downgrade
 *      and eFuse rejection), boot_rollback_evaluate_os (3-tier crash cascade), and
 *      boot_rollback_trigger_revert (32B aligned header read, asymmetric block
 *      solver max(dst_sec_size, src_sec_size), writes confined to CHIP_APP_SLOT_ABS_ADDR).
 *   3. boot_multiimage.c: whitelist firewall, whole-image & per-chunk SHA-256
 *      readback, CRIT-30 component_id < 32 enforcement, and bit-exact preservation
 *      of open_txn.transfer_bitmap[1..7].
 *      Note (Finding C — boot_effect.c:16-18,64-75 / boot_multiimage.c:168-175):
 *      stream_copy() forwards unaligned tail bytes (len % write_align != 0) to
 *      boot_flash_write_guarded() without 0xFF tail padding; whitelisted copy
 *      paths therefore document the producer precondition image_size % write_align == 0.
 *   4. TOOB_TRANSPORT_ONEWAY + TOOB_ONEWAY_BACKUP_REVERSE_DELTA:
 *      resolve_staging_rdelta (Head-TBM1 & sector-aligned Trailer-TBM1 auto-discovery,
 *      Region-6 bounds), ghost-base SHA-256 precheck before dest_addr modification
 *      in oneway_apply, and WAL_INTENT_TXN_ROLLBACK_PENDING + restored_sha256
 *      verification in oneway_rollback.
 */

#include "cbmc_common.h"
#include "boot_delta.h"
#include "boot_effect.h"
#include "boot_journal.h"
#include "boot_multiimage.h"
#include "boot_rollback.h"
#include "boot_slot_caps.h"
#include "boot_swap.h"
#include "boot_tbm1.h"
#include "boot_transport.h"

#define FV06_ARENA_BYTES 512U

static uint32_t g_write_count;
static uint32_t g_erase_count;
static uint32_t g_last_write_addr;
static size_t   g_last_write_len;
static uint8_t  g_tmr_active_slot;
static bool     g_tmr_has_override;

static uint32_t g_rb_resume_off;
static bool     g_in_rollback_revert;

static boot_status_t fv06_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "fv06 flash read buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "fv06 flash read must stay within physical flash");
    if (len == 0U) {
        return BOOT_OK;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    if (g_in_rollback_revert && addr == CHIP_STAGING_SLOT_ABS_ADDR && len == 32U) {
        __CPROVER_havoc_slice(buf, 32U);
        toob_image_header_t hdr_probe;
        memcpy(&hdr_probe, buf, sizeof(hdr_probe));
        /* Explore OOB/0/0xFFFFFFFF rejection and bounded tail at g_rb_resume_off */
        __CPROVER_assume(hdr_probe.image_size == 0U ||
                         hdr_probe.image_size > CHIP_APP_SLOT_SIZE ||
                         (hdr_probe.image_size > g_rb_resume_off &&
                          hdr_probe.image_size <= g_rb_resume_off + 256U));
    } else if (len == sizeof(tbm1_rdelta_desc_t)) {
        __CPROVER_havoc_slice(buf, sizeof(tbm1_rdelta_desc_t));
        const tbm1_rdelta_desc_t *rd = (const tbm1_rdelta_desc_t *)buf;
        __CPROVER_assume(rd->restored_size <= 256U ||
                         rd->restored_size > CHIP_APP_SLOT_SIZE);
    } else if (!g_in_rollback_revert && len == sizeof(toob_tds_header_t)) {
        __CPROVER_havoc_slice(buf, sizeof(toob_tds_header_t));
        const toob_tds_header_t *th = (const toob_tds_header_t *)buf;
        __CPROVER_assume(th->base_size <= 256U ||
                         th->base_size > CHIP_STAGING_SLOT_SIZE);
    } else if (len == sizeof(tbm1_header_t)) {
        __CPROVER_havoc_slice(buf, sizeof(tbm1_header_t));
    } else if (len == sizeof(toob_image_header_t)) {
        __CPROVER_havoc_slice(buf, sizeof(toob_image_header_t));
    } else {
        uint8_t *dst = (uint8_t *)buf;
        dst[0] = nondet_uint8_t();
    }
    return BOOT_OK;
}

static boot_status_t fv06_flash_write(uint32_t addr, const void *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);
    g_write_count++;
    g_last_write_addr = addr;
    g_last_write_len  = len;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv06_flash_erase_sector(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);
    g_erase_count++;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static size_t fv06_get_hash_ctx_size(void) {
    return 128U;
}

static boot_status_t fv06_entropy_random(uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "entropy random buffer must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_CRYPTO;
    }
    if (len > 0U) {
        cbmc_havoc_bytes(buf, len);
    }
    return BOOT_OK;
}

static boot_status_t fv06_read_monotonic_counter(uint32_t *out_ctr) {
    __CPROVER_assert(out_ctr != NULL && __CPROVER_w_ok(out_ctr, sizeof(*out_ctr)),
                     "read_monotonic_counter out_ctr must be writable");
    uint8_t mode = nondet_uint8_t();
    if (mode == 0U) {
        return BOOT_ERR_NOT_SUPPORTED;
    }
    if (mode == 1U) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_ctr = nondet_uint32_t();
    return BOOT_OK;
}

static bool g_bus_flushed;
static bool g_icache_invalidated;

static void fv06_flush_bus_matrix(void) {
    g_bus_flushed = true;
}

static void fv06_invalidate_icache(void) {
    g_icache_invalidated = true;
}

static uint32_t g_hw_active_slot;
static uint32_t g_hw_remap_addr;

static boot_status_t fv06_get_active_slot(uint32_t *out_slot) {
    __CPROVER_assert(out_slot != NULL && __CPROVER_w_ok(out_slot, sizeof(*out_slot)),
                     "get_active_slot out_slot must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    if (nondet_bool()) {
        *out_slot = g_hw_active_slot;
    } else {
        *out_slot = nondet_uint32_t();
    }
    return BOOT_OK;
}

static boot_status_t fv06_bank_flip(uint32_t target_slot) {
    __CPROVER_assert(target_slot <= 1U, "bank_flip target_slot must be 0 or 1");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    g_hw_active_slot = target_slot;
    return BOOT_OK;
}

static boot_status_t fv06_xip_remap_commit(uint32_t slot_phys_addr) {
    __CPROVER_assert(slot_phys_addr == CHIP_APP_SLOT_ABS_ADDR ||
                         slot_phys_addr == CHIP_STAGING_SLOT_ABS_ADDR,
                     "xip_remap_commit address must be a bootable slot base");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    g_hw_remap_addr  = slot_phys_addr;
    g_hw_active_slot = (slot_phys_addr == CHIP_APP_SLOT_ABS_ADDR) ? 0U : 1U;
    return BOOT_OK;
}

static boot_status_t fv06_image_link_check(uint32_t slot_phys_addr, uint32_t len) {
    __CPROVER_assert(slot_phys_addr == CHIP_APP_SLOT_ABS_ADDR ||
                         slot_phys_addr == CHIP_STAGING_SLOT_ABS_ADDR,
                     "image_link_check slot_phys_addr must be a bootable slot base");
    __CPROVER_assert(len > 0U, "image_link_check length must be positive");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

static boot_status_t fv06_exec_addr_select(uint32_t slot_phys_addr) {
    __CPROVER_assert(slot_phys_addr == CHIP_APP_SLOT_ABS_ADDR ||
                         slot_phys_addr == CHIP_STAGING_SLOT_ABS_ADDR,
                     "exec_addr_select slot_phys_addr must be a bootable slot base");
    if (nondet_bool()) {
        return BOOT_ERR_INVALID_STATE;
    }
    g_hw_remap_addr  = slot_phys_addr;
    g_hw_active_slot = (slot_phys_addr == CHIP_APP_SLOT_ABS_ADDR) ? 0U : 1U;
    return BOOT_OK;
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
        __CPROVER_assert(__CPROVER_w_ok(out_net_accum, sizeof(*out_net_accum)),
                         "out_net_accum must be writable");
        *out_net_accum = 0U;
    }
    if (out_resume_off != NULL) {
        __CPROVER_assert(__CPROVER_w_ok(out_resume_off, sizeof(*out_resume_off)),
                         "out_resume_off must be writable");
        *out_resume_off = 0U;
    }
    uint8_t mode = nondet_uint8_t();
    if (mode == 0U && g_rb_resume_off == 0U) {
        return BOOT_ERR_STATE;
    }
    if (mode == 1U) {
        return BOOT_ERR_FLASH_HW;
    }
    CBMC_HAVOC_OBJECT(*out_txn);
    if (g_rb_resume_off > 0U) {
        out_txn->intent = WAL_INTENT_TXN_ROLLBACK_PENDING;
        out_txn->delta_chunk_id = nondet_bool() ? g_rb_resume_off : (g_rb_resume_off + 1U);
    } else if (out_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
        out_txn->delta_chunk_id = 0U;
    }
    return BOOT_OK;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr) {
    __CPROVER_assert(platform != NULL && out_tmr != NULL &&
                         __CPROVER_w_ok(out_tmr, sizeof(*out_tmr)),
                     "boot_journal_get_tmr requires writable TMR struct");
    uint8_t mode = nondet_uint8_t();
    if (mode == 0U) {
        return BOOT_ERR_FLASH_HW;
    }
    if (mode == 1U) {
        return BOOT_ERR_NOT_FOUND;
    }
    CBMC_HAVOC_OBJECT(*out_tmr);
    __CPROVER_assume(out_tmr->app_slot_erase_counter < 90000U);
    __CPROVER_assume(out_tmr->staging_slot_erase_counter < 90000U);
    __CPROVER_assume(out_tmr->swap_buffer_erase_counter < 90000U);
    if (g_tmr_has_override && nondet_bool()) {
        out_tmr->active_app_slot = g_tmr_active_slot;
    }
    return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
    __CPROVER_assert(platform != NULL && new_tmr != NULL &&
                         __CPROVER_r_ok(new_tmr, sizeof(*new_tmr)),
                     "boot_journal_update_tmr requires readable TMR struct");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    g_tmr_active_slot  = new_tmr->active_app_slot;
    g_tmr_has_override = true;
    return BOOT_OK;
}

boot_status_t boot_journal_flush_tmr(const boot_platform_t *platform) {
    __CPROVER_assert(platform != NULL, "boot_journal_flush_tmr requires platform");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_verify_slot_image(const boot_platform_t *platform,
                                     uint32_t slot_addr,
                                     uint32_t slot_size,
                                     const toob_image_header_t *hdr,
                                     uint8_t *arena,
                                     size_t arena_len) {
    __CPROVER_assert(platform != NULL && hdr != NULL && arena != NULL &&
                         __CPROVER_r_ok(hdr, sizeof(*hdr)) &&
                         __CPROVER_w_ok(arena, arena_len),
                     "boot_verify_slot_image preconditions");
    __CPROVER_assert(hdr->magic == TOOB_MAGIC_HEADER &&
                         hdr->image_size <= slot_size &&
                         (UINT32_MAX - slot_addr) >= hdr->image_size,
                     "boot_verify_slot_image slot bounds invariant");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

static boot_platform_t make_fv06_platform(flash_hal_t *flash,
                                          crypto_hal_t *crypto,
                                          entropy_hal_t *entropy,
                                          keystore_hal_t *ks,
                                          soc_hal_t *soc,
                                          const slot_caps_t *caps) {
    *flash = (flash_hal_t){
        .read               = fv06_flash_read,
        .write              = fv06_flash_write,
        .erase_sector       = fv06_flash_erase_sector,
        .get_sector_size    = cbmc_flash_get_sector_size,
        .max_sector_size    = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size         = CHIP_FLASH_TOTAL_SIZE,
        .max_erase_cycles   = 100000U,
        .write_align        = CHIP_FLASH_WRITE_ALIGNMENT,
        .erased_value       = CHIP_FLASH_ERASED_BYTE,
    };
    *crypto = (crypto_hal_t){
        .verify_signature  = cbmc_ed25519_verify_sig,
        .hash_init         = cbmc_hash_init,
        .hash_update       = cbmc_hash_update,
        .hash_finish       = cbmc_hash_finish,
        .get_hash_ctx_size = fv06_get_hash_ctx_size,
    };
    *entropy = (entropy_hal_t){
        .random = fv06_entropy_random,
    };
    *ks = (keystore_hal_t){
        .read_monotonic_counter = fv06_read_monotonic_counter,
    };
    *soc = (soc_hal_t){
        .flush_bus_matrix  = fv06_flush_bus_matrix,
        .invalidate_icache = fv06_invalidate_icache,
    };
    boot_platform_t plat = {
        .flash     = flash,
        .wdt       = &g_cbmc_wdt_hal,
        .crypto    = crypto,
        .entropy   = entropy,
        .keystore  = ks,
        .soc       = soc,
        .slot_caps = caps,
    };
    return plat;
}

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER

void prove_pointer_apply_rollback_reassert(void) {
    g_write_count      = 0U;
    g_erase_count      = 0U;
    g_tmr_has_override = false;
    g_bus_flushed      = false;
    g_icache_invalidated = false;

    slot_caps_t caps;
    CBMC_HAVOC_OBJECT(caps);
    uint8_t model_sel = nondet_uint8_t();
    if (model_sel == 0U) {
        caps.exec_model = SLOT_EXEC_BANK_SWAP;
        caps.ops.bank_swap.bank_flip = nondet_bool() ? fv06_bank_flip : NULL;
    } else if (model_sel == 1U) {
        caps.exec_model = SLOT_EXEC_XIP_REMAP;
        caps.ops.xip_remap.xip_remap_commit =
            nondet_bool() ? fv06_xip_remap_commit : NULL;
    } else if (model_sel == 2U) {
        caps.exec_model = SLOT_EXEC_RELOCATABLE;
        caps.ops.relocatable.image_link_check =
            nondet_bool() ? fv06_image_link_check : NULL;
        caps.ops.relocatable.exec_addr_select =
            nondet_bool() ? fv06_exec_addr_select : NULL;
    } else {
        caps.exec_model = SLOT_EXEC_FIXED;
    }
    caps.commit_persistence =
        nondet_bool() ? SLOT_COMMIT_PERSISTENT : SLOT_COMMIT_VOLATILE;
    caps.get_active_slot = nondet_bool() ? fv06_get_active_slot : NULL;
    caps.slot_count      = nondet_uint8_t();
    __CPROVER_assume(caps.slot_count <= 3U);

    flash_hal_t flash;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    soc_hal_t soc;
    boot_platform_t platform =
        make_fv06_platform(&flash, &crypto, &entropy, &ks, &soc, &caps);

    const slot_transport_t *tp = boot_transport_active();
    __CPROVER_assert(tp != NULL && tp->id == TOOB_TRANSPORT_ID_POINTER,
                     "active transport must be POINTER");
    __CPROVER_assert(boot_transport_by_id(TOOB_TRANSPORT_ID_POINTER) == tp,
                     "boot_transport_by_id resolves POINTER");
    __CPROVER_assert(boot_transport_by_id(TOOB_TRANSPORT_ID_SWAPSCRATCH) == NULL,
                     "boot_transport_by_id rejects mismatched transport ID");

    uint8_t arena[FV06_ARENA_BYTES] __attribute__((aligned(8)));
    slot_txn_t txn;
    wal_entry_payload_t open_txn;
    CBMC_HAVOC_OBJECT(txn);
    CBMC_HAVOC_OBJECT(open_txn);

    if (txn.src_is_delta_output) {
        txn.src_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
        txn.src_region_size = CHIP_SCRATCH_SLOT_SIZE;
        __CPROVER_assume(txn.length >= 1U &&
                         txn.length <= CHIP_FLASH_MAX_SECTOR_SIZE);
        open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] =
            nondet_bool() ? 0U : TOOB_PHASE_POINTER_COPY;
        open_txn.delta_chunk_id = 0U;
    } else if (txn.target_slot_index <= 1U) {
        txn.src_addr = (txn.target_slot_index == 0U) ? CHIP_APP_SLOT_ABS_ADDR
                                                     : CHIP_STAGING_SLOT_ABS_ADDR;
        __CPROVER_assume(txn.length <= CHIP_APP_SLOT_SIZE);
    }

    boot_status_t ap_st =
        tp->apply(&platform, &caps, &txn, &open_txn, arena, sizeof(arena));
    if (!txn.src_verified) {
        __CPROVER_assert(ap_st != BOOT_OK && g_write_count == 0U && g_erase_count == 0U,
                         "unverified source must never commit or mutate flash");
    }
    if (ap_st == BOOT_OK) {
        __CPROVER_assert(!txn.src_is_delta_output ||
                             (txn.src_addr == CHIP_APP_SLOT_ABS_ADDR ||
                              txn.src_addr == CHIP_STAGING_SLOT_ABS_ADDR),
                         "delta output Scratch->Slot copy updates txn.src_addr to target slot");
        __CPROVER_assert(open_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] == 0U,
                         "successful pointer_apply clears phase marker");
    }

    (void)tp->rollback(&platform, &caps, &txn, arena, sizeof(arena));

    uint8_t resolved_slot = 0xFFU;
    uint32_t resolved_addr = 0U;
    boot_status_t res_st =
        boot_transport_resolve_active(&platform, &resolved_slot, &resolved_addr);
    __CPROVER_assert(res_st == BOOT_OK, "boot_transport_resolve_active succeeds on valid pointers");
    __CPROVER_assert(resolved_slot <= 1U, "resolved active_slot is strictly 0 or 1");
    __CPROVER_assert(resolved_addr == CHIP_APP_SLOT_ABS_ADDR ||
                         resolved_addr == CHIP_STAGING_SLOT_ABS_ADDR,
                     "resolved boot_addr is strictly a bootable slot base");

    (void)boot_transport_reassert(&platform, resolved_slot);
}

void prove_rollback_svn_and_revert(void) {
    g_write_count = 0U;
    g_erase_count = 0U;

    flash_hal_t flash;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    soc_hal_t soc;
    boot_platform_t platform =
        make_fv06_platform(&flash, &crypto, &entropy, &ks, &soc, NULL);

    /* 1. Hybrid SVN verification across APP / RECOVERY / STAGE1 + invalid target */
    uint32_t manifest_svn = nondet_uint32_t();
    rollback_target_t target = (rollback_target_t)nondet_uint32_t();
    boot_status_t svn_st = boot_rollback_verify_svn(&platform, manifest_svn, target);
    if ((uint32_t)target > (uint32_t)ROLLBACK_TARGET_STAGE1) {
        __CPROVER_assert(svn_st == BOOT_ERR_INVALID_ARG ||
                             svn_st == BOOT_ERR_FLASH_HW ||
                             svn_st == BOOT_ERR_CRYPTO,
                         "unknown rollback_target_t returns BOOT_ERR_INVALID_ARG (or early HW/TRNG error)");
    }

    /* 2. Crash cascade evaluation (normal -> recovery -> panic escalation) */
    wal_tmr_payload_t tmr;
    CBMC_HAVOC_OBJECT(tmr);
    bool boot_rec = true;
    boot_status_t ev_st = boot_rollback_evaluate_os(&platform, &tmr, &boot_rec);
    if (tmr.boot_failure_counter <= BOOT_CONFIG_MAX_RETRIES) {
        __CPROVER_assert(ev_st == BOOT_OK && !boot_rec,
                         "within normal retry limit boots primary OS");
    } else if (tmr.recovery_failure_counter <= BOOT_CONFIG_MAX_RECOVERY_RETRIES) {
        __CPROVER_assert(ev_st == BOOT_OK && boot_rec,
                         "exceeding normal retries within recovery budget selects Recovery OS");
    }

    /* 3. Physical reverse copy (boot_rollback_trigger_revert) across all sector sizes */
    uint8_t sel = nondet_uint8_t();
#if CBMC_ASYMMETRIC_SECTORS == 0
    g_rb_resume_off = (sel == 0U) ? 0U : CHIP_FLASH_MAX_SECTOR_SIZE;
#else
    if (sel == 0U) {
        g_rb_resume_off = 0U;
    } else if (sel == 1U) {
        g_rb_resume_off = 0x00004000U;
    } else {
        g_rb_resume_off = 0x00014000U;
    }
#endif
    uint8_t arena[FV06_ARENA_BYTES] __attribute__((aligned(8)));
    g_in_rollback_revert = true;
    if (nondet_bool()) {
        (void)boot_rollback_trigger_revert(&platform, arena, sizeof(arena));
    } else {
        (void)boot_rollback_trigger_revert(&platform, arena, 256U); /* < 512 guard */
    }
    g_in_rollback_revert = false;
    g_rb_resume_off = 0U;

    /* Prove every write produced by boot_rollback_trigger_revert targeted APP slot */
    if (g_write_count > 0U) {
        __CPROVER_assert(cbmc_subrange_of(g_last_write_addr, g_last_write_len,
                                          CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE),
                         "boot_rollback_trigger_revert writes strictly within CHIP_APP_SLOT");
    }
}

void prove_rollback_revert_loop_bounded(void) {
    g_write_count = 0U;
    g_erase_count = 0U;

    flash_hal_t flash;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    soc_hal_t soc;
    boot_platform_t platform =
        make_fv06_platform(&flash, &crypto, &entropy, &ks, &soc, NULL);

    /* Dedicated bounded-image revert proof exercising asymmetric block solver + effect copy */
    uint8_t arena[FV06_ARENA_BYTES] __attribute__((aligned(8)));
    boot_rollback_chunk_desc_t desc;
    desc.current_offset = 0U;
    desc.block_size = nondet_uint32_t();
    __CPROVER_assume(desc.block_size >= CHIP_FLASH_WRITE_ALIGNMENT &&
                     desc.block_size <= 256U &&
                     (desc.block_size % CHIP_FLASH_WRITE_ALIGNMENT) == 0U);
    desc.crc_src = nondet_uint32_t();

    flash_effect_t fx[2];
    size_t n_out = 0U;
    boot_status_t pst = boot_rollback_plan_chunk(&platform, &desc, fx, 2U, &n_out);
    __CPROVER_assert(pst == BOOT_OK && n_out == 2U, "boot_rollback_plan_chunk emits ERASE+COPY");

    boot_allowed_region_t wl[1] = {{CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE}};
    (void)boot_effect_execute(&platform, fx, n_out, wl, 1U, arena, sizeof(arena));
    if (g_write_count > 0U) {
        __CPROVER_assert(cbmc_subrange_of(g_last_write_addr, g_last_write_len,
                                          CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE),
                         "planned rollback effect writes strictly within CHIP_APP_SLOT");
    }
}

void prove_multiimage_apply_bounds(void) {
    g_write_count = 0U;
    g_erase_count = 0U;

    flash_hal_t flash;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    soc_hal_t soc;
    boot_platform_t platform =
        make_fv06_platform(&flash, &crypto, &entropy, &ks, &soc, NULL);

    uint8_t arena[FV06_ARENA_BYTES] __attribute__((aligned(8)));
    boot_allowed_region_t wl[2] = {
        {CHIP_STAGE1A_ABS_ADDR, CHIP_STAGE1A_SIZE},
        {CHIP_STAGE1B_ABS_ADDR, CHIP_STAGE1B_SIZE},
    };

    wal_entry_payload_t open_txn;
    CBMC_HAVOC_OBJECT(open_txn);
    uint32_t saved_bitmap[8];
    memcpy(saved_bitmap, open_txn.transfer_bitmap, sizeof(saved_bitmap));

    boot_component_t comps[2];
    CBMC_HAVOC_OBJECT(comps);

    uint8_t mode = nondet_uint8_t();
    if (mode == 0U) {
        /* Path A: Unconstrained symbolic component testing firewall & CRIT-30 >= 32 rejection */
        bool is_bad_id = (comps[0].component_id >= 32U && comps[0].image_size > 0U);
        bool in_wl = cbmc_subrange_of(comps[0].target_addr, comps[0].image_size,
                                      CHIP_STAGE1A_ABS_ADDR, CHIP_STAGE1A_SIZE) ||
                     cbmc_subrange_of(comps[0].target_addr, comps[0].image_size,
                                      CHIP_STAGE1B_ABS_ADDR, CHIP_STAGE1B_SIZE) ||
                     (comps[0].image_size == 0U);
        if (!in_wl || is_bad_id) {
            boot_status_t st = boot_multiimage_apply(
                &platform, CHIP_STAGING_SLOT_ABS_ADDR, comps, 1U, wl, 2U,
                &open_txn, arena, sizeof(arena));
            __CPROVER_assert(st != BOOT_OK && g_write_count == 0U && g_erase_count == 0U,
                             "out-of-whitelist or component_id >= 32 rejected with zero flash wear");
        }
    } else if (mode == 1U) {
        /* Path B: Duplicate component_id across distinct whitelisted slots must fail closed */
        uint32_t dup_id = nondet_uint32_t();
        __CPROVER_assume(dup_id < 32U);
        comps[0].component_id   = dup_id;
        comps[0].staging_offset = 0U;
        comps[0].target_addr    = CHIP_STAGE1A_ABS_ADDR;
        comps[0].image_size     = CHIP_FLASH_WRITE_ALIGNMENT;
        comps[1].component_id   = dup_id;
        comps[1].staging_offset = CHIP_FLASH_WRITE_ALIGNMENT;
        comps[1].target_addr    = CHIP_STAGE1B_ABS_ADDR;
        comps[1].image_size     = CHIP_FLASH_WRITE_ALIGNMENT;

        boot_status_t dst = boot_multiimage_apply(
            &platform, CHIP_STAGING_SLOT_ABS_ADDR, comps, 2U, wl, 2U,
            &open_txn, arena, sizeof(arena));
        __CPROVER_assert(dst != BOOT_OK && g_write_count == 0U && g_erase_count == 0U,
                         "duplicate component_id rejected before any flash write or erase");
    } else {
        /* Path C: Whitelisted sector-aligned component exercising ERASE + COPY + SHA-256 readback */
        comps[0].component_id   = nondet_uint32_t();
        __CPROVER_assume(comps[0].component_id < 32U);
        comps[0].staging_offset = 0U;
        comps[0].target_addr    = nondet_bool() ? CHIP_STAGE1A_ABS_ADDR : CHIP_STAGE1B_ABS_ADDR;
        comps[0].image_size     = nondet_uint32_t();
        __CPROVER_assume(comps[0].image_size <= 256U);
        if (nondet_bool()) {
            /* Per-chunk SHA-256 readback (TBM1 v2) */
            comps[0].chunk_size = 128U;
            comps[0].num_chunks = (comps[0].image_size == 0U)
                                      ? 0U
                                      : ((comps[0].image_size + 127U) / 128U);
            comps[0].chunk_hashes_flash_addr = CHIP_STAGING_SLOT_ABS_ADDR + 512U;
        } else {
            /* Whole-image SHA-256 readback */
            comps[0].chunk_size = 0U;
            comps[0].num_chunks = 0U;
        }

        boot_status_t st = boot_multiimage_apply(
            &platform, CHIP_STAGING_SLOT_ABS_ADDR, comps, 1U, wl, 2U,
            &open_txn, arena, sizeof(arena));
        for (size_t k = 1U; k < 8U; k++) {
            __CPROVER_assert(open_txn.transfer_bitmap[k] == saved_bitmap[k],
                             "CRIT-30: transfer_bitmap[1..7] never mutated by boot_multiimage_apply");
        }
        if (st == BOOT_OK && comps[0].image_size > 0U) {
            uint32_t mask = 1U << comps[0].component_id;
            __CPROVER_assert((open_txn.transfer_bitmap[0] & mask) != 0U,
                             "completed component sets checkpoint bit in transfer_bitmap[0]");
        }
    }
}

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER */

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY

/*
 * Sound contract for boot_delta_apply (proven directly in proof_boot_delta.c):
 * enforces that reverse-delta source resides strictly inside Staging, target
 * is CHIP_APP_SLOT_ABS_ADDR, and ghost-base resides strictly inside Staging or Scratch.
 */
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
                     "boot_delta_apply pointer and arena preconditions");
    __CPROVER_assert(cbmc_subrange_of(delta_flash_addr, delta_size,
                                      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE),
                     "reverse-delta stream must lie strictly within Staging slot");
    __CPROVER_assert(target_flash_addr == CHIP_APP_SLOT_ABS_ADDR &&
                         target_slot_size == CHIP_APP_SLOT_SIZE &&
                         (target_flash_addr % 8U) == 0U &&
                         (target_slot_size % 8U) == 0U,
                     "reverse-delta target must be 8-byte aligned CHIP_APP_SLOT");
    if (base_image_size > 0U) {
        bool base_ok = cbmc_subrange_of(base_flash_addr, base_image_size,
                                        CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE) ||
                       cbmc_subrange_of(base_flash_addr, base_image_size,
                                        CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE);
        __CPROVER_assert(base_ok,
                         "reverse-delta ghost base must reside in Staging or Scratch");
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

void prove_oneway_rdelta_apply_and_rollback(void) {
    g_write_count = 0U;
    g_erase_count = 0U;

    slot_caps_t caps = TOOB_SLOT_CAPS_FIXED(1, .has_scratch = false, .max_erase_cycles = 100000U);
    flash_hal_t flash;
    crypto_hal_t crypto;
    entropy_hal_t entropy;
    keystore_hal_t ks;
    soc_hal_t soc;
    boot_platform_t platform =
        make_fv06_platform(&flash, &crypto, &entropy, &ks, &soc, &caps);

    const slot_transport_t *tp = boot_transport_active();
    __CPROVER_assert(tp != NULL && tp->id == TOOB_TRANSPORT_ID_ONEWAY,
                     "active transport must be ONEWAY");

    uint8_t arena[FV06_ARENA_BYTES] __attribute__((aligned(8)));
    slot_txn_t txn;
    wal_entry_payload_t open_txn;
    CBMC_HAVOC_OBJECT(txn);
    CBMC_HAVOC_OBJECT(open_txn);

    txn.src_addr         = CHIP_STAGING_SLOT_ABS_ADDR;
    txn.src_region_size  = CHIP_STAGING_SLOT_SIZE;
    txn.dest_addr        = CHIP_APP_SLOT_ABS_ADDR;
    txn.dest_region_size = CHIP_APP_SLOT_SIZE;
    txn.backup_addr      = 0U;
    txn.backup_region_size = 0U;
    txn.dest_slot        = (uint8_t)BOOT_DEST_SLOT_APP;
    __CPROVER_assume(txn.length <= 256U &&
                     (txn.length % CHIP_FLASH_WRITE_ALIGNMENT) == 0U);
    open_txn.delta_chunk_id = 0U;

    /* Bound ghost-base hash loop in oneway_apply by bounding Staging/Scratch reads via arena */
    boot_status_t ap_st =
        tp->apply(&platform, &caps, &txn, &open_txn, arena, sizeof(arena));
    if (!txn.src_verified && txn.length > 0U) {
        __CPROVER_assert(ap_st != BOOT_OK && g_write_count == 0U && g_erase_count == 0U,
                         "unverified source rejected before any flash write/erase");
    }

    /* Prove Reverse-Delta Rollback (resolve_staging_rdelta + boot_delta_apply + restored_sha256) */
    (void)tp->rollback(&platform, &caps, &txn, arena, sizeof(arena));
}

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY */
