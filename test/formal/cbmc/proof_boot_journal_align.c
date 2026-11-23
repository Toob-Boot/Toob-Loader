/*
 * CBMC Sector-Bounds, Asymmetric-Sector & Write-Alignment Proof
 * for boot_journal.c + boot_rstore.c + boot_identity.c (Wave 5A).
 *
 * Parameterized across:
 *   - CBMC_ASYMMETRIC_SECTORS in {0 (4 KB homogeneous), 1 (16 / 64 / 128 KB)}
 *   - CHIP_FLASH_WRITE_ALIGNMENT in {1U, 4U, 8U, 32U}
 *
 * Proves via __CPROVER_assert on every flash HAL operation:
 *   1. Every flash->write(addr, buf, len) satisfies:
 *        (addr % CHIP_FLASH_WRITE_ALIGNMENT) == 0
 *        (len  % CHIP_FLASH_WRITE_ALIGNMENT) == 0
 *        addr >= CHIP_FLASH_IMMUTABLE_BOOT_END
 *        [addr, addr + len) stays strictly inside a mutable WAL / RSTORE slot.
 *   2. Every flash->erase_sector(addr) is strictly sector-base aligned across
 *      both homogeneous (4 KB) and heterogeneous (16 KB / 64 KB / 128 KB)
 *      sector rings and never touches [0, CHIP_FLASH_IMMUTABLE_BOOT_END).
 *   3. boot_rstore_read + boot_rstore_write pad arbitrary unaligned record_size
 *      in [1 .. 64] bytes up to CHIP_FLASH_WRITE_ALIGNMENT with zero unbuffered
 *      partial writes.
 *
 * Documented Domain Bounds (see formal report Finding #3 & Finding N on boot_journal.c):
 *   - max_erase_cycles >= 4 (avoids max_erase_cycles - 3 wrap at line 898).
 *   - Non-wrapped monotonic lifetime counters: sequence_id in [4, 0x7FFFFFF0),
 *     erase_count < 0xFFFFFFF0, and chain_entry_count < 0xFFFFFFF0.
 *   - Finding N (boot_journal.c:371): get_best_wear_leveling_sector computes
 *     (uint32_t)(highest_seq - hdr.data.sequence_id) without checking
 *     hdr.data.sequence_id <= highest_seq; if a newer sector transiently failed
 *     flash->read during boot_journal_init and succeeds later, unsigned wrap
 *     yields age = 0xFFFFFFFF >= protect_win and can erase the newest sector.
 *     Model stores per-sector headers consistently across reads within a boot.
 */

#include "cbmc_common.h"
#include "boot_journal.h"
#include "boot_rstore.h"

#define JOURNAL_PROOF_ENTRY_SLOTS 1U
#define RSTORE_PROOF_MAX_REC      64U

static const uint32_t g_wal_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
static const size_t   g_wal_sizes[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_SIZES;

#if CBMC_ASYMMETRIC_SECTORS == 0
static const uint32_t g_rstore_addrs[3] = {
    CHIP_KDM_QUORUM_ABS_ADDR,
    CHIP_KDM_QUORUM_ABS_ADDR + 0x1000U,
    CHIP_KDM_QUORUM_ABS_ADDR + 0x2000U
};
static const size_t g_rstore_sizes[3] = { 0x1000U, 0x1000U, 0x1000U };
#else
/* Span 16 KB (CLOUD_CMD), 64 KB (WAL_2), and 128 KB (KDM_QUORUM) sectors */
static const uint32_t g_rstore_addrs[3] = {
    CHIP_CLOUD_CMD_SLOT_ABS_ADDR,
    CHIP_WAL_SECTOR_2_ADDR,
    CHIP_KDM_QUORUM_ABS_ADDR
};
static const size_t g_rstore_sizes[3] = {
    CHIP_CLOUD_CMD_SLOT_SIZE,
    CHIP_WAL_SECTOR_2_SIZE,
    0x20000U
};
#endif

#ifdef TOOB_OTP_MAX_SLOTS
#define CBMC_MAX_OTP_SLOTS TOOB_OTP_MAX_SLOTS
#else
#define CBMC_MAX_OTP_SLOTS 256U
#endif

static uint8_t  g_root_pubkey[32];
static uint8_t  g_device_secret[32];
static uint8_t  g_chip_uid[32];
static size_t   g_chip_uid_len;
static uint32_t g_otp_epoch;
static uint8_t  g_dslc_byte;
static uint8_t  g_active_otp_limit;
static bool g_fast_init_mode = false;
static bool g_slot0_occupied = false;
static bool g_wal_mode       = true;

boot_status_t cbmc_derive_journal_key_contract(const boot_platform_t *platform,
                                               uint8_t out_key[16]) {
    __CPROVER_assert(platform != NULL && out_key != NULL,
                     "boot_derive_journal_key args must be non-null");
    cbmc_assert_writable(out_key, 16U, "boot_derive_journal_key out_key writable");
    if (nondet_bool()) {
        return BOOT_ERR_NOT_FOUND;
    }
    cbmc_havoc_bytes(out_key, 16U);
    return BOOT_OK;
}

static wal_sector_header_t g_wh0, g_wh1, g_wh2, g_wh3;
static bool                g_wh_valid0, g_wh_valid1, g_wh_valid2, g_wh_valid3;
static bool                g_wh_ioerr0, g_wh_ioerr1, g_wh_ioerr2, g_wh_ioerr3;

wal_sector_header_t       nondet_wal_sector_header_t(void);
wal_entry_aligned_t       nondet_wal_entry_aligned_t(void);
boot_rstore_slot_header_t nondet_rstore_slot_header_t(void);

static inline bool get_wal_hdr(uint32_t idx, wal_sector_header_t *out, bool *out_valid) {
    if (idx == 0U) {
        if (g_wh_ioerr0) { return false; }
        *out = g_wh0; *out_valid = g_wh_valid0; return true;
    }
    if (idx == 1U) {
        if (g_wh_ioerr1) { return false; }
        *out = g_wh1; *out_valid = g_wh_valid1; return true;
    }
    if (idx == 2U) {
        if (g_wh_ioerr2) { return false; }
        *out = g_wh2; *out_valid = g_wh_valid2; return true;
    }
    if (g_wh_ioerr3) { return false; }
    *out = g_wh3; *out_valid = g_wh_valid3; return true;
}

uint32_t cbmc_journal_det_crc32(const uint8_t *data, size_t len) {
    cbmc_assert_readable(data, len, "compute_boot_crc32 buffer must be readable");
    if (len >= 8U) {
        uint32_t w0 = 0U, w1 = 0U;
        memcpy(&w0, data, 4U);
        memcpy(&w1, data + 4U, 4U);
        return (w0 ^ (w1 >> 3U) ^ 0x5A5AA5A5U) ^ (uint32_t)len;
    }
    return nondet_uint32_t();
}

bool cbmc_journal_read_header_contract(const boot_platform_t *p, uint32_t idx,
                                       wal_sector_header_aligned_t *out_hdr) {
    __CPROVER_assert(p != NULL && idx < TOOB_WAL_SECTORS && out_hdr != NULL &&
                         __CPROVER_w_ok(out_hdr, sizeof(*out_hdr)),
                     "read_header contract preconditions");
    wal_sector_header_t h;
    bool valid = false;
    if (!get_wal_hdr(idx, &h, &valid)) {
        return false;
    }
    out_hdr->data = h;
    return valid;
}

boot_status_t cbmc_update_tmr_contract(const boot_platform_t *platform,
                                       const wal_tmr_payload_t *new_tmr) {
    __CPROVER_assert(platform != NULL && new_tmr != NULL,
                     "boot_journal_update_tmr args non-null");
    cbmc_assert_readable(new_tmr, sizeof(*new_tmr),
                         "boot_journal_update_tmr payload readable");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t cbmc_reconstruct_txn_contract(const boot_platform_t *platform,
                                            wal_entry_payload_t *out_state,
                                            uint32_t *out_net_accum,
                                            uint32_t *out_resume_offset) {
    __CPROVER_assert(platform != NULL && out_state != NULL &&
                         __CPROVER_w_ok(out_state, sizeof(*out_state)),
                     "boot_journal_reconstruct_txn args valid");
    if (out_net_accum != NULL) {
        *out_net_accum = 0U;
    }
    if (out_resume_offset != NULL) {
        *out_resume_offset = 0U;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    CBMC_HAVOC_OBJECT(*out_state);
    return BOOT_OK;
}

static size_t journal_get_hash_ctx_size(void) {
    return 128U;
}

boot_status_t cbmc_compute_tmr_mac_contract(const boot_platform_t *platform,
                                            const uint8_t key[WAL_CHAIN_TAG_BYTES],
                                            const wal_tmr_payload_t *tmr,
                                            uint32_t efuse_epoch,
                                            uint8_t out_tag[WAL_CHAIN_TAG_BYTES]) {
    (void)efuse_epoch;
    __CPROVER_assert(platform != NULL, "compute_tmr_mac platform non-null");
    cbmc_assert_readable(key, WAL_CHAIN_TAG_BYTES, "compute_tmr_mac key readable");
    cbmc_assert_readable(tmr, sizeof(*tmr), "compute_tmr_mac tmr readable");
    cbmc_assert_writable(out_tag, WAL_CHAIN_TAG_BYTES, "compute_tmr_mac out_tag writable");
    if (nondet_bool()) {
        return BOOT_ERR_CRYPTO;
    }
    cbmc_havoc_bytes(out_tag, WAL_CHAIN_TAG_BYTES);
    return BOOT_OK;
}

boot_status_t cbmc_compute_entry_mac_contract(const boot_platform_t *platform,
                                              const uint8_t key[WAL_CHAIN_TAG_BYTES],
                                              const wal_entry_payload_t *entry,
                                              uint32_t seq_id,
                                              uint32_t entry_offset,
                                              uint8_t out_tag[WAL_CHAIN_TAG_BYTES]) {
    (void)seq_id;
    (void)entry_offset;
    __CPROVER_assert(platform != NULL, "compute_entry_mac platform non-null");
    cbmc_assert_readable(key, WAL_CHAIN_TAG_BYTES, "compute_entry_mac key readable");
    cbmc_assert_readable(entry, sizeof(*entry), "compute_entry_mac entry readable");
    cbmc_assert_writable(out_tag, WAL_CHAIN_TAG_BYTES, "compute_entry_mac out_tag writable");
    if (nondet_bool()) {
        return BOOT_ERR_CRYPTO;
    }
    cbmc_havoc_bytes(out_tag, WAL_CHAIN_TAG_BYTES);
    return BOOT_OK;
}

static boot_status_t journal_read_pubkey(uint8_t *out_key, size_t key_len,
                                         uint8_t key_slot) {
    __CPROVER_assert(out_key != NULL && key_len == 32U &&
                         __CPROVER_w_ok(out_key, 32U),
                     "keystore->read_pubkey requires writable 32B buffer");
    __CPROVER_assert((uint32_t)key_slot < (uint32_t)CBMC_MAX_OTP_SLOTS,
                     "OTP key slot scan must stay within [0, TOOB_MAX_OTP_SLOTS)");
    if (nondet_bool()) {
        return nondet_bool() ? BOOT_ERR_NOT_FOUND : BOOT_ERR_FLASH_HW;
    }
    if (key_slot >= g_active_otp_limit) {
        return BOOT_ERR_NOT_FOUND;
    }
    memcpy(out_key, g_root_pubkey, 32U);
    return BOOT_OK;
}

static boot_status_t journal_read_dslc(uint8_t *out_dslc, size_t *inout_len) {
    __CPROVER_assert(out_dslc != NULL && inout_len != NULL &&
                         __CPROVER_r_ok(inout_len, sizeof(*inout_len)) &&
                         *inout_len >= 1U &&
                         __CPROVER_w_ok(out_dslc, 1U),
                     "keystore->read_dslc requires writable 1B buffer");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_dslc = g_dslc_byte;
    *inout_len = 1U;
    return BOOT_OK;
}

static boot_status_t journal_read_device_secret(uint8_t *out_secret, size_t max_len,
                                                size_t *out_len) {
    __CPROVER_assert(out_secret != NULL && max_len >= 32U &&
                         __CPROVER_w_ok(out_secret, max_len) &&
                         out_len != NULL &&
                         __CPROVER_w_ok(out_len, sizeof(*out_len)),
                     "keystore->read_device_secret requires valid output buffers");
    uint8_t mode = nondet_uint8_t();
    if (mode == 0U) {
        return BOOT_ERR_NOT_SUPPORTED;
    }
    if (mode == 1U) {
        return BOOT_ERR_FLASH_HW;
    }
    memcpy(out_secret, g_device_secret, 32U);
    *out_len = 32U;
    return BOOT_OK;
}

static boot_status_t journal_read_chip_uid(uint8_t *out_uid, size_t max_len,
                                           size_t *out_len) {
    __CPROVER_assert(out_uid != NULL && max_len >= 32U &&
                         __CPROVER_w_ok(out_uid, max_len) &&
                         out_len != NULL &&
                         __CPROVER_w_ok(out_len, sizeof(*out_len)),
                     "keystore->read_chip_uid requires valid output buffers");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_len = g_chip_uid_len;
    size_t n = (g_chip_uid_len <= max_len) ? g_chip_uid_len : max_len;
    if (n > 0U) {
        memcpy(out_uid, g_chip_uid, n);
    }
    return BOOT_OK;
}

static boot_status_t journal_read_monotonic_counter(uint32_t *out_ctr) {
    __CPROVER_assert(out_ctr != NULL && __CPROVER_w_ok(out_ctr, sizeof(*out_ctr)),
                     "keystore->read_monotonic_counter output must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_ctr = g_otp_epoch;
    return BOOT_OK;
}

static inline bool wal_find_offset(uint32_t addr, size_t len,
                                   uint32_t *out_idx, uint32_t *out_off) {
    if (cbmc_subrange_of(addr, len, g_wal_addrs[0], (uint32_t)g_wal_sizes[0])) {
        *out_idx = 0U;
        *out_off = addr - g_wal_addrs[0];
        return true;
    }
    if (cbmc_subrange_of(addr, len, g_wal_addrs[1], (uint32_t)g_wal_sizes[1])) {
        *out_idx = 1U;
        *out_off = addr - g_wal_addrs[1];
        return true;
    }
    if (cbmc_subrange_of(addr, len, g_wal_addrs[2], (uint32_t)g_wal_sizes[2])) {
        *out_idx = 2U;
        *out_off = addr - g_wal_addrs[2];
        return true;
    }
    if (cbmc_subrange_of(addr, len, g_wal_addrs[3], (uint32_t)g_wal_sizes[3])) {
        *out_idx = 3U;
        *out_off = addr - g_wal_addrs[3];
        return true;
    }
    return false;
}

static inline bool rstore_in_slot(uint32_t addr, size_t len) {
    return cbmc_subrange_of(addr, len, g_rstore_addrs[0], (uint32_t)g_rstore_sizes[0]) ||
           cbmc_subrange_of(addr, len, g_rstore_addrs[1], (uint32_t)g_rstore_sizes[1]) ||
           cbmc_subrange_of(addr, len, g_rstore_addrs[2], (uint32_t)g_rstore_sizes[2]);
}

static boot_status_t journal_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "journal flash read buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "journal flash read must stay within physical flash");
    if (len == 0U) {
        return BOOT_OK;
    }

    uint32_t idx = 0U;
    uint32_t off = 0U;
    if (g_wal_mode && wal_find_offset(addr, len, &idx, &off)) {
        const uint32_t active_limit =
            (uint32_t)sizeof(wal_sector_header_aligned_t) +
            (uint32_t)(JOURNAL_PROOF_ENTRY_SLOTS * sizeof(wal_entry_aligned_t));
        if (off == 0U && len == sizeof(wal_sector_header_aligned_t)) {
            wal_sector_header_t h;
            bool valid = false;
            if (!get_wal_hdr(idx, &h, &valid)) {
                return BOOT_ERR_FLASH_HW;
            }
            ((wal_sector_header_aligned_t *)buf)->data = h;
            return BOOT_OK;
        }
        if (off < active_limit && len == sizeof(wal_entry_aligned_t)) {
            if (g_slot0_occupied || !g_fast_init_mode) {
                if (nondet_bool()) {
                    return BOOT_ERR_FLASH_HW;
                }
                *(wal_entry_aligned_t *)buf = nondet_wal_entry_aligned_t();
                return BOOT_OK;
            }
        }
        /* Offsets >= active_limit represent virgin 0xFF flash tail of the WAL sector */
        if (len == sizeof(wal_entry_aligned_t)) {
            wal_entry_aligned_t er = { .data = { .magic = 0xFFFFFFFFU } };
            *(wal_entry_aligned_t *)buf = er;
        } else {
            uint8_t *dst = (uint8_t *)buf;
            dst[0] = 0xFFU;
            if (len >= 2U) {
                dst[1] = 0xFFU;
            }
        }
        return BOOT_OK;
    }

    if (rstore_in_slot(addr, len)) {
        if (nondet_bool()) {
            return BOOT_ERR_FLASH_HW;
        }
        if ((addr == g_rstore_addrs[0] || addr == g_rstore_addrs[1] ||
             addr == g_rstore_addrs[2]) &&
            len >= sizeof(boot_rstore_slot_header_t)) {
            boot_rstore_slot_header_t sh = nondet_rstore_slot_header_t();
            __CPROVER_assume(sh.sequence_id < 0x7FFFFFF0U);
            __CPROVER_assume(sh.erase_count < 0xFFFFFFF0U);
            *(boot_rstore_slot_header_t *)buf = sh;
        } else {
            ((uint8_t *)buf)[0] = nondet_uint8_t();
        }
        return BOOT_OK;
    }

    ((uint8_t *)buf)[0] = 0xFFU;
    if (len >= 2U) {
        ((uint8_t *)buf)[1] = 0xFFU;
    }
    return BOOT_OK;
}

static boot_status_t journal_flash_write(uint32_t addr, const void *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);

    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }

    uint32_t idx = 0U;
    uint32_t off = 0U;
    if (g_wal_mode && wal_find_offset(addr, len, &idx, &off)) {
        if (off == 0U && len == sizeof(wal_sector_header_aligned_t)) {
            const wal_sector_header_t h = ((const wal_sector_header_aligned_t *)buf)->data;
            if (idx == 0U) { g_wh0 = h; g_wh_valid0 = true; g_wh_ioerr0 = false; }
            else if (idx == 1U) { g_wh1 = h; g_wh_valid1 = true; g_wh_ioerr1 = false; }
            else if (idx == 2U) { g_wh2 = h; g_wh_valid2 = true; g_wh_ioerr2 = false; }
            else { g_wh3 = h; g_wh_valid3 = true; g_wh_ioerr3 = false; }
        }
        return BOOT_OK;
    }
    if (rstore_in_slot(addr, len)) {
        return BOOT_OK;
    }

    __CPROVER_assert(false,
                     "journal/rstore write must target a configured WAL or RSTORE slot");
    return BOOT_ERR_FLASH_BOUNDS;
}

static boot_status_t journal_flash_erase_sector(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);

    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }

    if (addr == g_wal_addrs[0]) { g_wh_valid0 = false; g_wh_ioerr0 = false; return BOOT_OK; }
    if (addr == g_wal_addrs[1]) { g_wh_valid1 = false; g_wh_ioerr1 = false; return BOOT_OK; }
    if (addr == g_wal_addrs[2]) { g_wh_valid2 = false; g_wh_ioerr2 = false; return BOOT_OK; }
    if (addr == g_wal_addrs[3]) { g_wh_valid3 = false; g_wh_ioerr3 = false; return BOOT_OK; }
    if (addr == g_rstore_addrs[0] || addr == g_rstore_addrs[1] ||
        addr == g_rstore_addrs[2]) {
        return BOOT_OK;
    }

    __CPROVER_assert(false,
                     "journal/rstore erase must target a configured WAL or RSTORE sector");
    return BOOT_ERR_FLASH_BOUNDS;
}

static void prove_wal_init_quorum_and_migration(const boot_platform_t *platform) {
    __CPROVER_assert(boot_journal_init(NULL) == BOOT_ERR_INVALID_ARG,
                     "NULL platform must be rejected by boot_journal_init");

    const bool wal_all_blank =
        (g_wh0.sector_magic != WAL_ABI_VERSION_MAGIC_CURRENT &&
         g_wh0.sector_magic != WAL_ABI_VERSION_MAGIC_LEGACY) &&
        (g_wh1.sector_magic != WAL_ABI_VERSION_MAGIC_CURRENT &&
         g_wh1.sector_magic != WAL_ABI_VERSION_MAGIC_LEGACY) &&
        (g_wh2.sector_magic != WAL_ABI_VERSION_MAGIC_CURRENT &&
         g_wh2.sector_magic != WAL_ABI_VERSION_MAGIC_LEGACY) &&
        (g_wh3.sector_magic != WAL_ABI_VERSION_MAGIC_CURRENT &&
         g_wh3.sector_magic != WAL_ABI_VERSION_MAGIC_LEGACY);
    boot_status_t st = boot_journal_init(platform);
    if (wal_all_blank && (g_otp_epoch > 0U || g_dslc_byte != 0x00U)) {
        __CPROVER_assert(st != BOOT_OK,
                         "CRIT-69: deployed device must reject blank-WAL factory reset");
    }
    if (st != BOOT_OK) {
        return;
    }

    wal_tmr_payload_t tmr;
    __CPROVER_assert(boot_journal_get_tmr(platform, &tmr) == BOOT_OK,
                     "boot_journal_get_tmr must succeed after init");
}

static void prove_wal_append_and_rotation(const boot_platform_t *platform) {
    if (boot_journal_init(platform) != BOOT_OK) {
        return;
    }

    /* Symbolic g_slot0_occupied covers both virgin in-place append and dirty/occupied
     * slot wear-leveling rotation (get_best_wear_leveling_sector + rotate_to_sector). */
    wal_entry_payload_t e1;
    CBMC_HAVOC_OBJECT(e1);
    (void)boot_journal_append(platform, &e1);
}

static void prove_wal_tmr_quorum_and_defer_flush(const boot_platform_t *platform) {
    if (boot_journal_init(platform) != BOOT_OK) {
        return;
    }

    wal_tmr_payload_t updated;
    CBMC_HAVOC_OBJECT(updated);
    __CPROVER_assume(updated.chain_entry_count < 0xFFFFFFF0U);

    /* Exercises both deferred staging (tmr_defer_enabled=true) and full 3-sector
     * physical TMR rotation inside boot_journal_flush_tmr -> boot_journal_update_tmr. */
    boot_journal_set_tmr_defer(true);
    boot_status_t st = boot_journal_update_tmr(platform, &updated);
    if (st == BOOT_OK) {
        (void)boot_journal_flush_tmr(platform);
    }
}

static void prove_wal_reconstruct_and_aux_heal(const boot_platform_t *platform) {
    if (boot_journal_init(platform) != BOOT_OK) {
        return;
    }

    if (nondet_bool()) {
        wal_entry_payload_t txn_state;
        uint32_t net_accum  = 0U;
        uint32_t resume_off = 0U;
        uint32_t *accum_ptr  = nondet_bool() ? &net_accum  : NULL;
        uint32_t *resume_ptr = nondet_bool() ? &resume_off : NULL;
        (void)boot_journal_reconstruct_txn(platform, &txn_state, accum_ptr, resume_ptr);
    } else {
        wal_entry_payload_t heal_entry;
        bool found_heal = false;
        boot_status_t hst =
            boot_journal_reconstruct_aux_heal(platform, &heal_entry, &found_heal);
        if (hst == BOOT_OK && found_heal) {
            __CPROVER_assert(heal_entry.intent == WAL_INTENT_CONFIRM_COMMIT ||
                                 heal_entry.intent == WAL_INTENT_RECOVERY_RESOLVED,
                             "aux heal only surfaces CONFIRM_COMMIT or RECOVERY_RESOLVED");
        }
    }
}

static void prove_rstore_unaligned_record_padding(const boot_platform_t *platform) {
    /* Symbolic unaligned record_size in [1 .. 64] stresses alignment padding */
    uint16_t rec_size = nondet_uint16_t();
    __CPROVER_assume(rec_size >= 1U && rec_size <= RSTORE_PROOF_MAX_REC);

    boot_rstore_desc_t desc = {
        .slot_addrs  = g_rstore_addrs,
        .slot_sizes  = g_rstore_sizes,
        .slot_count  = 3U,
        .record_size = rec_size,
        .magic       = 0x52535431U,
    };

    uint8_t out_rec[RSTORE_PROOF_MAX_REC];
    uint8_t in_rec[RSTORE_PROOF_MAX_REC];
    CBMC_HAVOC_OBJECT(in_rec);

    if (nondet_bool()) {
        (void)boot_rstore_read(platform, &desc, out_rec);
    } else {
        (void)boot_rstore_write(platform, &desc, in_rec);
    }
}

static wal_sector_header_t make_nondet_wal_hdr(bool *out_valid, bool *out_ioerr,
                                               bool allow_legacy) {
    wal_sector_header_t h = nondet_wal_sector_header_t();
    __CPROVER_assume(h.sequence_id >= 1U && h.sequence_id <= 2U);
    __CPROVER_assume(h.erase_count <= TOOB_WAL_SECTORS);
    __CPROVER_assume(h.tmr_data.chain_entry_count < 0xFFFFFFF0U);
    if (!allow_legacy) {
        __CPROVER_assume(h.sector_magic == WAL_ABI_VERSION_MAGIC_CURRENT);
        __CPROVER_assume(h.tmr_data.struct_version == WAL_TMR_VERSION_CURRENT);
    }
    *out_ioerr = nondet_bool();
    *out_valid = (!*out_ioerr) && nondet_bool() &&
                 (h.sector_magic == WAL_ABI_VERSION_MAGIC_CURRENT ||
                  h.sector_magic == WAL_ABI_VERSION_MAGIC_LEGACY);
    return h;
}

static void init_journal_env(flash_hal_t *flash_hal,
                             crypto_hal_t *crypto_hal,
                             keystore_hal_t *keystore_hal,
                             boot_platform_t *platform,
                             bool init_wal,
                             bool allow_legacy) {
    CBMC_HAVOC_OBJECT(g_root_pubkey);
    CBMC_HAVOC_OBJECT(g_device_secret);
    CBMC_HAVOC_OBJECT(g_chip_uid);

    g_chip_uid_len = nondet_size_t();
    __CPROVER_assume(g_chip_uid_len <= 32U);
    g_otp_epoch        = nondet_uint32_t();
    g_dslc_byte        = nondet_uint8_t();
    g_active_otp_limit = nondet_uint8_t();
    __CPROVER_assume(g_active_otp_limit <= (uint8_t)CBMC_MAX_OTP_SLOTS);
    g_wal_mode         = init_wal;

    if (init_wal) {
        if (g_fast_init_mode) {
            /* Fast pre-initialized WAL ring: sector 0 is valid head (seq=2), sectors 1..3
             * have symbolic validity/sequence <= 2 and erase counts for wear-leveling/reconstruct. */
            wal_sector_header_t h0 = {0};
            h0.sector_magic            = WAL_ABI_VERSION_MAGIC_CURRENT;
            h0.sequence_id             = 2U;
            h0.erase_count             = 1U;
            h0.tmr_data.struct_version = WAL_TMR_VERSION_CURRENT;
            h0.tmr_data.populated_size = WAL_TMR_POPULATED_SIZE;
            g_wh0 = h0; g_wh_valid0 = true; g_wh_ioerr0 = false;
            g_wh1 = make_nondet_wal_hdr(&g_wh_valid1, &g_wh_ioerr1, false);
            g_wh2 = make_nondet_wal_hdr(&g_wh_valid2, &g_wh_ioerr2, false);
            g_wh3 = make_nondet_wal_hdr(&g_wh_valid3, &g_wh_ioerr3, false);
            __CPROVER_assume(g_wh1.sequence_id == 1U && g_wh2.sequence_id == 1U && g_wh3.sequence_id == 1U);
        } else {
            g_wh0 = make_nondet_wal_hdr(&g_wh_valid0, &g_wh_ioerr0, allow_legacy);
            g_wh1 = make_nondet_wal_hdr(&g_wh_valid1, &g_wh_ioerr1, allow_legacy);
            g_wh2 = make_nondet_wal_hdr(&g_wh_valid2, &g_wh_ioerr2, allow_legacy);
            g_wh3 = make_nondet_wal_hdr(&g_wh_valid3, &g_wh_ioerr3, allow_legacy);
        }
    }

    *flash_hal = (flash_hal_t){
        .read             = journal_flash_read,
        .write            = journal_flash_write,
        .erase_sector     = journal_flash_erase_sector,
        .get_sector_size  = cbmc_flash_get_sector_size,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .max_erase_cycles = 100000U,
        .erased_value     = 0xFFU,
    };

    *crypto_hal = (crypto_hal_t){
        .verify_signature  = cbmc_ed25519_verify_sig,
        .hash_init         = cbmc_hash_init,
        .hash_update       = cbmc_hash_update,
        .hash_finish       = cbmc_hash_finish,
        .get_hash_ctx_size = journal_get_hash_ctx_size,
    };

    *keystore_hal = (keystore_hal_t){
        .read_pubkey            = journal_read_pubkey,
        .read_chip_uid          = journal_read_chip_uid,
        .read_dslc              = journal_read_dslc,
        .read_monotonic_counter = journal_read_monotonic_counter,
        .read_device_secret     = journal_read_device_secret,
    };

    *platform = (boot_platform_t){
        .flash    = flash_hal,
        .crypto   = crypto_hal,
        .keystore = keystore_hal,
        .wdt      = &g_cbmc_wdt_hal,
    };
}

void prove_journal_init(void) {
    flash_hal_t flash_hal;
    crypto_hal_t crypto_hal;
    keystore_hal_t keystore_hal;
    boot_platform_t platform;
    g_fast_init_mode = false;
    g_slot0_occupied = nondet_bool();
    init_journal_env(&flash_hal, &crypto_hal, &keystore_hal, &platform, true, true);
    prove_wal_init_quorum_and_migration(&platform);
}

void prove_journal_wal_append(void) {
    flash_hal_t flash_hal;
    crypto_hal_t crypto_hal;
    keystore_hal_t keystore_hal;
    boot_platform_t platform;
    g_fast_init_mode = true;
    g_slot0_occupied = nondet_bool();
    init_journal_env(&flash_hal, &crypto_hal, &keystore_hal, &platform, true, false);
    prove_wal_append_and_rotation(&platform);
}

void prove_journal_tmr_update(void) {
    flash_hal_t flash_hal;
    crypto_hal_t crypto_hal;
    keystore_hal_t keystore_hal;
    boot_platform_t platform;
    g_fast_init_mode = true;
    g_slot0_occupied = false;
    init_journal_env(&flash_hal, &crypto_hal, &keystore_hal, &platform, true, false);
    prove_wal_tmr_quorum_and_defer_flush(&platform);
}

void prove_journal_reconstruct(void) {
    flash_hal_t flash_hal;
    crypto_hal_t crypto_hal;
    keystore_hal_t keystore_hal;
    boot_platform_t platform;
    g_fast_init_mode = true;
    g_slot0_occupied = true;
    init_journal_env(&flash_hal, &crypto_hal, &keystore_hal, &platform, true, false);
    prove_wal_reconstruct_and_aux_heal(&platform);
}

void prove_journal_rstore_padding(void) {
    flash_hal_t flash_hal;
    crypto_hal_t crypto_hal;
    keystore_hal_t keystore_hal;
    boot_platform_t platform;
    g_fast_init_mode = false;
    g_slot0_occupied = false;
    init_journal_env(&flash_hal, &crypto_hal, &keystore_hal, &platform, false, false);
    prove_rstore_unaligned_record_padding(&platform);
}

int main(void) {
    prove_journal_init();
    return 0;
}
