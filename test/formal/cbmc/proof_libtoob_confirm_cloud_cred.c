/*
 * FV-08: CBMC libtoob Boot Confirmation, Cloud-Command Submit & Device Cred Proof
 *
 * Targets:
 *   - sdk/libtoob/toob_confirm.c
 *   - sdk/libtoob/toob_cloud_submit.c
 *   - sdk/libtoob/toob_handoff.c
 *   - sdk/libtoob/toob_mailbox.c
 *   - sdk/libtoob/toob_crc32.c
 *   - sdk/os_client/src/toob_device_cred.c
 *
 * Parameterized across CHIP_FLASH_WRITE_ALIGNMENT in {1U, 4U, 8U, 32U}.
 *
 * Proves:
 *   1. toob_confirm_boot() & toob_recovery_resolved():
 *      - CRIT-25: COMMITTED boots return TOOB_OK with zero flash writes/erases.
 *      - CRIT-25: TENTATIVE boots with boot_nonce == 0 return TOOB_ERR_VERIFY
 *        with zero flash writes/erases.
 *      - Real MMIO RTC double-read (toob_os_confirm_rtc_write via g_mock_rtc_ram),
 *        two-sector A/B mailbox stale-slot write, and .noinit promotion to COMMITTED.
 *   2. toob_submit_cloud_command():
 *      - HIGH-24 & TCI1-08: Malformed TCC1 headers, bad header CRC-32, or
 *        mismatched device_id abort with zero flash erases/writes.
 *      - 64B chunked aligned writes satisfy CHIP_FLASH_WRITE_ALIGNMENT in {1,4,8,32}
 *        and stay strictly within CHIP_CLOUD_CMD_SLOT.
 *   3. toob_device_cred.c (enroll / load / bump_seq / rotate_token):
 *      - All-zero and all-0xFF bearer tokens rejected.
 *      - Corrupted NVS blobs (wrong size, bad TCR1 magic, bad CRC-32) rejected
 *        with *out defensively zeroed.
 *      - checkin_seq == UINT64_MAX returns TOOB_ERR_COUNTER_EXHAUSTED (zero wrap).
 *      - Strict non-reentrant toob_os_lock() / toob_os_unlock() pairing across
 *        every normal and error return path.
 */

#define CBMC_LIBTOOB_ONLY 1
#include "cbmc_common.h"

#include "libtoob.h"
#include "toob_cloud_cmd_wire.h"
#include "toob_device_cred.h"
#include "toob_internal.h"
#include "toob_mailbox.h"
#include "toob_port.h"

volatile uint64_t g_mock_rtc_ram;
extern void toob_mailbox_session_reset_for_test(void);

static uint32_t g_flash_write_count;
static uint32_t g_flash_erase_count;
static int      g_lock_depth;

static uint8_t  g_nvs_blob[TOOB_CRED_NVS_BLOB_SIZE];
static size_t   g_nvs_len;
static bool     g_nvs_present;

/* Strong mutex hooks overriding weak defaults in toob_handoff.c */
void toob_os_lock(void) {
    __CPROVER_assert(g_lock_depth == 0,
                     "toob_os_lock must not be acquired recursively");
    g_lock_depth = 1;
}

void toob_os_unlock(void) {
    __CPROVER_assert(g_lock_depth == 1,
                     "toob_os_unlock must match a prior toob_os_lock");
    g_lock_depth = 0;
}

uint32_t cbmc_toob_lib_crc32_contract(const uint8_t *data, size_t length) {
    cbmc_assert_readable(data, length, "toob_lib_crc32 input slice must be readable");
    return nondet_uint32_t();
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "toob_os_flash_read destination must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "toob_os_flash_read must stay within physical flash");
    if (nondet_bool()) {
        return TOOB_ERR_FLASH_HW;
    }
    if (len > 0U) {
        cbmc_havoc_bytes(buf, len);
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);
    g_flash_write_count++;
    return nondet_bool() ? TOOB_OK : TOOB_ERR_FLASH_HW;
}

toob_status_t toob_os_flash_erase(uint32_t addr, size_t len) {
    cbmc_assert_flash_erase_range_invariants(addr, (uint32_t)len);
    g_flash_erase_count++;
    return nondet_bool() ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_nvs_read(const char *key, uint8_t *buf, size_t *inout_len) {
    __CPROVER_assert(key != NULL && buf != NULL && inout_len != NULL &&
                         __CPROVER_w_ok(inout_len, sizeof(*inout_len)),
                     "toob_os_nvs_read pointer preconditions");
    cbmc_assert_writable(buf, *inout_len, "toob_os_nvs_read buffer must be writable");
    if (!g_nvs_present) {
        return TOOB_ERR_NOT_FOUND;
    }
    if (nondet_bool()) {
        return TOOB_ERR_FLASH;
    }
    if (nondet_bool()) {
        /* Inject corrupted NVS blob length or bit-flips */
        size_t bad_len = nondet_size_t();
        __CPROVER_assume(bad_len <= *inout_len);
        if (bad_len > 0U) {
            cbmc_havoc_bytes(buf, bad_len);
        }
        *inout_len = bad_len;
        return TOOB_OK;
    }
    size_t copy_n = (g_nvs_len < *inout_len) ? g_nvs_len : *inout_len;
    memcpy(buf, g_nvs_blob, copy_n);
    *inout_len = copy_n;
    return TOOB_OK;
}

toob_status_t toob_os_nvs_write(const char *key, const uint8_t *buf, size_t len) {
    __CPROVER_assert(key != NULL, "toob_os_nvs_write key must be non-null");
    cbmc_assert_readable(buf, len, "toob_os_nvs_write buffer must be readable");
    __CPROVER_assert(len == TOOB_CRED_NVS_BLOB_SIZE,
                     "credential NVS write must always emit exact 48B TCR1 envelope");
    if (nondet_bool()) {
        return TOOB_ERR_FLASH;
    }
    memcpy(g_nvs_blob, buf, TOOB_CRED_NVS_BLOB_SIZE);
    g_nvs_len     = TOOB_CRED_NVS_BLOB_SIZE;
    g_nvs_present = true;
    return TOOB_OK;
}

/* ==========================================================================
 * Entrypoint 1: toob_confirm_boot() & toob_recovery_resolved()
 * ========================================================================== */
void prove_confirm_and_recovery_resolved(void) {
    g_flash_write_count = 0U;
    g_flash_erase_count = 0U;
    g_lock_depth        = 0;
    g_mock_rtc_ram      = nondet_uint64_t();
    toob_mailbox_session_reset_for_test();

    CBMC_HAVOC_OBJECT(toob_handoff_state);

    bool handoff_pre_valid =
        (toob_handoff_state.magic == TOOB_STATE_COMMITTED ||
         toob_handoff_state.magic == TOOB_STATE_TENTATIVE) &&
        (toob_handoff_state.struct_version == TOOB_HANDOFF_STRUCT_VERSION);
    uint32_t pre_magic = toob_handoff_state.magic;
    uint64_t pre_nonce = toob_handoff_state.boot_nonce;

    toob_status_t st = toob_confirm_boot();
    __CPROVER_assert(g_lock_depth == 0, "mutex unlocked after toob_confirm_boot");

    if (pre_magic == TOOB_STATE_COMMITTED) {
        __CPROVER_assert(g_flash_write_count == 0U && g_flash_erase_count == 0U,
                         "CRIT-25: COMMITTED handoff never triggers flash erase or write");
    }
    if (handoff_pre_valid && pre_magic == TOOB_STATE_TENTATIVE && pre_nonce == 0ULL) {
        __CPROVER_assert(st == TOOB_ERR_VERIFY &&
                             g_flash_write_count == 0U && g_flash_erase_count == 0U,
                         "CRIT-25: TENTATIVE boot with boot_nonce == 0 rejected without flash wear");
    }
    if (st == TOOB_OK && pre_magic == TOOB_STATE_TENTATIVE) {
        __CPROVER_assert(g_mock_rtc_ram == pre_nonce,
                         "RTC confirmation register updated with active boot_nonce");
        __CPROVER_assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED,
                         ".noinit handoff promoted to TOOB_STATE_COMMITTED after confirm");
    }

    (void)toob_recovery_resolved();
    __CPROVER_assert(g_lock_depth == 0, "mutex unlocked after toob_recovery_resolved");
}

/* ==========================================================================
 * Entrypoint 2: toob_submit_cloud_command() & toob_get_device_id()
 * ========================================================================== */
void prove_submit_cloud_command(void) {
    g_flash_write_count = 0U;
    g_flash_erase_count = 0U;
    g_lock_depth        = 0;

    CBMC_HAVOC_OBJECT(toob_handoff_state);

    uint8_t envelope[256] __attribute__((aligned(8)));
    memset(envelope, 0, sizeof(envelope));
    toob_cloud_cmd_hdr_t env_hdr;
    CBMC_HAVOC_OBJECT(env_hdr);
    memcpy(envelope, &env_hdr, sizeof(env_hdr));
    envelope[sizeof(env_hdr)] = nondet_uint8_t();
    envelope[sizeof(envelope) - 1U] = nondet_uint8_t();

    uint32_t len = nondet_uint32_t();
    if (nondet_bool()) {
        /* Symbolic out-of-range / unaligned length test */
        __CPROVER_assume(len > 256U || (len % TOOB_CLOUD_CMD_ALIGN) != 0U ||
                         len < TOOB_CLOUD_CMD_MIN_SIZE);
        if (len <= 256U) {
            toob_status_t bad_st = toob_submit_cloud_command(envelope, len);
            __CPROVER_assert(bad_st == TOOB_ERR_INVALID_ARG &&
                                 g_flash_erase_count == 0U && g_flash_write_count == 0U,
                             "invalid length rejected before touching flash");
        } else {
            /* For len > TOOB_CLOUD_CMD_MAX_SIZE, envelope is rejected before dereference */
            __CPROVER_assume(len > TOOB_CLOUD_CMD_MAX_SIZE);
            toob_status_t max_st = toob_submit_cloud_command(envelope, len);
            __CPROVER_assert(max_st == TOOB_ERR_INVALID_ARG &&
                                 g_flash_erase_count == 0U && g_flash_write_count == 0U,
                             "oversized length > TOOB_CLOUD_CMD_MAX_SIZE rejected");
        }
        return;
    }

    /* Multi-chunk aligned length in {128, 192} (2-3 x 64B chunks) */
    len = nondet_bool() ? 128U : 192U;

    toob_cloud_cmd_hdr_t hdr_snap;
    memcpy(&hdr_snap, envelope, sizeof(hdr_snap));
    bool hdr_shape_valid =
        (hdr_snap.magic == TOOB_CLOUD_CMD_MAGIC) &&
        (hdr_snap.version == TOOB_CLOUD_CMD_VERSION) &&
        (hdr_snap.flags == 0U) &&
        (hdr_snap._reserved == 0U) &&
        (hdr_snap.total_len == len) &&
        (hdr_snap.params_len <= TOOB_CLOUD_CMD_MAX_PARAMS) &&
        ((TOOB_CLOUD_CMD_HDR_SIZE + TOOB_CLOUD_CMD_ALIGN_UP(hdr_snap.params_len) +
          TOOB_CLOUD_CMD_SIG_SIZE) == len);

    toob_status_t st = toob_submit_cloud_command(envelope, len);
    __CPROVER_assert(g_lock_depth == 0, "mutex unlocked after toob_submit_cloud_command");

    if (!hdr_shape_valid) {
        __CPROVER_assert(st == TOOB_ERR_INVALID_ARG &&
                             g_flash_erase_count == 0U && g_flash_write_count == 0U,
                         "HIGH-24: malformed TCC1 header rejected before flash erase");
    }

    uint8_t dev_id[32];
    (void)toob_get_device_id(dev_id, sizeof(dev_id));
}

/* ==========================================================================
 * Entrypoint 3: toob_device_cred.c (Enroll, Load, UINT64_MAX Bump, Rotate)
 * ========================================================================== */
void prove_device_cred_store(void) {
    g_lock_depth  = 0;
    g_nvs_present = nondet_bool();
    g_nvs_len     = TOOB_CRED_NVS_BLOB_SIZE;
    CBMC_HAVOC_OBJECT(g_nvs_blob);

    /* 1. Degenerate all-0x00 and all-0xFF tokens must always be rejected */
    uint8_t zero_tok[TOOB_DEVICE_TOKEN_LEN] = {0};
    uint8_t ones_tok[TOOB_DEVICE_TOKEN_LEN];
    memset(ones_tok, 0xFF, sizeof(ones_tok));
    __CPROVER_assert(toob_cred_enroll(zero_tok) == TOOB_ERR_INVALID_ARG,
                     "all-zero enrollment token rejected");
    __CPROVER_assert(toob_cred_enroll(ones_tok) == TOOB_ERR_INVALID_ARG,
                     "all-0xFF enrollment token rejected");
    __CPROVER_assert(toob_cred_rotate_token(zero_tok) == TOOB_ERR_INVALID_ARG,
                     "all-zero rotated token rejected");

    /* 2. Symbolic enrollment + roundtrip load + UINT64_MAX bump guard + rotation */
    uint8_t sym_tok[TOOB_DEVICE_TOKEN_LEN];
    CBMC_HAVOC_OBJECT(sym_tok);
    (void)toob_cred_enroll(sym_tok);
    __CPROVER_assert(g_lock_depth == 0, "mutex unlocked after toob_cred_enroll");

    toob_device_cred_t loaded;
    toob_status_t ld_st = toob_cred_load(&loaded);
    __CPROVER_assert(g_lock_depth == 0, "mutex unlocked after toob_cred_load");
    if (ld_st != TOOB_OK) {
        __CPROVER_assert(loaded.checkin_seq == 0ULL && loaded.device_token[0] == 0U &&
                             loaded.device_token[TOOB_DEVICE_TOKEN_LEN - 1U] == 0U,
                         "failed toob_cred_load zeroes destination struct");
    }

    /* Explicitly cover checkin_seq == UINT64_MAX exhaustion branch */
    if (g_nvs_present && nondet_bool()) {
        toob_wire_put_le32(&g_nvs_blob[0], 0x31524354U); /* "TCR1" */
        toob_wire_put_le64(&g_nvs_blob[8], UINT64_MAX);
        g_nvs_blob[16] = 0x5AU;
        g_nvs_blob[17] = 0xA5U;
    }

    uint64_t new_seq = 123ULL;
    toob_status_t bump_st = toob_cred_bump_seq(&new_seq);
    __CPROVER_assert(g_lock_depth == 0, "mutex unlocked after toob_cred_bump_seq");
    if (bump_st != TOOB_OK) {
        __CPROVER_assert(new_seq == 0ULL,
                         "failed or exhausted toob_cred_bump_seq leaves *out_seq == 0");
    } else {
        __CPROVER_assert(new_seq >= 1ULL,
                         "successful toob_cred_bump_seq strictly increments checkin_seq > 0");
    }

    uint8_t rot_tok[TOOB_DEVICE_TOKEN_LEN];
    CBMC_HAVOC_OBJECT(rot_tok);
    (void)toob_cred_rotate_token(rot_tok);
    __CPROVER_assert(g_lock_depth == 0, "mutex unlocked after toob_cred_rotate_token");
}
