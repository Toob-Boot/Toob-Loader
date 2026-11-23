/*
 * CBMC Memory-Safety, Pre-Auth Bounds, Anti-Replay & Key-Rotation Proof
 * for boot_cloud_cmd.c + boot_rstore.c + boot_identity.c.
 *
 * Verifies:
 *   1. Fixed 64-byte TCC1 header pre-check (magic, version, flags, total_len
 *      16-byte alignment, params_len alignment consistency, header CRC-32)
 *      with zero variable-length parsing prior to Ed25519 verification.
 *   2. Symbolic Ed25519 verification (nondet_int() exploring both pass/fail
 *      branches) over [0 .. total_len - 64) and KDM 3-slot quorum loading
 *      (including DSLC == 0 eFuse fallback vs DSLC > 0 downgrade lock).
 *   3. Post-auth DICE device_id match, OTP monotonic counter anti-replay floor,
 *      UPD-006 issued_at freshness gate, and hard cap burns_needed <= 4
 *      (exhaustion defense: zero OTP burns prior to signature + ID + freshness).
 *   4. TOOB_CMD_ROTATE_KEY 128-byte KDM validation, Root-Key signature check,
 *      monotonic KDM sequence enforcement, and flash write/erase alignment +
 *      mutable-partition bounds across all 3 KDM quorum sectors.
 *   5. Both boot_cloud_cmd_evaluate_buffer and boot_cloud_cmd_evaluate_flash
 *      (TOCTOU single-read into crypto_arena + non-aliasing work_arena).
 */

#define CBMC_NO_ZEROIZE_STUB 1

#include "cbmc_common.h"
#include "boot_cloud_cmd.h"
#include "boot_journal.h"
#include "boot_rstore.h"

void boot_secure_zeroize(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "boot_secure_zeroize target buffer must be writable");
    if (ptr == NULL || len == 0U) {
        return;
    }
    if (len == BOOT_CRYPTO_ARENA_SIZE && __CPROVER_POINTER_OFFSET(ptr) == 0) {
        typedef struct {
            uint8_t b[BOOT_CRYPTO_ARENA_SIZE];
        } w5a05_arena_t;
        w5a05_arena_t z = {{0}};
        *(w5a05_arena_t *)ptr = z;
        return;
    }
    ((uint8_t *)ptr)[0] = 0U;
}

#define KDM_RECORD_FLASH_BYTES (sizeof(boot_rstore_slot_header_t) + sizeof(toob_kdm_t))
#define TCC1_PROOF_ENV_CAP     320U

#ifdef TOOB_OTP_MAX_SLOTS
#define CBMC_CLOUD_OTP_SLOTS TOOB_OTP_MAX_SLOTS
#else
#define CBMC_CLOUD_OTP_SLOTS 256U
#endif

static uint8_t  g_root_pubkey[32];
static uint8_t  g_prov_cloud_pubkey[32];
static uint8_t  g_chip_uid[32];
static size_t   g_chip_uid_len;
static uint8_t  g_dslc_byte;
static uint8_t  g_active_otp_limit;
static uint8_t  g_otp_fault_slot;
static uint32_t g_otp_counter;
static uint32_t g_otp_burns;
static uint32_t g_last_accepted_ts;
static uint32_t g_initial_kdm_floor;
static bool     g_tmr_avail;

static boot_status_t cloud_entropy_random(uint8_t *buf, size_t len) {
    __CPROVER_assert(len == 0U || (buf != NULL && __CPROVER_w_ok(buf, len)),
                     "entropy->random buffer must be writable");
    cbmc_havoc_bytes(buf, len);
    return nondet_bool() ? BOOT_OK : BOOT_ERR_CRYPTO;
}

static size_t cloud_get_hash_ctx_size(void) {
    return 128U;
}

static boot_status_t cloud_read_pubkey(uint8_t *out_key, size_t key_len,
                                       uint8_t key_slot) {
    __CPROVER_assert(out_key != NULL && key_len == 32U &&
                         __CPROVER_w_ok(out_key, 32U),
                     "keystore->read_pubkey requires writable 32B buffer");
    __CPROVER_assert((uint32_t)key_slot < (uint32_t)CBMC_CLOUD_OTP_SLOTS,
                     "boot_cloud_cmd OTP pubkey scan stays within [0, TOOB_MAX_OTP_SLOTS)");
    if (key_slot >= g_active_otp_limit) {
        return BOOT_ERR_NOT_FOUND;
    }
    if (key_slot == g_otp_fault_slot && nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    memcpy(out_key, (key_slot == 1U) ? g_prov_cloud_pubkey : g_root_pubkey, 32U);
    return BOOT_OK;
}

static boot_status_t cloud_read_dslc(uint8_t *out_dslc, size_t *inout_len) {
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

static boot_status_t cloud_read_chip_uid(uint8_t *out_uid, size_t max_len,
                                         size_t *out_len) {
    __CPROVER_assert(out_uid != NULL && max_len >= 32U &&
                         __CPROVER_w_ok(out_uid, max_len) &&
                         out_len != NULL &&
                         __CPROVER_w_ok(out_len, sizeof(*out_len)),
                     "keystore->read_chip_uid requires valid UID output buffers");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_len = g_chip_uid_len;
    size_t copy_n = (g_chip_uid_len <= max_len) ? g_chip_uid_len : max_len;
    if (copy_n > 0U) {
        memcpy(out_uid, g_chip_uid, copy_n);
    }
    return BOOT_OK;
}

static boot_status_t cloud_read_monotonic_counter(uint32_t *out_counter) {
    __CPROVER_assert(out_counter != NULL &&
                         __CPROVER_w_ok(out_counter, sizeof(*out_counter)),
                     "keystore->read_monotonic_counter output must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    *out_counter = g_otp_counter;
    return BOOT_OK;
}

static boot_status_t cloud_advance_monotonic_counter(void) {
    __CPROVER_assert(g_otp_burns < TOOB_CMD_MAX_BURN_STEPS,
                     "OTP counter burns per command must never exceed TOOB_CMD_MAX_BURN_STEPS");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    g_otp_burns++;
    if (g_otp_counter < UINT32_MAX) {
        g_otp_counter++;
    }
    return BOOT_OK;
}

static boot_status_t cloud_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "flash read buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "flash read must stay within physical flash");
    if (len == 0U) {
        return BOOT_OK;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    if (cbmc_subrange_of(addr, len, CHIP_KDM_QUORUM_ABS_ADDR, CHIP_KDM_QUORUM_SIZE) &&
        len == KDM_RECORD_FLASH_BYTES) {
        __CPROVER_havoc_slice(buf, KDM_RECORD_FLASH_BYTES);
        const boot_rstore_slot_header_t *sh = (const boot_rstore_slot_header_t *)buf;
        __CPROVER_assume(sh->sequence_id < 0x7FFFFFF0U);
        __CPROVER_assume(sh->erase_count < 0xFFFFFFF0U);
    } else if (len == 180U) {
        __CPROVER_havoc_slice(buf, 180U);
    } else {
        uint8_t *dst = (uint8_t *)buf;
        dst[0] = nondet_uint8_t();
    }
    return BOOT_OK;
}

static boot_status_t cloud_flash_write(uint32_t addr, const void *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);
    __CPROVER_assert(cbmc_subrange_of(addr, len, CHIP_KDM_QUORUM_ABS_ADDR,
                                      CHIP_KDM_QUORUM_SIZE),
                     "boot_cloud_cmd flash writes strictly target KDM quorum");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t cloud_flash_erase_sector(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);
    __CPROVER_assert(cbmc_subrange_of(addr, CHIP_FLASH_MAX_SECTOR_SIZE,
                                      CHIP_KDM_QUORUM_ABS_ADDR,
                                      CHIP_KDM_QUORUM_SIZE),
                     "boot_cloud_cmd flash erases strictly target KDM quorum");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr) {
    __CPROVER_assert(platform != NULL && out_tmr != NULL &&
                         __CPROVER_w_ok(out_tmr, sizeof(*out_tmr)),
                     "boot_journal_get_tmr out_tmr must be writable");
    if (!g_tmr_avail) {
        return BOOT_ERR_NOT_FOUND;
    }
    CBMC_HAVOC_OBJECT(*out_tmr);
    out_tmr->last_accepted_issued_at = g_last_accepted_ts;
    out_tmr->kdm_seq_floor           = g_initial_kdm_floor;
    return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
    __CPROVER_assert(platform != NULL && new_tmr != NULL &&
                         __CPROVER_r_ok(new_tmr, sizeof(*new_tmr)),
                     "boot_journal_update_tmr new_tmr must be readable");
    __CPROVER_assert(new_tmr->last_accepted_issued_at > g_last_accepted_ts,
                     "accepted cloud command must strictly advance issued_at watermark");
    __CPROVER_assert(new_tmr->kdm_seq_floor >= g_initial_kdm_floor,
                     "HIGH-104: kdm_seq_floor must remain non-decreasing in TMR");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static void init_cloud_cmd_env(flash_hal_t *flash_hal,
                               crypto_hal_t *crypto_hal,
                               keystore_hal_t *keystore_hal,
                               entropy_hal_t *entropy_hal,
                               boot_platform_t *platform) {
    uint8_t rk_fill = nondet_uint8_t();
    uint8_t ck_fill = nondet_uint8_t();
    memset(g_root_pubkey, rk_fill, sizeof(g_root_pubkey));
    memset(g_prov_cloud_pubkey, ck_fill, sizeof(g_prov_cloud_pubkey));
    if (nondet_bool()) {
        g_root_pubkey[0] ^= nondet_uint8_t();
        g_prov_cloud_pubkey[31] ^= nondet_uint8_t();
    }
    CBMC_HAVOC_OBJECT(g_chip_uid);

    uint8_t uid_sel = nondet_uint8_t();
    if (uid_sel == 0U) {
        g_chip_uid_len = 0U;
    } else if (uid_sel == 1U) {
        g_chip_uid_len = 16U;
    } else if (uid_sel == 2U) {
        g_chip_uid_len = 32U;
    } else {
        g_chip_uid_len = 40U;
    }
    g_dslc_byte        = nondet_uint8_t();
    g_active_otp_limit = nondet_uint8_t();
    __CPROVER_assume(g_active_otp_limit <= (uint8_t)CBMC_CLOUD_OTP_SLOTS);
    g_otp_fault_slot   = nondet_uint8_t();
    __CPROVER_assume(g_otp_fault_slot <= (uint8_t)CBMC_CLOUD_OTP_SLOTS);
    g_otp_counter      = nondet_uint32_t();
    g_otp_burns        = 0U;
    g_last_accepted_ts  = nondet_uint32_t();
    g_initial_kdm_floor = nondet_uint32_t();
    g_tmr_avail         = nondet_bool();

    *flash_hal = (flash_hal_t){
        .read             = cloud_flash_read,
        .write            = cloud_flash_write,
        .erase_sector     = cloud_flash_erase_sector,
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
        .get_hash_ctx_size = cloud_get_hash_ctx_size,
    };

    *keystore_hal = (keystore_hal_t){
        .read_pubkey               = cloud_read_pubkey,
        .read_dslc                 = cloud_read_dslc,
        .read_chip_uid             = cloud_read_chip_uid,
        .read_monotonic_counter    = cloud_read_monotonic_counter,
        .advance_monotonic_counter = cloud_advance_monotonic_counter,
    };

    *entropy_hal = (entropy_hal_t){
        .random = cloud_entropy_random,
    };

    *platform = (boot_platform_t){
        .flash    = flash_hal,
        .crypto   = crypto_hal,
        .keystore = keystore_hal,
        .wdt      = &g_cbmc_wdt_hal,
        .entropy  = entropy_hal,
    };
}

void prove_cloud_cmd_buffer(void) {
    flash_hal_t flash_hal;
    crypto_hal_t crypto_hal;
    keystore_hal_t keystore_hal;
    entropy_hal_t entropy_hal;
    boot_platform_t platform;
    init_cloud_cmd_env(&flash_hal, &crypto_hal, &keystore_hal, &entropy_hal, &platform);

    uint8_t work_arena[256] __attribute__((aligned(8)));
    toob_cloud_cmd_t out_cmd = (toob_cloud_cmd_t)0xFFU;

    __CPROVER_assert(boot_cloud_cmd_evaluate_buffer(&platform, NULL, 128U,
                                                    work_arena, &out_cmd) ==
                         BOOT_ERR_INVALID_ARG,
                     "NULL envelope_buf must be rejected");

    uint8_t ram_env[TCC1_PROOF_ENV_CAP] __attribute__((aligned(8)));
    CBMC_HAVOC_OBJECT(ram_env);
    size_t env_len = nondet_size_t();
    __CPROVER_assume(env_len <= sizeof(ram_env));

    boot_status_t st = boot_cloud_cmd_evaluate_buffer(
        &platform, ram_env, env_len, work_arena, &out_cmd);

    __CPROVER_assert(g_otp_burns <= TOOB_CMD_MAX_BURN_STEPS,
                     "total OTP burns bounded by TOOB_CMD_MAX_BURN_STEPS");
    if (st == BOOT_OK) {
        __CPROVER_assert((uint32_t)out_cmd <= (uint32_t)TOOB_CMD_REVOKE,
                         "accepted command enum must be within [0, TOOB_CMD_REVOKE]");
    }
}

void prove_cloud_cmd_flash(void) {
    flash_hal_t flash_hal;
    crypto_hal_t crypto_hal;
    keystore_hal_t keystore_hal;
    entropy_hal_t entropy_hal;
    boot_platform_t platform;
    init_cloud_cmd_env(&flash_hal, &crypto_hal, &keystore_hal, &entropy_hal, &platform);

    uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));
    toob_cloud_cmd_t out_cmd = (toob_cloud_cmd_t)0xFFU;

    __CPROVER_assert(boot_cloud_cmd_evaluate_flash(NULL, crypto_arena, &out_cmd) ==
                         BOOT_ERR_INVALID_ARG,
                     "NULL platform must be rejected");

    boot_status_t st = boot_cloud_cmd_evaluate_flash(&platform, crypto_arena, &out_cmd);
    __CPROVER_assert(g_otp_burns <= TOOB_CMD_MAX_BURN_STEPS,
                     "total OTP burns bounded by TOOB_CMD_MAX_BURN_STEPS");
    if (st == BOOT_OK) {
        __CPROVER_assert((uint32_t)out_cmd <= (uint32_t)TOOB_CMD_REVOKE,
                         "accepted command enum must be within [0, TOOB_CMD_REVOKE]");
    }
}

int main(void) {
    if (nondet_bool()) {
        prove_cloud_cmd_buffer();
    } else {
        prove_cloud_cmd_flash();
    }
    return 0;
}
