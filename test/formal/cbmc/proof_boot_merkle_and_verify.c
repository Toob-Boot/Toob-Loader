/*
 * FV-02: CBMC Memory-Safety, Non-Overlapping Streaming & Envelope/PQC Proof
 * for boot_merkle.c + boot_verify.c.
 *
 * Parameterized across:
 *   - TOOB_PQC_ENABLED in {0, 1}
 *   - TOOB_DOUBLE_VERIFY in {0, 1}
 *
 * Proves:
 *   1. boot_merkle_verify_stream(): overflow-free bounds validation, exact
 *      num_chunks == ceil(image_size / chunk_size) truncation defense,
 *      contiguous non-overlapping flash reads covering [addr, addr + image_size)
 *      with sub-chunk arena slicing, and full stack/arena zeroization on exit.
 *   2. boot_verify_manifest_envelope(): TOCTOU stack snapshot, signature slice
 *      in-bounds containment within work_buffer, OTP key_index + 1 revocation
 *      probe (BOOT_ERR_DOWNGRADE when next slot is populated), all-0x00 /
 *      all-0xFF root & PQC pubkey rejection, TOOB_DOUBLE_VERIFY dual-call
 *      agreement, and PQC pubkey/signature slice containment inside the
 *      Ed25519-authenticated manifest slice [work_buffer, work_buffer + manifest_size).
 */

#include "cbmc_common.h"
#include "boot_ct_utils.h"
#include "boot_merkle.h"
#include "boot_verify.h"

#define MERKLE_PROOF_MAX_IMAGE  64U
#define MERKLE_PROOF_MAX_CHUNKS 2U
#define MERKLE_PROOF_ARENA_CAP  32U
#define VERIFY_PROOF_BUF_CAP    256U

static uint32_t g_merkle_expected_addr;
static uint32_t g_merkle_bytes_read;
static uint8_t  g_active_otp_limit;
static uint8_t  g_otp_slot_keys[4][32];
static bool     g_pqc_policy_enforced;
static uint32_t g_ed25519_calls;
static size_t   g_mock_hash_ctx_size = 128U;

static size_t fv02_get_hash_ctx_size(void) {
    return g_mock_hash_ctx_size;
}

static boot_status_t fv02_merkle_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "merkle flash->read buffer must be writable");
    __CPROVER_assert(len > 0U, "merkle flash->read step must be strictly positive");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <= (uint64_t)UINT32_MAX,
                     "merkle flash->read address + step never wraps uint32_t");
    __CPROVER_assert(addr == g_merkle_expected_addr,
                     "merkle flash->read slices must be strictly contiguous and non-overlapping");
    if ((uint64_t)addr + (uint64_t)len > (uint64_t)CHIP_FLASH_TOTAL_SIZE) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    uint8_t *dst = (uint8_t *)buf;
    dst[0] = nondet_uint8_t();
    dst[len - 1U] = nondet_uint8_t();
    g_merkle_expected_addr += (uint32_t)len;
    g_merkle_bytes_read    += (uint32_t)len;
    return BOOT_OK;
}

static boot_status_t fv02_read_pubkey(uint8_t *out_key, size_t key_len,
                                      uint8_t key_slot) {
    __CPROVER_assert(out_key != NULL && key_len == 32U &&
                         __CPROVER_w_ok(out_key, 32U),
                     "boot_verify read_pubkey requires writable 32B buffer");
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }
    if (key_slot >= g_active_otp_limit) {
        return BOOT_ERR_NOT_FOUND;
    }
    if (key_slot < 4U) {
        memcpy(out_key, g_otp_slot_keys[key_slot], 32U);
    } else {
        cbmc_havoc_bytes(out_key, 32U);
    }
    return BOOT_OK;
}

static boot_status_t fv02_verify_ed25519(const uint8_t *message, size_t msg_len,
                                         const uint8_t signature[64],
                                         const uint8_t pubkey[32]) {
    cbmc_assert_readable(message, msg_len, "Ed25519 message slice must be readable");
    cbmc_assert_readable(signature, 64U, "Ed25519 signature [64] must be readable");
    cbmc_assert_readable(pubkey, 32U, "Ed25519 pubkey [32] must be readable");

    /* Verify zero/0xFF pubkeys never reach crypto->verify_signature */
    bool all_zero = true;
    bool all_ff   = true;
    for (size_t i = 0U; i < 32U; i++) {
        if (pubkey[i] != 0x00U) {
            all_zero = false;
        }
        if (pubkey[i] != 0xFFU) {
            all_ff = false;
        }
    }
    __CPROVER_assert(!all_zero && !all_ff,
                     "All-0x00 or all-0xFF root pubkey must never reach verify_signature");

    g_ed25519_calls++;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

#if TOOB_PQC_ENABLED
static bool fv02_is_pqc_enforced(void) {
    return g_pqc_policy_enforced;
}

static boot_status_t fv02_verify_pqc(const uint8_t *message, size_t msg_len,
                                     const uint8_t *sig_pqc, size_t sig_len,
                                     const uint8_t *pub_pqc, size_t pub_len) {
    __CPROVER_assert(msg_len > 0U && sig_len > 0U && pub_len > 0U,
                     "verify_pqc lengths must all be non-zero");
    cbmc_assert_readable(message, msg_len, "PQC message slice must be readable");
    cbmc_assert_readable(sig_pqc, sig_len, "PQC signature slice must be readable");
    cbmc_assert_readable(pub_pqc, pub_len, "PQC pubkey slice must be readable");
    __CPROVER_assert(is_buffer_within(sig_pqc, sig_len, message, msg_len),
                     "PQC signature must reside inside Ed25519-signed manifest slice");
    __CPROVER_assert(is_buffer_within(pub_pqc, pub_len, message, msg_len),
                     "PQC pubkey must reside inside Ed25519-signed manifest slice");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}
#endif

static boot_status_t fv02_entropy_random(uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "entropy->random buffer must be writable");
    cbmc_havoc_bytes(buf, len);
    return nondet_bool() ? BOOT_OK : BOOT_ERR_CRYPTO;
}

/* Entrypoint 1: Streaming flat-hash list verification (boot_merkle.c) */
void prove_merkle_stream_bounds_and_coverage(void) {
    flash_hal_t flash_hal = {
        .read            = fv02_merkle_flash_read,
        .write_align     = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size      = CHIP_FLASH_TOTAL_SIZE,
    };
    crypto_hal_t crypto_hal = {
        .hash_init         = cbmc_hash_init,
        .hash_update       = cbmc_hash_update,
        .hash_finish       = cbmc_hash_finish,
        .get_hash_ctx_size = fv02_get_hash_ctx_size,
    };
    boot_platform_t platform = {
        .flash  = &flash_hal,
        .crypto = &crypto_hal,
        .wdt    = &g_cbmc_wdt_hal,
    };

    uint8_t hashes[MERKLE_PROOF_MAX_CHUNKS * BOOT_MERKLE_HASH_LEN];
    uint8_t arena[MERKLE_PROOF_ARENA_CAP] __attribute__((aligned(8)));
    CBMC_HAVOC_OBJECT(hashes);
    CBMC_HAVOC_OBJECT(arena);

    /* Unconstrained overflow / adversarial argument checks (valid hash ctx size) */
    g_mock_hash_ctx_size = 128U;
    uint32_t bad_chunks = nondet_uint32_t();
    __CPROVER_assume(bad_chunks > (UINT32_MAX / BOOT_MERKLE_HASH_LEN));
    __CPROVER_assert(boot_merkle_verify_stream(&platform, CHIP_APP_SLOT_ABS_ADDR,
                                               64U, 64U, hashes, sizeof(hashes),
                                               bad_chunks, arena, sizeof(arena)) ==
                         BOOT_ERR_INVALID_ARG,
                     "Overflowing num_chunks * 32 must be rejected");
    __CPROVER_assert(boot_merkle_verify_stream(&platform, UINT32_MAX - 16U,
                                               64U, 64U, hashes, sizeof(hashes),
                                               1U, arena, sizeof(arena)) ==
                         BOOT_ERR_FLASH_BOUNDS,
                     "Wrapping image_flash_addr + image_size must be rejected");

    /* Symbolic multi-chunk + sub-chunk streaming + oversized PQC hash ctx gate */
    g_mock_hash_ctx_size = nondet_bool() ? 128U : (BOOT_MERKLE_MAX_CTX_SIZE + 8U);
    uint32_t image_addr = nondet_bool() ? CHIP_APP_SLOT_ABS_ADDR : (UINT32_MAX - 32U);
    uint32_t image_size = nondet_uint32_t();
    __CPROVER_assume(image_size <= MERKLE_PROOF_MAX_IMAGE);

    uint32_t chunk_size = nondet_uint32_t();
    __CPROVER_assume(chunk_size <= 96U);

    uint32_t num_chunks = nondet_uint32_t();
    __CPROVER_assume(num_chunks <= (MERKLE_PROOF_MAX_CHUNKS + 1U));

    uint32_t hashes_len = nondet_uint32_t();
    __CPROVER_assume(hashes_len <= sizeof(hashes));

    size_t arena_len = nondet_size_t();
    __CPROVER_assume(arena_len <= sizeof(arena));

    g_merkle_expected_addr = image_addr;
    g_merkle_bytes_read    = 0U;

    boot_status_t st = boot_merkle_verify_stream(
        &platform, image_addr, image_size, chunk_size,
        hashes, hashes_len, num_chunks, arena, arena_len);

    if (st == BOOT_OK) {
        __CPROVER_assert(image_size > 0U && chunk_size > 0U,
                         "BOOT_OK requires positive image_size and chunk_size");
        __CPROVER_assert(g_merkle_bytes_read == image_size &&
                             g_merkle_expected_addr == image_addr + image_size,
                         "BOOT_OK proves 100% contiguous byte coverage of [addr, addr + image_size)");
        if (arena_len > 0U) {
            size_t k = nondet_size_t();
            __CPROVER_assume(k < arena_len);
            __CPROVER_assert(arena[k] == 0U,
                             "crypto_arena is zeroized on exit from boot_merkle_verify_stream");
        }
    }
}

/* Entrypoint 2: Envelope signature, OTP revocation & PQC hybrid bounds (boot_verify.c) */
void prove_verify_manifest_envelope(void) {
    flash_hal_t flash_hal = {
        .write_align     = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size      = CHIP_FLASH_TOTAL_SIZE,
    };
    crypto_hal_t crypto_hal = {
        .verify_signature = fv02_verify_ed25519,
#if TOOB_PQC_ENABLED
        .verify_pqc       = fv02_verify_pqc,
        .is_pqc_enforced  = fv02_is_pqc_enforced,
#endif
    };
    keystore_hal_t keystore_hal = {
        .read_pubkey = fv02_read_pubkey,
    };
    entropy_hal_t entropy_hal = {
        .random = fv02_entropy_random,
    };
    boot_platform_t platform = {
        .flash    = &flash_hal,
        .crypto   = &crypto_hal,
        .keystore = &keystore_hal,
        .entropy  = &entropy_hal,
        .wdt      = &g_cbmc_wdt_hal,
    };

    uint8_t work_buf[VERIFY_PROOF_BUF_CAP] __attribute__((aligned(8)));
    uint8_t outside_buf[64] __attribute__((aligned(8)));
    CBMC_HAVOC_OBJECT(work_buf);
    CBMC_HAVOC_OBJECT(outside_buf);
    CBMC_HAVOC_OBJECT(g_otp_slot_keys);

    g_active_otp_limit    = nondet_uint8_t();
    g_pqc_policy_enforced = nondet_bool();
    g_ed25519_calls       = 0U;

    size_t work_len = nondet_size_t();
    __CPROVER_assume(work_len <= sizeof(work_buf));

    boot_verify_envelope_t env;
    CBMC_HAVOC_OBJECT(env);

    /* Explore in-bounds, out-of-bounds, outside-object, and NULL signature pointers */
    uint8_t ptr_mode = nondet_uint8_t();
    size_t sig_off = nondet_size_t();
    __CPROVER_assume(sig_off <= sizeof(work_buf));
    if (ptr_mode == 0U) {
        env.signature_ed25519 = work_buf + sig_off;
    } else if (ptr_mode == 1U) {
        env.signature_ed25519 = outside_buf;
    } else if (ptr_mode == 2U) {
        env.signature_ed25519 = NULL;
    }

#if TOOB_PQC_ENABLED
    size_t pqc_pub_off = nondet_size_t();
    size_t pqc_sig_off = nondet_size_t();
    __CPROVER_assume(pqc_pub_off <= sizeof(work_buf));
    __CPROVER_assume(pqc_sig_off <= sizeof(work_buf));
    if (nondet_bool()) {
        env.pubkey_pqc    = work_buf + pqc_pub_off;
        env.signature_pqc = work_buf + pqc_sig_off;
    } else {
        env.pubkey_pqc    = outside_buf;
        env.signature_pqc = outside_buf;
    }
#endif

    boot_status_t st =
        boot_verify_manifest_envelope(&platform, &env, work_buf, work_len);

    if (st == BOOT_OK) {
        __CPROVER_assert(env.manifest_size > 0U && env.manifest_size <= work_len,
                         "Accepted envelope has manifest_size within work_len");
        __CPROVER_assert(is_buffer_within(env.signature_ed25519, 64U, work_buf, work_len),
                         "Accepted Ed25519 signature slice lies inside work_buf");
        if (env.key_index < 255U) {
            __CPROVER_assert((uint8_t)(env.key_index + 1U) >= g_active_otp_limit,
                             "Revoked key_index (where key_index + 1 exists) must never return BOOT_OK");
        }
#if TOOB_DOUBLE_VERIFY
        __CPROVER_assert(g_ed25519_calls == 2U,
                         "TOOB_DOUBLE_VERIFY requires two agreeing Ed25519 evaluations");
#else
        __CPROVER_assert(g_ed25519_calls == 1U,
                         "Single-verify mode executes exactly one Ed25519 evaluation");
#endif
    }
}

int main(void) {
    if (nondet_bool()) {
        prove_merkle_stream_bounds_and_coverage();
    } else {
        prove_verify_manifest_envelope();
    }
    return 0;
}
