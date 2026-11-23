#include "hal_qual.h"
#include "boot_secure_zeroize.h"
#include <string.h>

#define QUAL_CANARY_WORDS  16U
#define QUAL_CANARY_MAGIC  0xA55AF00DU
#define QUAL_TIMING_ITERS  16U
#define QUAL_SHA_MAX_CTX   256U

static void record_check(hal_qual_report_t *rep, bool cond, const char *name) {
    rep->tests_run++;
    if (cond) {
        rep->tests_passed++;
    } else {
        rep->tests_failed++;
        if (rep->first_failure == NULL) {
            rep->first_failure = name;
        }
    }
}

static bool verify_sha256_kat(const boot_platform_t *plat, const uint8_t *msg, size_t len,
                              const uint8_t expected[32], size_t chunk_step) {
    struct {
        uint32_t head_canary[QUAL_CANARY_WORDS];
        uint8_t ctx[QUAL_SHA_MAX_CTX] __attribute__((aligned(8)));
        uint32_t tail_canary[QUAL_CANARY_WORDS];
    } guarded;

    for (uint32_t i = 0U; i < QUAL_CANARY_WORDS; i++) {
        guarded.head_canary[i] = QUAL_CANARY_MAGIC ^ i;
        guarded.tail_canary[i] = (QUAL_CANARY_MAGIC ^ 0xFFFFFFFFU) ^ i;
    }
    memset(guarded.ctx, 0, sizeof(guarded.ctx));

    size_t req_ctx = (plat->crypto->get_hash_ctx_size != NULL)
                         ? plat->crypto->get_hash_ctx_size()
                         : sizeof(guarded.ctx);
    if (req_ctx == 0U || req_ctx > sizeof(guarded.ctx)) {
        return false;
    }

    if (plat->crypto->hash_init(guarded.ctx, req_ctx) != BOOT_OK) {
        return false;
    }

    size_t off = 0U;
    while (off < len) {
        size_t step = (chunk_step == 0U || (len - off) < chunk_step) ? (len - off) : chunk_step;
        if (plat->crypto->hash_update(guarded.ctx, &msg[off], step) != BOOT_OK) {
            return false;
        }
        off += step;
    }

    uint8_t digest[32];
    size_t dlen = sizeof(digest);
    memset(digest, 0, sizeof(digest));
    if (plat->crypto->hash_finish(guarded.ctx, digest, &dlen) != BOOT_OK || dlen != 32U) {
        return false;
    }

    for (uint32_t i = 0U; i < QUAL_CANARY_WORDS; i++) {
        if (guarded.head_canary[i] != (QUAL_CANARY_MAGIC ^ i) ||
            guarded.tail_canary[i] != ((QUAL_CANARY_MAGIC ^ 0xFFFFFFFFU) ^ i)) {
            return false;
        }
    }

    bool ok = (memcmp(digest, expected, 32U) == 0);
    boot_secure_zeroize(&guarded, sizeof(guarded));
    boot_secure_zeroize(digest, sizeof(digest));
    return ok;
}

int hal_qual_crypto(const boot_platform_t *plat, hal_qual_report_t *rep) {
    if (plat == NULL || rep == NULL) {
        return HAL_QUAL_FAIL;
    }
    if (plat->crypto == NULL || plat->crypto->abi_version != TOOB_HAL_ABI_V3 ||
        plat->crypto->init == NULL || plat->crypto->deinit == NULL ||
        plat->crypto->hash_init == NULL || plat->crypto->hash_update == NULL ||
        plat->crypto->hash_finish == NULL || plat->crypto->verify_signature == NULL) {
        record_check(rep, false, "crypto_abi_and_pointers");
        return HAL_QUAL_FAIL;
    }

    record_check(rep, plat->crypto->init() == BOOT_OK, "crypto_init");

    /* RFC 8032 Section 7.1 Test Vector 1 (empty message) */
    static const uint8_t tv1_pk[32] = {
        0xd7U, 0x5aU, 0x98U, 0x01U, 0x82U, 0xb1U, 0x0aU, 0xb7U,
        0xd5U, 0x4bU, 0xfeU, 0xd3U, 0xc9U, 0x64U, 0x07U, 0x3aU,
        0x0eU, 0xe1U, 0x72U, 0xf3U, 0xdaU, 0xa6U, 0x23U, 0x25U,
        0xafU, 0x02U, 0x1aU, 0x68U, 0xf7U, 0x07U, 0x51U, 0x1aU
    };
    static const uint8_t tv1_sig[64] = {
        0xe5U, 0x56U, 0x43U, 0x00U, 0xc3U, 0x60U, 0xacU, 0x72U,
        0x90U, 0x86U, 0xe2U, 0xccU, 0x80U, 0x6eU, 0x82U, 0x8aU,
        0x84U, 0x87U, 0x7fU, 0x1eU, 0xb8U, 0xe5U, 0xd9U, 0x74U,
        0xd8U, 0x73U, 0xe0U, 0x65U, 0x22U, 0x49U, 0x01U, 0x55U,
        0x5fU, 0xb8U, 0x82U, 0x15U, 0x90U, 0xa3U, 0x3bU, 0xacU,
        0xc6U, 0x1eU, 0x39U, 0x70U, 0x1cU, 0xf9U, 0xb4U, 0x6bU,
        0xd2U, 0x5bU, 0xf5U, 0xf0U, 0x59U, 0x5bU, 0xbeU, 0x24U,
        0x65U, 0x51U, 0x41U, 0x43U, 0x8eU, 0x7aU, 0x10U, 0x0bU
    };
    static const uint8_t empty_msg[1] = { 0x00U };
    record_check(rep, plat->crypto->verify_signature(empty_msg, 0U, tv1_sig, tv1_pk) == BOOT_OK,
                 "ed25519_rfc8032_tv1");

    /* RFC 8032 Section 7.1 Test Vector 2 (1-byte message 0x72) */
    static const uint8_t tv2_pk[32] = {
        0x3dU, 0x40U, 0x17U, 0xc3U, 0xe8U, 0x43U, 0x89U, 0x5aU,
        0x92U, 0xb7U, 0x0aU, 0xa7U, 0x4dU, 0x1bU, 0x7eU, 0xbcU,
        0x9cU, 0x98U, 0x2cU, 0xcfU, 0x2eU, 0xc4U, 0x96U, 0x8cU,
        0xc0U, 0xcdU, 0x55U, 0xf1U, 0x2aU, 0xf4U, 0x66U, 0x0cU
    };
    static const uint8_t tv2_msg[1] = { 0x72U };
    static const uint8_t tv2_sig[64] = {
        0x92U, 0xa0U, 0x09U, 0xa9U, 0xf0U, 0xd4U, 0xcaU, 0xb8U,
        0x72U, 0x0eU, 0x82U, 0x0bU, 0x5fU, 0x64U, 0x25U, 0x40U,
        0xa2U, 0xb2U, 0x7bU, 0x54U, 0x16U, 0x50U, 0x3fU, 0x8fU,
        0xb3U, 0x76U, 0x22U, 0x23U, 0xebU, 0xdbU, 0x69U, 0xdaU,
        0x08U, 0x5aU, 0xc1U, 0xe4U, 0x3eU, 0x15U, 0x99U, 0x6eU,
        0x45U, 0x8fU, 0x36U, 0x13U, 0xd0U, 0xf1U, 0x1dU, 0x8cU,
        0x38U, 0x7bU, 0x2eU, 0xaeU, 0xb4U, 0x30U, 0x2aU, 0xeeU,
        0xb0U, 0x0dU, 0x29U, 0x16U, 0x12U, 0xbbU, 0x0cU, 0x00U
    };
    record_check(rep,
                 plat->crypto->verify_signature(tv2_msg, sizeof(tv2_msg), tv2_sig, tv2_pk) == BOOT_OK,
                 "ed25519_rfc8032_tv2");

    /* RFC 8032 Section 7.1 Test Vector 3 (2-byte message 0xaf 0x82) */
    static const uint8_t tv3_pk[32] = {
        0xfcU, 0x51U, 0xcdU, 0x8eU, 0x62U, 0x18U, 0xa1U, 0xa3U,
        0x8dU, 0xa4U, 0x7eU, 0xd0U, 0x02U, 0x30U, 0xf0U, 0x58U,
        0x08U, 0x16U, 0xedU, 0x13U, 0xbaU, 0x33U, 0x03U, 0xacU,
        0x5dU, 0xebU, 0x91U, 0x15U, 0x48U, 0x90U, 0x80U, 0x25U
    };
    static const uint8_t tv3_msg[2] = { 0xafU, 0x82U };
    static const uint8_t tv3_sig[64] = {
        0x62U, 0x91U, 0xd6U, 0x57U, 0xdeU, 0xecU, 0x24U, 0x02U,
        0x48U, 0x27U, 0xe6U, 0x9cU, 0x3aU, 0xbeU, 0x01U, 0xa3U,
        0x0cU, 0xe5U, 0x48U, 0xa2U, 0x84U, 0x74U, 0x3aU, 0x44U,
        0x5eU, 0x36U, 0x80U, 0xd7U, 0xdbU, 0x5aU, 0xc3U, 0xacU,
        0x18U, 0xffU, 0x9bU, 0x53U, 0x8dU, 0x16U, 0xf2U, 0x90U,
        0xaeU, 0x67U, 0xf7U, 0x60U, 0x98U, 0x4dU, 0xc6U, 0x59U,
        0x4aU, 0x7cU, 0x15U, 0xe9U, 0x71U, 0x6eU, 0xd2U, 0x8dU,
        0xc0U, 0x27U, 0xbeU, 0xceU, 0xeaU, 0x1eU, 0xc4U, 0x0aU
    };
    record_check(rep,
                 plat->crypto->verify_signature(tv3_msg, sizeof(tv3_msg), tv3_sig, tv3_pk) == BOOT_OK,
                 "ed25519_rfc8032_tv3");

    /* 1-bit flip negative tests on msg, pk, sig(R), sig(S) */
    uint8_t bad_msg[2];
    uint8_t bad_pk[32];
    uint8_t bad_sig[64];

    memcpy(bad_msg, tv3_msg, sizeof(bad_msg));
    bad_msg[0] ^= 0x01U;
    record_check(rep,
                 plat->crypto->verify_signature(bad_msg, sizeof(bad_msg), tv3_sig, tv3_pk) != BOOT_OK,
                 "ed25519_neg_flip_msg");

    memcpy(bad_pk, tv3_pk, sizeof(bad_pk));
    bad_pk[15] ^= 0x80U;
    record_check(rep,
                 plat->crypto->verify_signature(tv3_msg, sizeof(tv3_msg), tv3_sig, bad_pk) != BOOT_OK,
                 "ed25519_neg_flip_pk");

    memcpy(bad_sig, tv3_sig, sizeof(bad_sig));
    bad_sig[0] ^= 0x01U;
    record_check(rep,
                 plat->crypto->verify_signature(tv3_msg, sizeof(tv3_msg), bad_sig, tv3_pk) != BOOT_OK,
                 "ed25519_neg_flip_sig_r");

    memcpy(bad_sig, tv3_sig, sizeof(bad_sig));
    bad_sig[63] ^= 0x01U;
    record_check(rep,
                 plat->crypto->verify_signature(tv3_msg, sizeof(tv3_msg), bad_sig, tv3_pk) != BOOT_OK,
                 "ed25519_neg_flip_sig_s");

    record_check(rep, plat->crypto->verify_signature(NULL, 1U, tv3_sig, tv3_pk) != BOOT_OK,
                 "ed25519_neg_null_msg");
    record_check(rep, plat->crypto->verify_signature(tv3_msg, sizeof(tv3_msg), NULL, tv3_pk) != BOOT_OK,
                 "ed25519_neg_null_sig");
    record_check(rep, plat->crypto->verify_signature(tv3_msg, sizeof(tv3_msg), tv3_sig, NULL) != BOOT_OK,
                 "ed25519_neg_null_pk");

    /* FIPS 180-4 SHA-256 KATs + arena canary guards */
    static const uint8_t sha_empty_exp[32] = {
        0xe3U, 0xb0U, 0xc4U, 0x42U, 0x98U, 0xfcU, 0x1cU, 0x14U,
        0x9aU, 0xfbU, 0xf4U, 0xc8U, 0x99U, 0x6fU, 0xb9U, 0x24U,
        0x27U, 0xaeU, 0x41U, 0xe4U, 0x64U, 0x9bU, 0x93U, 0x4cU,
        0xa4U, 0x95U, 0x99U, 0x1bU, 0x78U, 0x52U, 0xb8U, 0x55U
    };
    static const uint8_t sha_abc_msg[3] = { 'a', 'b', 'c' };
    static const uint8_t sha_abc_exp[32] = {
        0xbaU, 0x78U, 0x16U, 0xbfU, 0x8fU, 0x01U, 0xcfU, 0xeaU,
        0x41U, 0x41U, 0x40U, 0xdeU, 0x5dU, 0xaeU, 0x22U, 0x23U,
        0xb0U, 0x03U, 0x61U, 0xa3U, 0x96U, 0x17U, 0x7aU, 0x9cU,
        0xb4U, 0x10U, 0xffU, 0x61U, 0xf2U, 0x00U, 0x15U, 0xadU
    };
    static const char sha_mb_str[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const uint8_t sha_mb_exp[32] = {
        0x24U, 0x8dU, 0x6aU, 0x61U, 0xd2U, 0x06U, 0x38U, 0xb8U,
        0xe5U, 0xc0U, 0x26U, 0x93U, 0x0cU, 0x3eU, 0x60U, 0x39U,
        0xa3U, 0x3cU, 0xe4U, 0x59U, 0x64U, 0xffU, 0x21U, 0x67U,
        0xf6U, 0xecU, 0xedU, 0xd4U, 0x19U, 0xdbU, 0x06U, 0xc1U
    };

    record_check(rep, verify_sha256_kat(plat, empty_msg, 0U, sha_empty_exp, 0U),
                 "sha256_kat_empty_canary");
    record_check(rep, verify_sha256_kat(plat, sha_abc_msg, sizeof(sha_abc_msg), sha_abc_exp, 0U),
                 "sha256_kat_abc_canary");
    record_check(rep,
                 verify_sha256_kat(plat, (const uint8_t *)sha_mb_str, sizeof(sha_mb_str) - 1U,
                                   sha_mb_exp, 0U),
                 "sha256_kat_multiblock_canary");
    record_check(rep,
                 verify_sha256_kat(plat, (const uint8_t *)sha_mb_str, sizeof(sha_mb_str) - 1U,
                                   sha_mb_exp, 7U),
                 "sha256_kat_chunked_7b_canary");

    /* Repeated timing and determinism sanity check */
    uint32_t t0 = (plat->clock != NULL && plat->clock->get_tick_ms != NULL)
                      ? plat->clock->get_tick_ms()
                      : 0U;
    bool repeat_ok = true;
    for (uint32_t it = 0U; it < QUAL_TIMING_ITERS; it++) {
        if (plat->crypto->verify_signature(tv2_msg, sizeof(tv2_msg), tv2_sig, tv2_pk) != BOOT_OK) {
            repeat_ok = false;
        }
        if (plat->crypto->verify_signature(bad_msg, sizeof(bad_msg), tv3_sig, tv3_pk) == BOOT_OK) {
            repeat_ok = false;
        }
    }
    uint32_t t1 = (plat->clock != NULL && plat->clock->get_tick_ms != NULL)
                      ? plat->clock->get_tick_ms()
                      : 0U;
    uint32_t elapsed = (t1 >= t0) ? (t1 - t0) : ((UINT32_MAX - t0) + 1U + t1);
    record_check(rep, repeat_ok && elapsed < 30000U, "crypto_repeated_timing_sanity");

    plat->crypto->deinit();
    return (rep->tests_failed == 0U) ? HAL_QUAL_OK : HAL_QUAL_FAIL;
}
