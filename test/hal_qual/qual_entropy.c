#include "hal_qual.h"
#include "boot_ct_utils.h"
#include "boot_secure_zeroize.h"
#include <string.h>

#define QUAL_ENTROPY_TOTAL_BYTES  1024U
#define QUAL_ENTROPY_CHUNK_BYTES  64U
#define QUAL_RCT_CUTOFF           6U
#define QUAL_APT_WINDOW           512U
#define QUAL_APT_CUTOFF           40U

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

static bool sp800_90b_rct_pass(const uint8_t *buf, size_t len, uint32_t cutoff) {
    if (buf == NULL || len == 0U || cutoff < 2U) {
        return false;
    }
    uint8_t prev = buf[0];
    uint32_t run = 1U;
    for (size_t i = 1U; i < len; i++) {
        if (buf[i] == prev) {
            run++;
            if (run >= cutoff) {
                return false;
            }
        } else {
            prev = buf[i];
            run = 1U;
        }
    }
    return true;
}

static bool sp800_90b_apt_pass(const uint8_t *buf, size_t len, size_t window, uint32_t cutoff) {
    if (buf == NULL || len < window || window == 0U) {
        return false;
    }
    for (size_t start = 0U; start + window <= len; start += window) {
        uint16_t counts[256];
        memset(counts, 0, sizeof(counts));
        for (size_t i = 0U; i < window; i++) {
            uint8_t v = buf[start + i];
            counts[v]++;
            if ((uint32_t)counts[v] > cutoff) {
                return false;
            }
        }
    }
    return true;
}

static bool entropy_non_degenerate(const uint8_t *buf, size_t len) {
    if (buf == NULL || len < 8U) {
        return false;
    }
    uint8_t or_acc = 0x00U;
    uint8_t and_acc = 0xFFU;
    uint8_t first = buf[0];
    bool all_same = true;
    uint8_t stride = (uint8_t)(buf[1] - buf[0]);
    bool const_stride = true;

    for (size_t i = 0U; i < len; i++) {
        or_acc |= buf[i];
        and_acc &= buf[i];
        if (buf[i] != first) {
            all_same = false;
        }
        if (i > 0U && (uint8_t)(buf[i] - buf[i - 1U]) != stride) {
            const_stride = false;
        }
    }
    return (or_acc != 0x00U) && (and_acc != 0xFFU) && !all_same && !const_stride;
}

/* Synthetic broken TRNG callbacks to verify boot_random_safe fail-closed rejection. */
static uint8_t s_bad_mode = 0U;

static boot_status_t bad_trng_init(void) {
    return BOOT_OK;
}

static void bad_trng_deinit(void) {
}

static boot_status_t bad_trng_random(uint8_t *buf, size_t len) {
    if (buf == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (s_bad_mode == 0U) {
        memset(buf, 0x00, len);
        return BOOT_OK;
    }
    if (s_bad_mode == 1U) {
        memset(buf, 0xFF, len);
        return BOOT_OK;
    }
    if (s_bad_mode == 2U) {
        for (size_t i = 0U; i < len; i++) {
            buf[i] = (uint8_t)(0x10U + (uint8_t)(i * 3U));
        }
        return BOOT_OK;
    }
    if (s_bad_mode == 3U) {
        for (size_t i = 0U; i < len; i++) {
            buf[i] = (i < 8U) ? 0x5AU : (uint8_t)(i * 17U + 1U);
        }
        return BOOT_OK;
    }
    return BOOT_ERR_TIMEOUT;
}

int hal_qual_entropy(const boot_platform_t *plat, hal_qual_report_t *rep) {
    if (plat == NULL || rep == NULL) {
        return HAL_QUAL_FAIL;
    }
    if (plat->entropy == NULL || plat->entropy->abi_version != TOOB_HAL_ABI_V3 ||
        plat->entropy->random == NULL) {
        record_check(rep, false, "entropy_abi_and_pointers");
        return HAL_QUAL_FAIL;
    }

    if (plat->entropy->init != NULL) {
        record_check(rep, plat->entropy->init() == BOOT_OK, "entropy_init");
    }

    /* Argument validation (fail-closed on NULL) */
    record_check(rep, plat->entropy->random(NULL, 16U) != BOOT_OK, "entropy_neg_null_buf");

    uint8_t sample_pool[QUAL_ENTROPY_TOTAL_BYTES];
    memset(sample_pool, 0, sizeof(sample_pool));
    bool draws_ok = true;
    for (size_t off = 0U; off < sizeof(sample_pool); off += QUAL_ENTROPY_CHUNK_BYTES) {
        if (plat->entropy->random(&sample_pool[off], QUAL_ENTROPY_CHUNK_BYTES) != BOOT_OK) {
            draws_ok = false;
            break;
        }
    }
    record_check(rep, draws_ok, "entropy_draw_1024");
    record_check(rep, draws_ok && entropy_non_degenerate(sample_pool, sizeof(sample_pool)),
                 "entropy_non_degenerate");
    record_check(rep, draws_ok && sp800_90b_rct_pass(sample_pool, sizeof(sample_pool), QUAL_RCT_CUTOFF),
                 "entropy_sp800_90b_rct");
    record_check(rep,
                 draws_ok && sp800_90b_apt_pass(sample_pool, sizeof(sample_pool), QUAL_APT_WINDOW,
                                                QUAL_APT_CUTOFF),
                 "entropy_sp800_90b_apt");

    /* Successive draws must not repeat identically */
    uint8_t draw_a[32];
    uint8_t draw_b[32];
    bool pair_ok = (plat->entropy->random(draw_a, sizeof(draw_a)) == BOOT_OK) &&
                   (plat->entropy->random(draw_b, sizeof(draw_b)) == BOOT_OK) &&
                   (memcmp(draw_a, draw_b, sizeof(draw_a)) != 0);
    record_check(rep, pair_ok, "entropy_distinct_draws");

    /* Verify boot_random_safe() succeeds on healthy platform and fails closed on faulty TRNGs */
    uint8_t safe_buf[32];
    record_check(rep, boot_random_safe(plat, safe_buf, sizeof(safe_buf)) == BOOT_OK,
                 "boot_random_safe_ok");

    const entropy_hal_t bad_entropy = TOOB_ENTROPY_HAL_V3(
        bad_trng_init, bad_trng_deinit, bad_trng_random, .is_hardware_trng = true);
    boot_platform_t bad_plat = *plat;
    bad_plat.entropy = &bad_entropy;

    for (uint8_t mode = 0U; mode <= 4U; mode++) {
        s_bad_mode = mode;
        memset(safe_buf, 0xAA, sizeof(safe_buf));
        boot_status_t st = boot_random_safe(&bad_plat, safe_buf, sizeof(safe_buf));
        bool wiped = true;
        for (size_t i = 0U; i < sizeof(safe_buf); i++) {
            if (safe_buf[i] != 0U) {
                wiped = false;
            }
        }
        record_check(rep, (st != BOOT_OK) && wiped, "boot_random_safe_rejects_faulty_trng");
    }

    boot_secure_zeroize(sample_pool, sizeof(sample_pool));
    boot_secure_zeroize(draw_a, sizeof(draw_a));
    boot_secure_zeroize(draw_b, sizeof(draw_b));
    boot_secure_zeroize(safe_buf, sizeof(safe_buf));

    if (plat->entropy->deinit != NULL) {
        plat->entropy->deinit();
    }
    return (rep->tests_failed == 0U) ? HAL_QUAL_OK : HAL_QUAL_FAIL;
}
