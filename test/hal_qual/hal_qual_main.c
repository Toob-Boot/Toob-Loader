#include "hal_qual.h"
#include "boot_secure_zeroize.h"
#include "crypto_monocypher.h"
#include "crypto_sha256.h"
#include "generated_boot_config.h"

#include <stdio.h>
#include <string.h>

int toob_hal_qualify_with_report(const boot_platform_t *plat, hal_qual_report_t *report) {
    if (plat == NULL || report == NULL) {
        return HAL_QUAL_FAIL;
    }

    int rc_crypto = hal_qual_crypto(plat, report);
    int rc_entropy = hal_qual_entropy(plat, report);
    int rc_flash = hal_qual_flash(plat, report);
    int rc_ks = hal_qual_keystore_soc(plat, report);

    if (rc_crypto != HAL_QUAL_OK || rc_entropy != HAL_QUAL_OK ||
        rc_flash != HAL_QUAL_OK || rc_ks != HAL_QUAL_OK ||
        report->tests_failed != 0U) {
        return HAL_QUAL_FAIL;
    }
    return HAL_QUAL_OK;
}

int toob_hal_qualify(const boot_platform_t *plat) {
    hal_qual_report_t rep;
    memset(&rep, 0, sizeof(rep));
#ifdef CHIP_SCRATCH_SLOT_ABS_ADDR
    rep.scratch_flash_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
#endif
    return toob_hal_qualify_with_report(plat, &rep);
}

#ifndef TOOB_HAL_QUAL_LIBRARY_ONLY

/* ============================================================================
 * Built-in Host Reference HAL (for positive & negative selftest verification)
 * ============================================================================ */

static uint8_t s_ref_flash[CHIP_FLASH_TOTAL_SIZE];
static uint32_t s_ref_tick_ms = 100U;
static uint64_t s_ref_rng = 0xD1B54A32D192ED03ULL;
static uint32_t s_ref_mono = 0U;
static uint32_t s_ref_lockdown_count = 0U;
static bool s_ref_otp_hole_fault = false;
static bool s_ref_huk_nondet_fault = false;
static uint32_t s_ref_huk_calls = 0U;

static boot_status_t ref_flash_init(void) {
    return BOOT_OK;
}

static void ref_flash_deinit(void) {
}

static boot_status_t ref_flash_read(uint32_t addr, void *buf, size_t len) {
    if (buf == NULL && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (addr > (uint32_t)sizeof(s_ref_flash) || len > (size_t)sizeof(s_ref_flash) - (size_t)addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if (len > 0U) {
        memcpy(buf, &s_ref_flash[addr], len);
    }
    return BOOT_OK;
}

static boot_status_t ref_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (buf == NULL && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (len == 0U) {
        return BOOT_OK;
    }
    if (addr > (uint32_t)sizeof(s_ref_flash) || len > (size_t)sizeof(s_ref_flash) - (size_t)addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U || (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    const uint8_t *src = (const uint8_t *)buf;
    for (size_t i = 0U; i < len; i++) {
        if ((~s_ref_flash[addr + i] & src[i]) != 0U) {
            return BOOT_ERR_FLASH_HW;
        }
    }
    for (size_t i = 0U; i < len; i++) {
        s_ref_flash[addr + i] &= src[i];
    }
    return BOOT_OK;
}

static boot_status_t ref_flash_erase_sector(uint32_t addr) {
    if (addr >= (uint32_t)sizeof(s_ref_flash) ||
        (uint32_t)CHIP_FLASH_MAX_SECTOR_SIZE > (uint32_t)sizeof(s_ref_flash) - addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if ((addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    memset(&s_ref_flash[addr], CHIP_FLASH_ERASED_BYTE, CHIP_FLASH_MAX_SECTOR_SIZE);
    return BOOT_OK;
}

static boot_status_t ref_flash_get_sector_size(uint32_t addr, size_t *out_sz) {
    if (out_sz == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (addr >= (uint32_t)sizeof(s_ref_flash)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    *out_sz = CHIP_FLASH_MAX_SECTOR_SIZE;
    return BOOT_OK;
}

static boot_status_t ref_entropy_init(void) {
    return BOOT_OK;
}

static void ref_entropy_deinit(void) {
}

static uint64_t ref_splitmix64(void) {
    s_ref_rng += 0x9E3779B97F4A7C15ULL;
    uint64_t z = s_ref_rng;
    z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31U);
}

static boot_status_t ref_entropy_random(uint8_t *buf, size_t len) {
    if (buf == NULL && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < len; i++) {
        buf[i] = (uint8_t)(ref_splitmix64() >> ((i & 7U) * 8U));
    }
    if (len >= 2U && buf[0] == buf[1]) {
        buf[1] ^= 0x3CU;
    }
    return BOOT_OK;
}

static boot_status_t ref_ks_init(void) {
    return BOOT_OK;
}

static void ref_ks_deinit(void) {
}

static boot_status_t ref_ks_read_pubkey(uint8_t *key, size_t key_len, uint8_t key_index) {
    static const uint8_t pk0[32] = {
        0xd7U, 0x5aU, 0x98U, 0x01U, 0x82U, 0xb1U, 0x0aU, 0xb7U,
        0xd5U, 0x4bU, 0xfeU, 0xd3U, 0xc9U, 0x64U, 0x07U, 0x3aU,
        0x0eU, 0xe1U, 0x72U, 0xf3U, 0xdaU, 0xa6U, 0x23U, 0x25U,
        0xafU, 0x02U, 0x1aU, 0x68U, 0xf7U, 0x07U, 0x51U, 0x1aU
    };
    static const uint8_t pk1[32] = {
        0x3dU, 0x40U, 0x17U, 0xc3U, 0xe8U, 0x43U, 0x89U, 0x5aU,
        0x92U, 0xb7U, 0x0aU, 0xa7U, 0x4dU, 0x1bU, 0x7eU, 0xbcU,
        0x9cU, 0x98U, 0x2cU, 0xcfU, 0x2eU, 0xc4U, 0x96U, 0x8cU,
        0xc0U, 0xcdU, 0x55U, 0xf1U, 0x2aU, 0xf4U, 0x66U, 0x0cU
    };
    if (key == NULL || key_len != 32U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (key_index == 0U) {
        memcpy(key, pk0, 32U);
        return BOOT_OK;
    }
    if (key_index == 1U && !s_ref_otp_hole_fault) {
        memcpy(key, pk1, 32U);
        return BOOT_OK;
    }
    if (key_index == 2U && s_ref_otp_hole_fault) {
        memcpy(key, pk1, 32U);
        return BOOT_OK;
    }
    return BOOT_ERR_NOT_FOUND;
}

static boot_status_t ref_ks_read_uid(uint8_t *buf, size_t max_len, size_t *out_len) {
    static const uint8_t uid[8] = { 0x52U, 0x84U, 0x00U, 0x01U, 0xDEU, 0xADU, 0xBEU, 0xEFU };
    if (buf == NULL || out_len == NULL || max_len < sizeof(uid)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(buf, uid, sizeof(uid));
    *out_len = sizeof(uid);
    return BOOT_OK;
}

static boot_status_t ref_ks_read_dslc(uint8_t *buf, size_t *len) {
    if (buf == NULL || len == NULL || *len == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    buf[0] = 0x01U;
    *len = 1U;
    return BOOT_OK;
}

static boot_status_t ref_ks_write_dslc(const uint8_t *val, size_t len) {
    if (val == NULL || len == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    return BOOT_OK;
}

static boot_status_t ref_ks_read_mono(uint32_t *ctr) {
    if (ctr == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    *ctr = s_ref_mono;
    return BOOT_OK;
}

static boot_status_t ref_ks_adv_mono(void) {
    s_ref_mono++;
    return BOOT_OK;
}

static boot_status_t ref_ks_read_secret(uint8_t *buf, size_t max_len, size_t *out_len) {
    if (buf == NULL || out_len == NULL || max_len < 32U) {
        return BOOT_ERR_INVALID_ARG;
    }
    s_ref_huk_calls++;
    for (size_t i = 0U; i < 32U; i++) {
        buf[i] = (uint8_t)(0x42U ^ (uint8_t)(i * 7U));
    }
    if (s_ref_huk_nondet_fault) {
        buf[0] ^= (uint8_t)s_ref_huk_calls;
    }
    *out_len = 32U;
    return BOOT_OK;
}

static boot_status_t ref_ks_read_pqc_hash(uint8_t out_hash[32], uint8_t key_index) {
    if (out_hash == NULL || key_index > 1U) {
        return BOOT_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < 32U; i++) {
        out_hash[i] = (uint8_t)(0x91U ^ (uint8_t)i ^ key_index);
    }
    return BOOT_OK;
}

static boot_status_t ref_clock_init(void) {
    return BOOT_OK;
}

static void ref_clock_deinit(void) {
}

static uint32_t ref_clock_tick(void) {
    s_ref_tick_ms += 5U;
    return s_ref_tick_ms;
}

static void ref_clock_delay(uint32_t ms) {
    s_ref_tick_ms += ms;
}

static reset_reason_t ref_clock_reset_reason(void) {
    return RESET_REASON_POWER_ON;
}

static boot_status_t ref_wdt_init(uint32_t timeout_ms) {
    (void)timeout_ms;
    return BOOT_OK;
}

static void ref_wdt_deinit(void) {
}

static void ref_wdt_kick(void) {
}

static void ref_wdt_suspend(void) {
}

static void ref_wdt_resume(void) {
}

static boot_status_t ref_soc_init(void) {
    return BOOT_OK;
}

static void ref_soc_deinit(void) {
}

static boot_status_t ref_soc_lockdown(void) {
    s_ref_lockdown_count++;
    return BOOT_OK;
}

/* Negative HAL fault stubs */
static boot_status_t broken_crypto_accept_all(const uint8_t *m, size_t ml,
                                              const uint8_t *s, const uint8_t *p) {
    (void)m;
    (void)ml;
    (void)s;
    (void)p;
    return BOOT_OK;
}

static boot_status_t broken_entropy_zeros(uint8_t *buf, size_t len) {
    if (buf == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    memset(buf, 0x00, len);
    return BOOT_OK;
}

static boot_status_t broken_flash_allows_wrap(uint32_t addr, const void *buf, size_t len) {
    (void)addr;
    (void)buf;
    (void)len;
    return BOOT_OK;
}

int main(void) {
    memset(s_ref_flash, CHIP_FLASH_ERASED_BYTE, sizeof(s_ref_flash));

    const flash_hal_t ref_flash = TOOB_FLASH_HAL_V2(
        ref_flash_init, ref_flash_deinit, ref_flash_read, ref_flash_write,
        ref_flash_erase_sector, ref_flash_get_sector_size,
        .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size = CHIP_FLASH_TOTAL_SIZE,
        .max_erase_cycles = 100000U,
        .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
        .erased_value = CHIP_FLASH_ERASED_BYTE
    );
    const crypto_hal_t ref_crypto = TOOB_CRYPTO_HAL_V3(
        crypto_monocypher_init, crypto_monocypher_deinit,
        crypto_sha256_init, crypto_sha256_update, crypto_sha256_finish,
        crypto_monocypher_verify_signature, crypto_sha256_get_ctx_size,
        .verify_signature_ph = crypto_monocypher_verify_signature_ph
    );
    const entropy_hal_t ref_entropy = TOOB_ENTROPY_HAL_V3(
        ref_entropy_init, ref_entropy_deinit, ref_entropy_random,
        .is_hardware_trng = true
    );
    const keystore_hal_t ref_keystore = TOOB_KEYSTORE_HAL_V3(
        ref_ks_init, ref_ks_deinit, ref_ks_read_pubkey, ref_ks_read_dslc, ref_ks_write_dslc,
        .read_chip_uid = ref_ks_read_uid,
        .read_monotonic_counter = ref_ks_read_mono,
        .advance_monotonic_counter = ref_ks_adv_mono,
        .read_device_secret = ref_ks_read_secret,
        .read_pqc_pubkey_hash = ref_ks_read_pqc_hash
    );
    const clock_hal_t ref_clock = TOOB_CLOCK_HAL_V2(
        ref_clock_init, ref_clock_deinit, ref_clock_tick, ref_clock_delay, ref_clock_reset_reason
    );
    const wdt_hal_t ref_wdt = TOOB_WDT_HAL_V2(
        ref_wdt_init, ref_wdt_deinit, ref_wdt_kick, ref_wdt_suspend, ref_wdt_resume
    );
    const soc_hal_t ref_soc = TOOB_SOC_HAL_V2(
        ref_soc_init, ref_soc_deinit,
        .lockdown_before_handoff = ref_soc_lockdown
    );

    const boot_platform_t ref_plat = {
        .flash = &ref_flash,
        .crypto = &ref_crypto,
        .clock = &ref_clock,
        .wdt = &ref_wdt,
        .soc = &ref_soc,
        .entropy = &ref_entropy,
        .keystore = &ref_keystore
    };

    /* 1. Public API positive qualification */
    if (toob_hal_qualify(&ref_plat) != HAL_QUAL_OK) {
        fprintf(stderr, "FAIL: toob_hal_qualify(&ref_plat) failed\n");
        return 1;
    }

    /* 2. Full report with monotonic OTP counter advance verification */
    hal_qual_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.scratch_flash_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
    rep.flags = HAL_QUAL_FLAG_TEST_OTP_ADVANCE;
    if (toob_hal_qualify_with_report(&ref_plat, &rep) != HAL_QUAL_OK || s_ref_mono != 1U ||
        s_ref_lockdown_count < 4U) {
        fprintf(stderr, "FAIL: full report failed at '%s' (failed=%u)\n",
                rep.first_failure ? rep.first_failure : "none", (unsigned)rep.tests_failed);
        return 1;
    }

    /* 3. Negative checks: verify broken HAL implementations are strictly rejected! */
    uint32_t neg_caught = 0U;

    /* 3a. Forged-signature accepting crypto HAL */
    crypto_hal_t bad_crypto = ref_crypto;
    bad_crypto.verify_signature = broken_crypto_accept_all;
    boot_platform_t bad_plat = ref_plat;
    bad_plat.crypto = &bad_crypto;
    hal_qual_report_t neg_rep;
    memset(&neg_rep, 0, sizeof(neg_rep));
    if (hal_qual_crypto(&bad_plat, &neg_rep) == HAL_QUAL_OK) {
        fprintf(stderr, "FAIL: hal_qual_crypto accepted broken accept-all verify\n");
        return 1;
    }
    neg_caught++;

    /* 3b. Stuck-zero entropy HAL */
    entropy_hal_t bad_entropy = ref_entropy;
    bad_entropy.random = broken_entropy_zeros;
    bad_plat = ref_plat;
    bad_plat.entropy = &bad_entropy;
    memset(&neg_rep, 0, sizeof(neg_rep));
    if (hal_qual_entropy(&bad_plat, &neg_rep) == HAL_QUAL_OK) {
        fprintf(stderr, "FAIL: hal_qual_entropy accepted stuck-zero TRNG\n");
        return 1;
    }
    neg_caught++;

    /* 3c. Wraparound-vulnerable flash HAL */
    flash_hal_t bad_flash = ref_flash;
    bad_flash.write = broken_flash_allows_wrap;
    bad_plat = ref_plat;
    bad_plat.flash = &bad_flash;
    memset(&neg_rep, 0, sizeof(neg_rep));
    neg_rep.scratch_flash_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
    if (hal_qual_flash(&bad_plat, &neg_rep) == HAL_QUAL_OK) {
        fprintf(stderr, "FAIL: hal_qual_flash accepted wraparound-unsafe flash\n");
        return 1;
    }
    neg_caught++;

    /* 3d. OTP blank-hole keystore HAL */
    s_ref_otp_hole_fault = true;
    memset(&neg_rep, 0, sizeof(neg_rep));
    if (hal_qual_keystore_soc(&ref_plat, &neg_rep) == HAL_QUAL_OK) {
        fprintf(stderr, "FAIL: hal_qual_keystore_soc accepted non-contiguous OTP hole\n");
        return 1;
    }
    s_ref_otp_hole_fault = false;
    neg_caught++;

    /* 3e. Non-deterministic HUK */
    s_ref_huk_nondet_fault = true;
    memset(&neg_rep, 0, sizeof(neg_rep));
    if (hal_qual_keystore_soc(&ref_plat, &neg_rep) == HAL_QUAL_OK) {
        fprintf(stderr, "FAIL: hal_qual_keystore_soc accepted non-deterministic HUK\n");
        return 1;
    }
    s_ref_huk_nondet_fault = false;
    neg_caught++;

    printf("HAL_QUAL_SUMMARY positive_passed=%u/%u negative_fault_hals_caught=%u status=PASS\n",
           (unsigned)rep.tests_passed, (unsigned)rep.tests_run, (unsigned)neg_caught);
    return 0;
}

#endif /* !TOOB_HAL_QUAL_LIBRARY_ONLY */
