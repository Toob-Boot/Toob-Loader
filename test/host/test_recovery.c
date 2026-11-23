/**
 * @file test_recovery.c
 * @brief Integration Test: Roach-Motel Recovery exhaustion & counter retention verification.
 */

#include "generated_boot_config.h"
#include "flash_model.h"
#include "boot_slot_caps.h"
#include "boot_state.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include "crypto_monocypher.h"
#include "crypto_sha256.h"
#include "monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#define __USE_MINGW_SETJMP_NON_SEH
#endif
#include <setjmp.h>

#define SIM_FLASH_FILE "builds/sim_recovery_flash.bin"

static uint8_t g_arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));
static const uint32_t dummy_key[4] = {0x11111111U, 0x22222222U, 0x33333333U, 0x44444444U};
static uint8_t s_test_dslc = 0x00U;
static uint32_t s_tick_ms = 100U;
static jmp_buf s_panic_jmp;
static bool s_expect_panic = false;
static boot_status_t s_last_panic = BOOT_OK;

_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason,
                                  uint16_t site_id) {
    (void)platform;
    (void)site_id;
    s_last_panic = reason;
    if (s_expect_panic) {
        longjmp(s_panic_jmp, 1);
    }
    fprintf(stderr, "Unexpected boot_terminal_halt(0x%08X)\n", (unsigned)reason);
    abort();
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    boot_terminal_halt(platform, reason, 0U);
}

static boot_status_t test_clock_init(void) { return BOOT_OK; }
static void test_clock_deinit(void) {}
static uint32_t test_get_tick_ms(void) { return s_tick_ms++; }
static void test_delay_ms(uint32_t ms) { s_tick_ms += ms; }
static reset_reason_t test_get_reset_reason(void) { return RESET_REASON_POWER_ON; }

static const clock_hal_t s_test_clock_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = test_clock_init,
    .deinit = test_clock_deinit,
    .get_tick_ms = test_get_tick_ms,
    .delay_ms = test_delay_ms,
    .get_reset_reason = test_get_reset_reason,
};

static boot_status_t test_wdt_init(uint32_t timeout_ms) { (void)timeout_ms; return BOOT_OK; }
static void test_wdt_deinit(void) {}
static void test_wdt_kick(void) {}

static const wdt_hal_t s_test_wdt_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = test_wdt_init,
    .deinit = test_wdt_deinit,
    .kick = test_wdt_kick,
};

static boot_status_t test_confirm_init(void) { return BOOT_OK; }
static void test_confirm_deinit(void) {}
static bool test_confirm_check(uint64_t expected_nonce) {
    (void)expected_nonce;
    return false;
}

static const confirm_hal_t s_test_confirm_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = test_confirm_init,
    .deinit = test_confirm_deinit,
    .check_ok = test_confirm_check,
};

static boot_status_t test_crypto_init(void) { return BOOT_OK; }
static void test_crypto_deinit(void) {}

static const crypto_hal_t s_test_crypto_hal = TOOB_CRYPTO_HAL_V3(
    test_crypto_init,
    test_crypto_deinit,
    crypto_sha256_init,
    crypto_sha256_update,
    crypto_sha256_finish,
    crypto_monocypher_verify_signature,
    crypto_sha256_get_ctx_size,
    .verify_signature_ph = crypto_monocypher_verify_signature_ph,
    .has_hw_acceleration = false
);

static boot_status_t test_random(uint8_t *buf, size_t len) {
    if (!buf && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < len; i++) {
        buf[i] = (uint8_t)(0x3DU ^ (uint8_t)(i * 19U));
    }
    return BOOT_OK;
}

static const entropy_hal_t s_test_entropy_hal = TOOB_ENTROPY_HAL_V3(
    test_crypto_init,
    test_crypto_deinit,
    test_random,
    .is_hardware_trng = false
);

static boot_status_t test_read_chip_uid(uint8_t *uid_out, size_t max_len, size_t *actual_len) {
    static const uint8_t k_uid[16] = {
        0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
        0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x01U
    };
    if (!uid_out || !actual_len || max_len < sizeof(k_uid)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(uid_out, k_uid, sizeof(k_uid));
    *actual_len = sizeof(k_uid);
    return BOOT_OK;
}

static boot_status_t test_read_pubkey(uint8_t *pubkey_out, size_t buf_len, uint8_t key_index) {
    static const uint8_t k_tv1_pub[32] = {
        0xd7U, 0x5aU, 0x98U, 0x01U, 0x82U, 0xb1U, 0x0aU, 0xb7U,
        0xd5U, 0x4bU, 0xfeU, 0xd3U, 0xc9U, 0x64U, 0x07U, 0x3aU,
        0x0eU, 0xe1U, 0x72U, 0xf3U, 0xdaU, 0xa6U, 0x23U, 0x25U,
        0xafU, 0x02U, 0x1aU, 0x68U, 0xf7U, 0x07U, 0x51U, 0x1aU
    };
    if (!pubkey_out || buf_len < sizeof(k_tv1_pub)) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (key_index > 0U) {
        return BOOT_ERR_NOT_FOUND;
    }
    memcpy(pubkey_out, k_tv1_pub, sizeof(k_tv1_pub));
    return BOOT_OK;
}

static boot_status_t test_read_monotonic_counter(uint32_t *counter_out) {
    if (!counter_out) {
        return BOOT_ERR_INVALID_ARG;
    }
    *counter_out = 0U;
    return BOOT_OK;
}

static boot_status_t test_read_dslc(uint8_t *buffer, size_t *len) {
    if (!buffer || !len || *len == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    buffer[0] = s_test_dslc;
    *len = 1U;
    return BOOT_OK;
}

static boot_status_t test_read_device_secret(uint8_t *secret_out, size_t max_len, size_t *actual_len) {
    static const uint8_t k_huk[32] = {
        0x51U, 0x62U, 0x73U, 0x84U, 0x95U, 0xA6U, 0xB7U, 0xC8U,
        0xD9U, 0xEAU, 0xFBU, 0x0CU, 0x1DU, 0x2EU, 0x3FU, 0x40U,
        0x01U, 0x12U, 0x23U, 0x34U, 0x45U, 0x56U, 0x67U, 0x78U,
        0x89U, 0x9AU, 0xABU, 0xBCU, 0xCDU, 0xDEU, 0xEFU, 0xF2U
    };
    if (!secret_out || !actual_len || max_len < sizeof(k_huk)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(secret_out, k_huk, sizeof(k_huk));
    *actual_len = sizeof(k_huk);
    return BOOT_OK;
}

static const keystore_hal_t s_test_keystore_hal = TOOB_KEYSTORE_HAL_V3(
    test_crypto_init,
    test_crypto_deinit,
    test_read_pubkey,
    test_read_dslc,
    NULL,
    .read_chip_uid = test_read_chip_uid,
    .read_monotonic_counter = test_read_monotonic_counter,
    .read_device_secret = test_read_device_secret
);

static uint32_t s_active_hw_slot = 0U;

static boot_status_t test_xip_remap(uint32_t phys_addr) {
    if (phys_addr == CHIP_APP_SLOT_ABS_ADDR) {
        s_active_hw_slot = 0U;
        return BOOT_OK;
    }
    if (phys_addr == CHIP_STAGING_SLOT_ABS_ADDR) {
        s_active_hw_slot = 1U;
        return BOOT_OK;
    }
    return BOOT_ERR_INVALID_ARG;
}

static boot_status_t test_get_active_slot(uint32_t *out_slot) {
    if (!out_slot) {
        return BOOT_ERR_INVALID_ARG;
    }
    *out_slot = s_active_hw_slot;
    return BOOT_OK;
}

static const slot_caps_t s_test_slot_caps = TOOB_SLOT_CAPS_XIP_REMAP(
    2U, test_xip_remap, test_get_active_slot,
    .commit_persistence = SLOT_COMMIT_VOLATILE
);

const slot_caps_t *boot_get_slot_caps(void) { return &s_test_slot_caps; }

static void write_signed_slot_image(const flash_hal_t *flash, uint32_t slot_addr,
                                    uint8_t fill_byte) {
    uint8_t img[512];
    memset(img, fill_byte, sizeof(img));

    toob_image_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = TOOB_MAGIC_HEADER;
    hdr.image_size = (uint32_t)sizeof(img);
    hdr.entry_point = 0x40U;
    memcpy(img, &hdr, sizeof(hdr));

    uint32_t signed_len = (uint32_t)(sizeof(img) - sizeof(toob_img_sig_trailer_t));
    uint8_t digest[32];
    uint8_t sha_ctx[256] __attribute__((aligned(8)));
    size_t dlen = sizeof(digest);
    assert(crypto_sha256_init(sha_ctx, sizeof(sha_ctx)) == BOOT_OK);
    assert(crypto_sha256_update(sha_ctx, img, signed_len) == BOOT_OK);
    assert(crypto_sha256_finish(sha_ctx, digest, &dlen) == BOOT_OK);

    static const uint8_t k_tv1_seed[32] = {
        0x9dU, 0x61U, 0xb1U, 0x9dU, 0xefU, 0xfdU, 0x5aU, 0x60U,
        0xbaU, 0x84U, 0x4aU, 0xf4U, 0x92U, 0xecU, 0x2cU, 0xc4U,
        0x44U, 0x49U, 0xc5U, 0x69U, 0x7bU, 0x32U, 0x69U, 0x19U,
        0x70U, 0x3bU, 0xacU, 0x03U, 0x1cU, 0xaeU, 0x7fU, 0x60U
    };
    uint8_t seed_copy[32];
    memcpy(seed_copy, k_tv1_seed, sizeof(seed_copy));
    uint8_t sk[64];
    uint8_t pk[32];
    crypto_ed25519_key_pair(sk, pk, seed_copy);

    toob_img_sig_trailer_t trailer;
    memset(&trailer, 0, sizeof(trailer));
    trailer.magic = TOOB_IMG_SIG_MAGIC;
    trailer.key_index = 0U;
    trailer.flags = TOOB_IMG_SIG_FLAG_SHA256;
    trailer.reserved = 0U;
    crypto_ed25519_sign(trailer.sig_ed25519, sk, digest, sizeof(digest));
    memcpy(img + signed_len, &trailer, sizeof(trailer));

    assert(flash->erase_sector(slot_addr) == BOOT_OK);
    assert(flash->write(slot_addr, img, sizeof(img)) == BOOT_OK);
}

int main(void) {
    printf("==================================================\n");
    printf("   Recovery OS Integration & Roach-Motel Test\n");
    printf("==================================================\n\n");

    remove(SIM_FLASH_FILE);

    /* 1. Setup Flash Model */
    flash_model_t model;
    memset(&model, 0, sizeof(model));
    model.file_path = SIM_FLASH_FILE;
    model.total_size = CHIP_FLASH_TOTAL_SIZE;
    model.sector_size = CHIP_FLASH_MAX_SECTOR_SIZE;
    model.erased_value = 0xFFU;
    model.write_align = CHIP_FLASH_WRITE_ALIGNMENT;

    const flash_hal_t *flash_hal = flash_model_get_hal(&model);
    assert(flash_hal != NULL);
    assert(flash_hal->init() == BOOT_OK);

    boot_platform_t test_plat;
    memset(&test_plat, 0, sizeof(test_plat));
    test_plat.flash = flash_hal;
    test_plat.confirm = &s_test_confirm_hal;
    test_plat.crypto = &s_test_crypto_hal;
    test_plat.clock = &s_test_clock_hal;
    test_plat.wdt = &s_test_wdt_hal;
    test_plat.entropy = &s_test_entropy_hal;
    test_plat.keystore = &s_test_keystore_hal;
    test_plat.slot_caps = &s_test_slot_caps;

    /* Flash valid TSIG-signed App & Recovery images */
    write_signed_slot_image(flash_hal, CHIP_APP_SLOT_ABS_ADDR, 0x11U);
    write_signed_slot_image(flash_hal, CHIP_RECOVERY_OS_ABS_ADDR, 0x22U);

    boot_target_config_t target_cfg;
    memset(&target_cfg, 0, sizeof(target_cfg));

    /* Initialize blank WAL in unprovisioned DSLC == 0x00 state (CRIT-69), then switch to deployed */
    s_test_dslc = 0x00U;
    assert(boot_journal_init(&test_plat) == BOOT_OK);
    s_test_dslc = 0x01U;

    /* Populate initial healthy TMR in flash */
    boot_status_t status = boot_state_run(&test_plat, &target_cfg, dummy_key, g_arena, sizeof(g_arena));
    printf("Initial boot status: 0x%08X, boot_recovery: %d\n", (unsigned)status, target_cfg.boot_recovery_os);
    assert(status == BOOT_OK);
    assert(target_cfg.boot_recovery_os == false);

    /* Get current TMR */
    wal_tmr_payload_t tmr;
    assert(boot_journal_get_tmr(&test_plat, &tmr) == BOOT_OK);
    printf("Initial boot_failure_counter: %u, recovery_failure_counter: %u\n",
           (unsigned)tmr.boot_failure_counter, (unsigned)tmr.recovery_failure_counter);

    /* Verify Recovery routing when normal counter exceeds BOOT_CONFIG_MAX_RETRIES */
    tmr.boot_failure_counter = BOOT_CONFIG_MAX_RETRIES + 1U;
    tmr.recovery_failure_counter = 1U;
    assert(boot_journal_update_tmr(&test_plat, &tmr) == BOOT_OK);
    memset(&target_cfg, 0, sizeof(target_cfg));
    assert(boot_state_run(&test_plat, &target_cfg, dummy_key, g_arena, sizeof(g_arena)) == BOOT_OK);
    assert(target_cfg.boot_recovery_os == true);
    /* Wave-1 invariant: recovery_failure_counter is retained until CONFIRM_COMMIT */
    assert(boot_journal_get_tmr(&test_plat, &tmr) == BOOT_OK);
    assert(tmr.recovery_failure_counter == 1U);

    /* Exhaust both counters and verify Roach-Motel escalation */
    printf("\nExhausting counters directly in TMR...\n");
    tmr.boot_failure_counter = BOOT_CONFIG_MAX_RETRIES + 1U;
    tmr.recovery_failure_counter = BOOT_CONFIG_MAX_RECOVERY_RETRIES + 1U;
    assert(boot_journal_update_tmr(&test_plat, &tmr) == BOOT_OK);

    /* Trigger reboot run. Must halt into BOOT_RECOVERY_REQUESTED (Serial Rescue) and NOT sleep */
    memset(&target_cfg, 0, sizeof(target_cfg));
    s_expect_panic = true;
    s_last_panic = BOOT_OK;
    if (setjmp(s_panic_jmp) == 0) {
        (void)boot_state_run(&test_plat, &target_cfg, dummy_key, g_arena, sizeof(g_arena));
    }
    s_expect_panic = false;

    printf("Final panic reason: 0x%08X (expected: 0x%08X)\n",
           (unsigned)s_last_panic, (unsigned)BOOT_RECOVERY_REQUESTED);
    assert(s_last_panic == BOOT_RECOVERY_REQUESTED);

    /* Verify WAL has no Sleep Intent (either no entry yet or active intent != SLEEP_BACKOFF) */
    wal_entry_payload_t open_txn;
    boot_secure_zeroize(&open_txn, sizeof(open_txn));
    uint32_t dummy_accum = 0U;
    uint32_t dummy_resume = 0U;
    boot_status_t recon_st = boot_journal_reconstruct_txn(&test_plat, &open_txn, &dummy_accum, &dummy_resume);
    assert(recon_st == BOOT_OK || recon_st == BOOT_ERR_STATE);
    printf("Active intent in WAL: 0x%X (recon=0x%08X, must not be WAL_INTENT_SLEEP_BACKOFF)\n",
           (unsigned)open_txn.intent, (unsigned)recon_st);
    if (recon_st == BOOT_OK) {
        assert(open_txn.intent != (uint32_t)WAL_INTENT_SLEEP_BACKOFF);
    }

    remove(SIM_FLASH_FILE);
    printf("\n==================================================\n");
    printf("   ROACH-MOTEL RECOVERY INVARIANT VERIFIED!\n");
    printf("==================================================\n");
    return 0;
}
