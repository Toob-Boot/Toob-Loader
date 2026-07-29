#include "boot_hal.h"
#include <stdlib.h>
#include <string.h>

extern const flash_hal_t sandbox_flash_hal;
extern const confirm_hal_t sandbox_confirm_hal;
extern const clock_hal_t sandbox_clock_hal;
extern const wdt_hal_t sandbox_wdt_hal;
extern const console_hal_t sandbox_console_hal;
extern const soc_hal_t sandbox_soc_hal;

/* Mock sandbox crypto HAL */
static boot_status_t sandbox_crypto_init(void) {
    return BOOT_OK;
}

static void sandbox_crypto_deinit(void) {
}

static boot_status_t sandbox_crypto_hash_init(void *ctx, size_t ctx_size) {
    (void)ctx; (void)ctx_size;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_hash_update(void *ctx, const void *data, size_t len) {
    (void)ctx; (void)data; (void)len;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_hash_finish(void *ctx, uint8_t *digest, size_t *digest_len) {
    (void)ctx;
    memset(digest, 0, *digest_len);
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_verify_signature(const uint8_t *message, size_t msg_len, const uint8_t *sig, const uint8_t *pubkey) {
    (void)message; (void)msg_len; (void)sig; (void)pubkey;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_verify_signature_ph(const uint8_t *msg_digest, const uint8_t *sig, const uint8_t *pubkey) {
    (void)msg_digest; (void)sig; (void)pubkey;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_verify_pqc(const uint8_t *message, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    (void)message; (void)msg_len; (void)sig; (void)sig_len; (void)pubkey; (void)pubkey_len;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() % 256);
    }
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_read_pubkey(uint8_t *key, size_t key_len, uint8_t key_index) {
    (void)key_index;
    memset(key, 0, key_len);
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_read_chip_uid(uint8_t *buf, size_t max_len, size_t *out_len) {
    memset(buf, 0x42, max_len);
    *out_len = max_len;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_read_dslc(uint8_t *buffer, size_t *len) {
    memset(buffer, 0, *len);
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_write_dslc(const uint8_t *value, size_t len) {
    (void)value; (void)len;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_read_monotonic_counter(uint32_t *ctr) {
    *ctr = 0;
    return BOOT_OK;
}

static boot_status_t sandbox_crypto_advance_monotonic_counter(void) {
    return BOOT_OK;
}

static size_t sandbox_crypto_get_hash_ctx_size(void) {
    return 64;
}

static const crypto_hal_t sandbox_crypto_hal =
    TOOB_CRYPTO_HAL_V2(
        sandbox_crypto_init,
        sandbox_crypto_deinit,
        sandbox_crypto_hash_init,
        sandbox_crypto_hash_update,
        sandbox_crypto_hash_finish,
        sandbox_crypto_verify_signature,
        sandbox_crypto_random,
        sandbox_crypto_get_hash_ctx_size,
        .verify_pqc               = sandbox_crypto_verify_pqc,
        .read_pubkey              = sandbox_crypto_read_pubkey,
        .read_chip_uid            = sandbox_crypto_read_chip_uid,
        .read_dslc                = sandbox_crypto_read_dslc,
        .write_dslc               = sandbox_crypto_write_dslc,
        .read_monotonic_counter   = sandbox_crypto_read_monotonic_counter,
        .advance_monotonic_counter = sandbox_crypto_advance_monotonic_counter,
        .verify_signature_ph      = sandbox_crypto_verify_signature_ph,
    );

static const entropy_hal_t sandbox_entropy_hal =
    TOOB_ENTROPY_HAL_V3(
        sandbox_crypto_init,
        sandbox_crypto_deinit,
        sandbox_crypto_random,
        .is_hardware_trng = false
    );

static const keystore_hal_t sandbox_keystore_hal =
    TOOB_KEYSTORE_HAL_V3(
        sandbox_crypto_init,
        sandbox_crypto_deinit,
        sandbox_crypto_read_pubkey,
        sandbox_crypto_read_dslc,
        sandbox_crypto_write_dslc,
        .read_chip_uid            = sandbox_crypto_read_chip_uid,
        .read_monotonic_counter   = sandbox_crypto_read_monotonic_counter,
        .advance_monotonic_counter = sandbox_crypto_advance_monotonic_counter
    );

static boot_platform_t sandbox_platform = {
    .flash = &sandbox_flash_hal,
    .confirm = &sandbox_confirm_hal,
    .crypto = &sandbox_crypto_hal,
    .clock = &sandbox_clock_hal,
    .wdt = &sandbox_wdt_hal,
    .console = &sandbox_console_hal,
    .soc = &sandbox_soc_hal,
    .provisioning = NULL,
    .entropy = &sandbox_entropy_hal,
    .keystore = &sandbox_keystore_hal
};

const boot_platform_t *boot_platform_init(void) {
    return &sandbox_platform;
}
