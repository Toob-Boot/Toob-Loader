#include "fuzz_common.h"

#include "boot_secure_zeroize.h"
#include "boot_slot_caps.h"
#include "crypto_monocypher.h"
#include "crypto_sha256.h"
#include "monocypher-ed25519.h"

#include <stdio.h>
#include <stdlib.h>

uint8_t g_fuzz_flash[CHIP_FLASH_TOTAL_SIZE];
uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

jmp_buf g_fuzz_trap_jmp;
volatile int g_fuzz_trap_active = 0;
volatile int g_fuzz_uart_eof_longjmp = 0;

uint8_t g_fuzz_root_sk[64];
uint8_t g_fuzz_root_pk[32];
uint8_t g_fuzz_cloud_sk[64];
uint8_t g_fuzz_cloud_pk[32];

static uint8_t s_otp_keys[TOOB_DEVICE_KEY_SLOTS][32];
static bool s_otp_valid[TOOB_DEVICE_KEY_SLOTS];
static uint8_t s_pqc_hashes[TOOB_DEVICE_KEY_SLOTS][32];
static bool s_pqc_hash_valid[TOOB_DEVICE_KEY_SLOTS];
static uint8_t s_device_secret[32];
static uint8_t s_chip_uid[8];
static uint8_t s_dslc_val = 0x01U;
static uint32_t s_monotonic_ctr = 0U;
static uint64_t s_rng_state = 0x9E3779B97F4A7C15ULL;
static uint32_t s_tick_ms = 100U;
static reset_reason_t s_reset_reason = RESET_REASON_POWER_ON;
static bool s_enforce_nor = false;
static uint64_t s_confirm_nonce = 0ULL;
static uint32_t s_rtc_backup[8];

static const uint8_t *s_uart_rx_buf = NULL;
static size_t s_uart_rx_len = 0U;
static size_t s_uart_rx_pos = 0U;

static bool s_keys_initialized = false;

static void ensure_keys_init(void) {
    if (s_keys_initialized) {
        return;
    }
    /* RFC 8032 TV1 seed for Root Key 0 */
    static const uint8_t root_seed[32] = {
        0x9dU, 0x61U, 0xb1U, 0x9dU, 0xefU, 0xfdU, 0x5aU, 0x60U,
        0xbaU, 0x84U, 0x4aU, 0xf4U, 0x92U, 0xecU, 0x2cU, 0xc4U,
        0x44U, 0x49U, 0xc5U, 0x69U, 0x7bU, 0x32U, 0x69U, 0x19U,
        0x70U, 0x3bU, 0xacU, 0x03U, 0x1cU, 0xaeU, 0x7fU, 0x60U
    };
    /* RFC 8032 TV2 seed for Cloud / Rotation Key 1 */
    static const uint8_t cloud_seed[32] = {
        0x4cU, 0xcdU, 0x08U, 0x9bU, 0x28U, 0xffU, 0x96U, 0xdaU,
        0x9dU, 0xb6U, 0xc3U, 0x46U, 0xecU, 0x11U, 0x4eU, 0x0fU,
        0x5bU, 0x8aU, 0x31U, 0x9fU, 0x35U, 0xabU, 0xa6U, 0x24U,
        0xdaU, 0x8cU, 0xf6U, 0xedU, 0x4fU, 0xb8U, 0xa6U, 0xfbU
    };
    uint8_t tmp_r[32];
    uint8_t tmp_c[32];
    memcpy(tmp_r, root_seed, sizeof(tmp_r));
    memcpy(tmp_c, cloud_seed, sizeof(tmp_c));
    crypto_ed25519_key_pair(g_fuzz_root_sk, g_fuzz_root_pk, tmp_r);
    crypto_ed25519_key_pair(g_fuzz_cloud_sk, g_fuzz_cloud_pk, tmp_c);
    boot_secure_zeroize(tmp_r, sizeof(tmp_r));
    boot_secure_zeroize(tmp_c, sizeof(tmp_c));
    s_keys_initialized = true;
}

static boot_status_t fuzz_flash_init(void) {
    return BOOT_OK;
}

static void fuzz_flash_deinit(void) {
}

static boot_status_t fuzz_flash_read(uint32_t addr, void *buf, size_t len) {
    if (buf == NULL && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (addr > (uint32_t)sizeof(g_fuzz_flash) || len > (size_t)sizeof(g_fuzz_flash) - (size_t)addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if (len > 0U) {
        memcpy(buf, &g_fuzz_flash[addr], len);
    }
    return BOOT_OK;
}

static boot_status_t fuzz_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (buf == NULL && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (len == 0U) {
        return BOOT_OK;
    }
    if (addr > (uint32_t)sizeof(g_fuzz_flash) || len > (size_t)sizeof(g_fuzz_flash) - (size_t)addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U || (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    const uint8_t *src = (const uint8_t *)buf;
    if (s_enforce_nor) {
        for (size_t i = 0U; i < len; i++) {
            if ((~g_fuzz_flash[addr + i] & src[i]) != 0U) {
                return BOOT_ERR_FLASH_HW;
            }
        }
    }
    for (size_t i = 0U; i < len; i++) {
        g_fuzz_flash[addr + i] &= src[i];
    }
    return BOOT_OK;
}

static boot_status_t fuzz_flash_erase_sector(uint32_t addr) {
    if ((addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U ||
        addr >= (uint32_t)sizeof(g_fuzz_flash) ||
        (uint32_t)CHIP_FLASH_MAX_SECTOR_SIZE > (uint32_t)sizeof(g_fuzz_flash) - addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    memset(&g_fuzz_flash[addr], CHIP_FLASH_ERASED_BYTE, CHIP_FLASH_MAX_SECTOR_SIZE);
    return BOOT_OK;
}

static boot_status_t fuzz_flash_get_sector_size(uint32_t addr, size_t *size_out) {
    if (size_out == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (addr >= (uint32_t)sizeof(g_fuzz_flash)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    *size_out = CHIP_FLASH_MAX_SECTOR_SIZE;
    return BOOT_OK;
}

static boot_status_t fuzz_flash_set_otfdec(bool enable) {
    (void)enable;
    return BOOT_OK;
}

static uint32_t fuzz_flash_last_err(void) {
    return 0U;
}

static boot_status_t fuzz_confirm_init(void) {
    return BOOT_OK;
}

static void fuzz_confirm_deinit(void) {
}

static bool fuzz_confirm_check_ok(uint64_t expected_nonce) {
    if (expected_nonce == 0ULL || s_confirm_nonce == 0ULL || s_confirm_nonce != expected_nonce) {
        return false;
    }
    s_confirm_nonce = 0ULL;
    return true;
}

static boot_status_t fuzz_confirm_clear(void) {
    s_confirm_nonce = 0ULL;
    return BOOT_OK;
}

static boot_status_t fuzz_clock_init(void) {
    return BOOT_OK;
}

static void fuzz_clock_deinit(void) {
}

static uint32_t fuzz_clock_get_tick_ms(void) {
    s_tick_ms += 10U;
    return s_tick_ms;
}

static void fuzz_clock_delay_ms(uint32_t ms) {
    s_tick_ms += ms;
}

static reset_reason_t fuzz_clock_get_reset_reason(void) {
    return s_reset_reason;
}

static boot_status_t fuzz_wdt_init(uint32_t timeout_ms_required) {
    (void)timeout_ms_required;
    return BOOT_OK;
}

static void fuzz_wdt_deinit(void) {
}

static void fuzz_wdt_kick(void) {
}

static void fuzz_wdt_suspend(void) {
}

static void fuzz_wdt_resume(void) {
}

static boot_status_t fuzz_console_init(uint32_t baudrate) {
    (void)baudrate;
    return BOOT_OK;
}

static void fuzz_console_deinit(void) {
}

static void fuzz_console_putchar(char c) {
    (void)c;
}

static boot_status_t fuzz_console_getchar(uint8_t *out, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (out == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (s_uart_rx_buf != NULL && s_uart_rx_pos < s_uart_rx_len) {
        *out = s_uart_rx_buf[s_uart_rx_pos++];
        return BOOT_OK;
    }
    if (g_fuzz_uart_eof_longjmp != 0 && g_fuzz_trap_active != 0) {
        longjmp(g_fuzz_trap_jmp, 2);
    }
    return BOOT_ERR_TIMEOUT;
}

static void fuzz_console_flush(void) {
}

static boot_status_t fuzz_soc_init(void) {
    return BOOT_OK;
}

static void fuzz_soc_deinit(void) {
}

static uint32_t fuzz_soc_battery_mv(void) {
    return 3300U;
}

static bool fuzz_soc_can_sustain(void) {
    return true;
}

static void fuzz_soc_low_power(uint32_t wakeup_s) {
    (void)wakeup_s;
}

static void fuzz_soc_assert_sec(void) {
}

static void fuzz_soc_flush_bus(void) {
}

static void fuzz_soc_inv_icache(void) {
}

static void fuzz_soc_disable_irq(void) {
}

static bool fuzz_soc_recovery_pin(void) {
    return false;
}

static boot_status_t fuzz_soc_read_rtc(uint8_t slot, uint32_t *val) {
    if (val == NULL || slot >= 8U) {
        return BOOT_ERR_INVALID_ARG;
    }
    *val = s_rtc_backup[slot];
    return BOOT_OK;
}

static boot_status_t fuzz_soc_write_rtc(uint8_t slot, uint32_t val) {
    if (slot >= 8U) {
        return BOOT_ERR_INVALID_ARG;
    }
    s_rtc_backup[slot] = val;
    return BOOT_OK;
}

static boot_status_t fuzz_soc_lockdown(void) {
    return BOOT_OK;
}

static boot_status_t fuzz_entropy_init(void) {
    return BOOT_OK;
}

static void fuzz_entropy_deinit(void) {
}

static uint64_t next_rng_word(void) {
    uint64_t x = s_rng_state;
    if (x == 0ULL) {
        x = 0xA55AA55A5AA55AA5ULL;
    }
    x ^= x >> 12U;
    x ^= x << 25U;
    x ^= x >> 27U;
    s_rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static boot_status_t fuzz_entropy_random(uint8_t *buf, size_t len) {
    if (buf == NULL && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < len; i++) {
        buf[i] = (uint8_t)(next_rng_word() >> ((i & 7U) * 8U));
    }
    /* Prevent accidental single-value draws on small len > 1 */
    if (len >= 2U && buf[0] == buf[1]) {
        buf[1] ^= 0x5AU;
    }
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_init(void) {
    return BOOT_OK;
}

static void fuzz_keystore_deinit(void) {
}

static boot_status_t fuzz_keystore_read_pubkey(uint8_t *key, size_t key_len, uint8_t key_index) {
    if (key == NULL || key_len != 32U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (key_index >= TOOB_DEVICE_KEY_SLOTS || !s_otp_valid[key_index]) {
        return BOOT_ERR_NOT_FOUND;
    }
    memcpy(key, s_otp_keys[key_index], 32U);
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_read_chip_uid(uint8_t *buf, size_t max_len, size_t *out_len) {
    if (buf == NULL || out_len == NULL || max_len < sizeof(s_chip_uid)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(buf, s_chip_uid, sizeof(s_chip_uid));
    *out_len = sizeof(s_chip_uid);
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_read_dslc(uint8_t *buffer, size_t *len) {
    if (buffer == NULL || len == NULL || *len == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    buffer[0] = s_dslc_val;
    *len = 1U;
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_write_dslc(const uint8_t *value, size_t len) {
    if (value == NULL || len == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    s_dslc_val = value[0];
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_read_monotonic(uint32_t *ctr) {
    if (ctr == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    *ctr = s_monotonic_ctr;
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_advance_monotonic(void) {
    if (s_monotonic_ctr == UINT32_MAX) {
        return BOOT_ERR_COUNTER_EXHAUSTED;
    }
    s_monotonic_ctr++;
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_read_device_secret(uint8_t *buf, size_t max_len, size_t *out_len) {
    if (buf == NULL || out_len == NULL || max_len < sizeof(s_device_secret)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(buf, s_device_secret, sizeof(s_device_secret));
    *out_len = sizeof(s_device_secret);
    return BOOT_OK;
}

static boot_status_t fuzz_keystore_read_pqc_hash(uint8_t out_hash[32], uint8_t key_index) {
    if (out_hash == NULL || key_index >= TOOB_DEVICE_KEY_SLOTS || !s_pqc_hash_valid[key_index]) {
        return BOOT_ERR_NOT_FOUND;
    }
    memcpy(out_hash, s_pqc_hashes[key_index], 32U);
    return BOOT_OK;
}

static const flash_hal_t s_fuzz_flash_hal = TOOB_FLASH_HAL_V2(
    fuzz_flash_init,
    fuzz_flash_deinit,
    fuzz_flash_read,
    fuzz_flash_write,
    fuzz_flash_erase_sector,
    fuzz_flash_get_sector_size,
    .set_otfdec_mode = fuzz_flash_set_otfdec,
    .get_last_vendor_error = fuzz_flash_last_err,
    .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
    .total_size = CHIP_FLASH_TOTAL_SIZE,
    .max_erase_cycles = 100000U,
    .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
    .erased_value = CHIP_FLASH_ERASED_BYTE,
    .erase_time_us_max = 0U,
    .write_time_us_page = 0U,
    .get_supply_mv = NULL
);

static const confirm_hal_t s_fuzz_confirm_hal = TOOB_CONFIRM_HAL_V2(
    fuzz_confirm_init,
    fuzz_confirm_deinit,
    fuzz_confirm_check_ok,
    fuzz_confirm_clear
);

static const crypto_hal_t s_fuzz_crypto_hal = TOOB_CRYPTO_HAL_V3(
    crypto_monocypher_init,
    crypto_monocypher_deinit,
    crypto_sha256_init,
    crypto_sha256_update,
    crypto_sha256_finish,
    crypto_monocypher_verify_signature,
    crypto_sha256_get_ctx_size,
    .verify_pqc = NULL,
    .get_last_vendor_error = NULL,
    .has_hw_acceleration = false,
    .is_pqc_enforced = NULL,
    .verify_signature_ph = crypto_monocypher_verify_signature_ph
);

static const clock_hal_t s_fuzz_clock_hal = TOOB_CLOCK_HAL_V2(
    fuzz_clock_init,
    fuzz_clock_deinit,
    fuzz_clock_get_tick_ms,
    fuzz_clock_delay_ms,
    fuzz_clock_get_reset_reason
);

static const wdt_hal_t s_fuzz_wdt_hal = TOOB_WDT_HAL_V2(
    fuzz_wdt_init,
    fuzz_wdt_deinit,
    fuzz_wdt_kick,
    fuzz_wdt_suspend,
    fuzz_wdt_resume
);

static const console_hal_t s_fuzz_console_hal = TOOB_CONSOLE_HAL_V2(
    fuzz_console_init,
    fuzz_console_deinit,
    fuzz_console_putchar,
    fuzz_console_getchar,
    fuzz_console_flush
);

static const soc_hal_t s_fuzz_soc_hal = TOOB_SOC_HAL_V2(
    fuzz_soc_init,
    fuzz_soc_deinit,
    .battery_level_mv = fuzz_soc_battery_mv,
    .can_sustain_update = fuzz_soc_can_sustain,
    .enter_low_power = fuzz_soc_low_power,
    .assert_secondary_cores_reset = fuzz_soc_assert_sec,
    .flush_bus_matrix = fuzz_soc_flush_bus,
    .invalidate_icache = fuzz_soc_inv_icache,
    .disable_interrupts = fuzz_soc_disable_irq,
    .get_recovery_pin_state = fuzz_soc_recovery_pin,
    .read_rtc_backup = fuzz_soc_read_rtc,
    .write_rtc_backup = fuzz_soc_write_rtc,
    .min_battery_mv = 2700U,
    .swap_notify = NULL,
    .lockdown_before_handoff = fuzz_soc_lockdown
);

static const entropy_hal_t s_fuzz_entropy_hal = TOOB_ENTROPY_HAL_V3(
    fuzz_entropy_init,
    fuzz_entropy_deinit,
    fuzz_entropy_random,
    .is_hardware_trng = true
);

static const keystore_hal_t s_fuzz_keystore_hal = TOOB_KEYSTORE_HAL_V3(
    fuzz_keystore_init,
    fuzz_keystore_deinit,
    fuzz_keystore_read_pubkey,
    fuzz_keystore_read_dslc,
    fuzz_keystore_write_dslc,
    .read_chip_uid = fuzz_keystore_read_chip_uid,
    .read_monotonic_counter = fuzz_keystore_read_monotonic,
    .advance_monotonic_counter = fuzz_keystore_advance_monotonic,
    .read_device_secret = fuzz_keystore_read_device_secret,
    .read_pqc_pubkey_hash = fuzz_keystore_read_pqc_hash
);

static const slot_caps_t s_fuzz_slot_caps = TOOB_SLOT_CAPS_FIXED(
    2U,
    .commit_persistence = SLOT_COMMIT_PERSISTENT,
    .has_scratch = true,
    .scratch_size = CHIP_SCRATCH_SLOT_SIZE
);

static const boot_platform_t s_fuzz_platform = {
    .flash = &s_fuzz_flash_hal,
    .confirm = &s_fuzz_confirm_hal,
    .crypto = &s_fuzz_crypto_hal,
    .clock = &s_fuzz_clock_hal,
    .wdt = &s_fuzz_wdt_hal,
    .console = &s_fuzz_console_hal,
    .soc = &s_fuzz_soc_hal,
    .provisioning = NULL,
    .slot_caps = &s_fuzz_slot_caps,
    .entropy = &s_fuzz_entropy_hal,
    .keystore = &s_fuzz_keystore_hal
};

const slot_caps_t *boot_get_slot_caps(void) {
    return &s_fuzz_slot_caps;
}

_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason,
                                  uint16_t site_id) {
    (void)platform;
    (void)reason;
    (void)site_id;
    if (g_fuzz_trap_active != 0) {
        longjmp(g_fuzz_trap_jmp, 1);
    }
    abort();
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    boot_terminal_halt(platform, reason, 0U);
}

void fuzz_platform_reset(uint64_t rng_seed) {
    ensure_keys_init();
    memset(g_fuzz_flash, CHIP_FLASH_ERASED_BYTE, sizeof(g_fuzz_flash));
    memset(crypto_arena, 0, sizeof(crypto_arena));
    memset(s_otp_keys, 0, sizeof(s_otp_keys));
    memset(s_otp_valid, 0, sizeof(s_otp_valid));
    memset(s_pqc_hashes, 0, sizeof(s_pqc_hashes));
    memset(s_pqc_hash_valid, 0, sizeof(s_pqc_hash_valid));
    memset(s_rtc_backup, 0, sizeof(s_rtc_backup));

    memcpy(s_otp_keys[0], g_fuzz_root_pk, 32U);
    s_otp_valid[0] = true;

    for (size_t i = 0U; i < sizeof(s_device_secret); i++) {
        s_device_secret[i] = (uint8_t)(0x3AU + (uint8_t)i);
    }
    static const uint8_t default_uid[8] = { 0x52U, 0x84U, 0x00U, 0x01U, 0xDEU, 0xADU, 0xBEU, 0xEFU };
    memcpy(s_chip_uid, default_uid, sizeof(s_chip_uid));

    s_dslc_val = 0x01U;
    s_monotonic_ctr = 0U;
    s_rng_state = (rng_seed != 0ULL) ? rng_seed : 0x9E3779B97F4A7C15ULL;
    s_tick_ms = 100U;
    s_reset_reason = RESET_REASON_POWER_ON;
    s_enforce_nor = false;
    s_confirm_nonce = 0ULL;
    s_uart_rx_buf = NULL;
    s_uart_rx_len = 0U;
    s_uart_rx_pos = 0U;
    g_fuzz_uart_eof_longjmp = 0;
}

const boot_platform_t *fuzz_platform_get(void) {
    return &s_fuzz_platform;
}

void fuzz_flash_write_raw(uint32_t addr, const uint8_t *src, size_t len) {
    if (src == NULL || len == 0U || addr >= (uint32_t)sizeof(g_fuzz_flash)) {
        return;
    }
    size_t max_len = sizeof(g_fuzz_flash) - (size_t)addr;
    size_t copy_len = (len < max_len) ? len : max_len;
    memcpy(&g_fuzz_flash[addr], src, copy_len);
}

void fuzz_flash_fill_erased(uint32_t addr, size_t len) {
    if (len == 0U || addr >= (uint32_t)sizeof(g_fuzz_flash)) {
        return;
    }
    size_t max_len = sizeof(g_fuzz_flash) - (size_t)addr;
    size_t fill_len = (len < max_len) ? len : max_len;
    memset(&g_fuzz_flash[addr], CHIP_FLASH_ERASED_BYTE, fill_len);
}

void fuzz_flash_set_enforce_nor(bool enforce) {
    s_enforce_nor = enforce;
}

void fuzz_keystore_set_dslc(uint8_t dslc_val) {
    s_dslc_val = dslc_val;
}

void fuzz_keystore_set_monotonic(uint32_t ctr) {
    s_monotonic_ctr = ctr;
}

uint32_t fuzz_keystore_get_monotonic(void) {
    return s_monotonic_ctr;
}

void fuzz_keystore_set_key(uint8_t slot, const uint8_t *pk, bool valid) {
    if (slot >= TOOB_DEVICE_KEY_SLOTS) {
        return;
    }
    s_otp_valid[slot] = valid;
    if (valid && pk != NULL) {
        memcpy(s_otp_keys[slot], pk, 32U);
    } else {
        memset(s_otp_keys[slot], 0, 32U);
    }
}

void fuzz_keystore_set_pqc_hash(uint8_t slot, const uint8_t hash[32], bool valid) {
    if (slot >= TOOB_DEVICE_KEY_SLOTS) {
        return;
    }
    s_pqc_hash_valid[slot] = valid;
    if (valid && hash != NULL) {
        memcpy(s_pqc_hashes[slot], hash, 32U);
    } else {
        memset(s_pqc_hashes[slot], 0, 32U);
    }
}

void fuzz_clock_set_reset_reason(reset_reason_t reason) {
    s_reset_reason = reason;
}

void fuzz_uart_set_rx(const uint8_t *data, size_t len, bool eof_longjmp) {
    s_uart_rx_buf = data;
    s_uart_rx_len = len;
    s_uart_rx_pos = 0U;
    g_fuzz_uart_eof_longjmp = eof_longjmp ? 1 : 0;
}

void fuzz_uart_reset_tx(void) {
}

size_t fuzz_uart_rx_remaining(void) {
    if (s_uart_rx_pos >= s_uart_rx_len) {
        return 0U;
    }
    return s_uart_rx_len - s_uart_rx_pos;
}
