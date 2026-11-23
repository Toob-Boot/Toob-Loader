/**
 * @file test_provisioning.c
 * @brief Host Integration Test: Factory Provisioning Protocol & eFuse Drivers
 *
 * Verifies:
 * 1. eFuse Mock OTP Primitives (read_chip_uid, burn_pubkey, prov_write_dslc,
 *    advance_monotonic, set_protection_bits, enable_secure_boot, enable_flash_encryption).
 * 2. OTP Monotonicity enforcement (cannot clear 1-bits to 0-bits).
 * 3. Factory Provisioning Wire Protocol (COBS + CRC32 command handling):
 *    - PROV_CMD_READ_ID
 *    - PROV_CMD_BURN_KEY
 *    - PROV_CMD_SET_PROTECTION
 *    - PROV_CMD_ENABLE_SB
 *    - PROV_CMD_ENABLE_FE
 *    - PROV_CMD_SET_DSLC
 *    - Frame corruption / CRC error rejection
 *    - Unsupported command rejection
 *    - PROV_CMD_REBOOT handoff
 */

#include "boot_hal.h"
#include "boot_cobs.h"
#include "boot_crc32.h"
#include "boot_journal.h"
#include "boot_panic.h"
#include "boot_provisioning.h"
#include "boot_secure_zeroize.h"
#include "../../toob-infra/registry/packages/drivers/keystore/esp_efuse/efuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#define __USE_MINGW_SETJMP_NON_SEH
#endif
#include <setjmp.h>

#define ARENA_SIZE 1024

/* Simulation UART buffers */
#define UART_BUF_SIZE 4096
static uint8_t s_uart_rx_fifo[UART_BUF_SIZE];
static size_t s_uart_rx_head = 0;
static size_t s_uart_rx_tail = 0;

static uint8_t s_uart_tx_fifo[UART_BUF_SIZE];
static size_t s_uart_tx_len = 0;

static jmp_buf s_halt_jmp;
static bool s_halt_expected = false;
static boot_status_t s_last_halt_reason = BOOT_OK;

/* Mock boot_terminal_halt and boot_panic for host test */
_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason, uint16_t site_id) {
    (void)platform;
    (void)site_id;
    s_last_halt_reason = reason;
    if (s_halt_expected) {
        longjmp(s_halt_jmp, 1);
    }
    fprintf(stderr, "Unexpected terminal halt: reason 0x%08X\n", reason);
    exit(1);
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    boot_terminal_halt(platform, reason, 0);
}

static boot_status_t mock_console_init(uint32_t baudrate) { (void)baudrate; return BOOT_OK; }
static void mock_console_deinit(void) {}

static void mock_console_putchar(char c) {
    if (s_uart_tx_len < UART_BUF_SIZE) {
        s_uart_tx_fifo[s_uart_tx_len++] = (uint8_t)c;
    }
}

static boot_status_t mock_console_getchar(uint8_t *out, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (s_uart_rx_tail < s_uart_rx_head) {
        *out = s_uart_rx_fifo[s_uart_rx_tail++];
        return BOOT_OK;
    }
    return BOOT_ERR_TIMEOUT;
}

static void mock_console_flush(void) {}

static const console_hal_t s_mock_console_hal = {
    .abi_version = 0x02000000,
    .init        = mock_console_init,
    .deinit      = mock_console_deinit,
    .putchar     = mock_console_putchar,
    .getchar     = mock_console_getchar,
    .flush       = mock_console_flush
};

/* Queue a raw frame into RX FIFO encoded as COBS */
static void queue_cobs_frame(const uint8_t *payload, size_t payload_len) {
    uint32_t crc = compute_boot_crc32(payload, payload_len);
    uint8_t raw[256];
    memcpy(raw, payload, payload_len);
    memcpy(&raw[payload_len], &crc, 4);
    size_t raw_len = payload_len + 4;

    size_t read_idx = 0;
    size_t write_idx = 1;
    size_t code_idx = 0;
    uint8_t code = 1;

    uint8_t encoded[512];
    while (read_idx < raw_len) {
        if (raw[read_idx] == 0) {
            encoded[code_idx] = code;
            code = 1;
            code_idx = write_idx++;
            read_idx++;
        } else {
            encoded[write_idx++] = raw[read_idx++];
            code++;
            if (code == 0xFF) {
                encoded[code_idx] = code;
                code = 1;
                code_idx = write_idx++;
            }
        }
    }
    encoded[code_idx] = code;

    for (size_t i = 0; i < write_idx; i++) {
        assert(s_uart_rx_head < UART_BUF_SIZE);
        s_uart_rx_fifo[s_uart_rx_head++] = encoded[i];
    }
    assert(s_uart_rx_head < UART_BUF_SIZE);
    s_uart_rx_fifo[s_uart_rx_head++] = 0x00;
}

/* Queue a corrupted frame (invalid CRC) */
static void queue_corrupted_cobs_frame(const uint8_t *payload, size_t payload_len) {
    uint32_t bad_crc = 0xBAD0DEAD;
    uint8_t raw[256];
    memcpy(raw, payload, payload_len);
    memcpy(&raw[payload_len], &bad_crc, 4);
    size_t raw_len = payload_len + 4;

    size_t read_idx = 0;
    size_t write_idx = 1;
    size_t code_idx = 0;
    uint8_t code = 1;

    uint8_t encoded[512];
    while (read_idx < raw_len) {
        if (raw[read_idx] == 0) {
            encoded[code_idx] = code;
            code = 1;
            code_idx = write_idx++;
            read_idx++;
        } else {
            encoded[write_idx++] = raw[read_idx++];
            code++;
            if (code == 0xFF) {
                encoded[code_idx] = code;
                code = 1;
                code_idx = write_idx++;
            }
        }
    }
    encoded[code_idx] = code;

    for (size_t i = 0; i < write_idx; i++) {
        assert(s_uart_rx_head < UART_BUF_SIZE);
        s_uart_rx_fifo[s_uart_rx_head++] = encoded[i];
    }
    assert(s_uart_rx_head < UART_BUF_SIZE);
    s_uart_rx_fifo[s_uart_rx_head++] = 0x00;
}

static void test_efuse_mock_primitives(void) {
    printf("[1/3] Testing eFuse Mock Primitives & OTP Invariants...\n");
    esp_efuse_mock_reset();

    /* 1. UID Read */
    uint8_t uid[16];
    size_t uid_len = 0;
    assert(esp_efuse_read_chip_uid(uid, sizeof(uid), &uid_len) == BOOT_OK);
    assert(uid_len == 6);
    assert(uid[0] == 0x60 && uid[1] == 0x55 && uid[2] == 0xF9);
    printf("  [PASS] read_chip_uid: %02X:%02X:%02X:%02X:%02X:%02X\n",
           uid[0], uid[1], uid[2], uid[3], uid[4], uid[5]);

    /* 2. Buffer bounds check */
    assert(esp_efuse_read_chip_uid(uid, 5, &uid_len) == BOOT_ERR_INVALID_ARG);
    assert(esp_efuse_read_chip_uid(NULL, sizeof(uid), &uid_len) == BOOT_ERR_INVALID_ARG);
    printf("  [PASS] read_chip_uid parameter validation\n");

    /* 3. Read default pubkey */
    uint8_t pubkey[32];
    assert(esp_efuse_read_pubkey(pubkey, sizeof(pubkey), 0) == BOOT_OK);
    assert(pubkey[0] == 0xd7 && pubkey[31] == 0x1a);
    printf("  [PASS] read_pubkey default slot 0\n");

    /* 4. Burn new pubkey to slot 1 */
    uint8_t new_key[32];
    memset(new_key, 0xA5, sizeof(new_key));
    assert(esp_efuse_burn_pubkey(new_key, sizeof(new_key), 1) == BOOT_OK);

    uint8_t read_back[32];
    assert(esp_efuse_read_pubkey(read_back, sizeof(read_back), 1) == BOOT_OK);
    assert(memcmp(read_back, new_key, 32) == 0);
    printf("  [PASS] burn_pubkey slot 1 & verified readback\n");

    /* 5. Degenerate key rejection & OTP overwrite check on key burn */
    uint8_t zero_key[32];
    memset(zero_key, 0x00, sizeof(zero_key));
    assert(esp_efuse_burn_pubkey(zero_key, sizeof(zero_key), 1) == BOOT_ERR_INVALID_ARG);

    uint8_t conflicting_key[32];
    memset(conflicting_key, 0x5A, sizeof(conflicting_key)); /* Tries to clear 0xA5 bits -> 0x5A */
    assert(esp_efuse_burn_pubkey(conflicting_key, sizeof(conflicting_key), 1) == BOOT_ERR_VERIFY);
    printf("  [PASS] burn_pubkey degenerate key & OTP anti-clear invariants hold\n");

    /* 6. DSLC monotonicity */
    uint8_t dslc_val = 0;
    size_t dslc_len = sizeof(dslc_val);
    assert(esp_efuse_read_dslc(&dslc_val, &dslc_len) == BOOT_OK);
    assert(dslc_val == 0x01);

    /* Setting more bits: 0x01 | 0x02 = 0x03 */
    uint8_t dslc_set = 0x03U;
    assert(esp_efuse_write_dslc(&dslc_set, 1U) == BOOT_OK);
    assert(esp_efuse_read_dslc(&dslc_val, &dslc_len) == BOOT_OK);
    assert(dslc_val == 0x03U);

    /* Attempting to clear bits: 0x03 -> 0x02 (missing bit 0) must fail */
    uint8_t dslc_clear = 0x02U;
    assert(esp_efuse_write_dslc(&dslc_clear, 1U) == BOOT_ERR_VERIFY);
    printf("  [PASS] write_dslc monotonicity (0->1 only) holds\n");

    /* 7. Monotonic counter */
    uint32_t ctr = 0;
    assert(esp_efuse_read_monotonic(&ctr) == BOOT_OK);
    assert(ctr == 10);
    assert(esp_efuse_advance_monotonic() == BOOT_OK);
    assert(esp_efuse_read_monotonic(&ctr) == BOOT_OK);
    assert(ctr == 11);
    printf("  [PASS] advance_monotonic increments counter (%u -> %u)\n", 10, ctr);

    /* 8. Protection and Secure Boot */
    assert(esp_efuse_set_protection_bits(0x00000006) == BOOT_OK);
    assert(esp_efuse_enable_secure_boot() == BOOT_OK);
    assert(esp_efuse_enable_flash_encryption() == BOOT_OK);
    printf("  [PASS] security protection bits & secure boot enabled\n");
}

static uint32_t s_lock_flash_calls = 0U;
static uint32_t s_last_lock_offset = 0U;
static uint32_t s_last_lock_size = 0U;
static uint32_t s_wal_init_calls = 0U;
static uint32_t s_wal_zeroize_calls = 0U;
static boot_status_t s_wal_init_result = BOOT_OK;

boot_status_t boot_journal_init(const boot_platform_t *platform) {
    (void)platform;
    s_wal_init_calls++;
    return s_wal_init_result;
}

void boot_journal_zeroize_secrets(void) {
    s_wal_zeroize_calls++;
}

static boot_status_t mock_lock_immutable_flash(uint32_t offset, uint32_t size) {
    if (size == 0U || UINT32_MAX - offset < size) {
        return BOOT_ERR_INVALID_ARG;
    }
    s_lock_flash_calls++;
    s_last_lock_offset = offset;
    s_last_lock_size = size;
    return BOOT_OK;
}

static void test_provisioning_protocol_loop(void) {
    printf("\n[2/3] Testing Factory Provisioning Protocol Flow...\n");
    esp_efuse_mock_reset();
    s_lock_flash_calls = 0U;
    s_last_lock_offset = 0U;
    s_last_lock_size = 0U;
    s_wal_init_calls = 0U;
    s_wal_zeroize_calls = 0U;
    s_wal_init_result = BOOT_OK;

    /* Prepare UART fifos */
    s_uart_rx_head = 0;
    s_uart_rx_tail = 0;
    s_uart_tx_len = 0;

    /* Build platform struct */
    keystore_hal_t mock_keystore = {
        .abi_version = TOOB_HAL_ABI_V3,
        .read_pubkey = esp_efuse_read_pubkey,
        .read_chip_uid = esp_efuse_read_chip_uid,
        .read_dslc = esp_efuse_read_dslc,
        .write_dslc = esp_efuse_write_dslc,
        .read_monotonic_counter = esp_efuse_read_monotonic,
        .advance_monotonic_counter = esp_efuse_advance_monotonic
    };

    provisioning_hal_t mock_prov = {
        .abi_version = TOOB_HAL_ABI_V3,
        .burn_pubkey = esp_efuse_burn_pubkey,
        .write_dslc = esp_efuse_write_dslc,
        .set_protection_bits = esp_efuse_set_protection_bits,
        .enable_secure_boot = esp_efuse_enable_secure_boot,
        .enable_flash_encryption = esp_efuse_enable_flash_encryption,
        .lock_immutable_flash = mock_lock_immutable_flash
    };

    boot_platform_t platform = {
        .console = &s_mock_console_hal,
        .keystore = &mock_keystore,
        .provisioning = &mock_prov,
        .wdt = NULL
    };

    /* 1. Queue command 0x06: PROV_CMD_READ_ID */
    uint8_t cmd_read_id[] = { PROV_CMD_READ_ID };
    queue_cobs_frame(cmd_read_id, sizeof(cmd_read_id));

    /* 2. Queue command 0x01: PROV_CMD_BURN_KEY (slot 0, 32 bytes) */
    uint8_t prod_root_key[32];
    for (size_t i = 0; i < 32; i++) prod_root_key[i] = (uint8_t)(0xC0 + i);

    uint8_t cmd_burn_key[34];
    cmd_burn_key[0] = PROV_CMD_BURN_KEY;
    cmd_burn_key[1] = 0x00; /* slot 0 */
    memcpy(&cmd_burn_key[2], prod_root_key, 32);
    queue_cobs_frame(cmd_burn_key, sizeof(cmd_burn_key));

    /* 3. Queue command 0x03: PROV_CMD_SET_PROTECTION */
    uint8_t cmd_prot[] = { PROV_CMD_SET_PROTECTION, 0x06, 0x00, 0x00, 0x00 }; /* bitmask = 6 */
    queue_cobs_frame(cmd_prot, sizeof(cmd_prot));

    /* 4. Queue command 0x04: PROV_CMD_ENABLE_SB */
    uint8_t cmd_sb[] = { PROV_CMD_ENABLE_SB };
    queue_cobs_frame(cmd_sb, sizeof(cmd_sb));

    /* 5. Queue command 0x05: PROV_CMD_ENABLE_FE */
    uint8_t cmd_fe[] = { PROV_CMD_ENABLE_FE };
    queue_cobs_frame(cmd_fe, sizeof(cmd_fe));

    /* 6. Queue command 0x07: PROV_CMD_LOCK_BOOT_FLASH (default 0-byte & explicit 8-byte LE) */
    uint8_t cmd_lock_default[] = { PROV_CMD_LOCK_BOOT_FLASH };
    queue_cobs_frame(cmd_lock_default, sizeof(cmd_lock_default));

    uint8_t cmd_lock_explicit[] = {
        PROV_CMD_LOCK_BOOT_FLASH,
        0x00, 0x10, 0x00, 0x00, /* offset = 0x00001000 */
        0x00, 0x80, 0x00, 0x00  /* size   = 0x00008000 */
    };
    queue_cobs_frame(cmd_lock_explicit, sizeof(cmd_lock_explicit));

    /* 7. Queue command 0x02: PROV_CMD_SET_DSLC (0x01 = PROVISIONED) */
    uint8_t cmd_dslc[] = { PROV_CMD_SET_DSLC, 0x01 };
    queue_cobs_frame(cmd_dslc, sizeof(cmd_dslc));

    /* 8. Queue command 0xFF: PROV_CMD_REBOOT */
    uint8_t cmd_reboot[] = { PROV_CMD_REBOOT };
    queue_cobs_frame(cmd_reboot, sizeof(cmd_reboot));

    /* Run provisioning loop with setjmp trap for reboot */
    uint8_t arena[ARENA_SIZE];
    s_halt_expected = true;
    if (setjmp(s_halt_jmp) == 0) {
        boot_provisioning_run(&platform, arena, sizeof(arena));
    }
    s_halt_expected = false;

    assert(s_last_halt_reason == BOOT_OK);
    printf("  [PASS] Provisioning loop completed successfully via PROV_CMD_REBOOT\n");

    /* Verify that the key was burned into slot 0 */
    uint8_t active_pubkey[32];
    assert(mock_keystore.read_pubkey(active_pubkey, 32, 0) == BOOT_OK);
    assert(memcmp(active_pubkey, prod_root_key, 32) == 0);
    printf("  [PASS] Root public key matches burned factory key\n");

    /* Verify that immutable boot flash lock hook was invoked for both default and explicit payloads */
    assert(s_lock_flash_calls == 2U);
    assert(s_last_lock_offset == 0x00001000U);
    assert(s_last_lock_size == 0x00008000U);
    printf("  [PASS] PROV_CMD_LOCK_BOOT_FLASH default & explicit 8B LE payloads verified\n");

    /* Verify that DSLC is now 0x01 after formatting genesis WAL and wiping secrets */
    assert(s_wal_init_calls == 1U);
    assert(s_wal_zeroize_calls == 1U);
    uint8_t final_dslc = 0;
    size_t dlen = 1;
    assert(mock_keystore.read_dslc(&final_dslc, &dlen) == BOOT_OK);
    assert(final_dslc == 0x01);
    printf("  [PASS] Genesis WAL formatted, secrets zeroized, and DSLC = PROVISIONED (0x01)\n");
}

static void test_provisioning_tamper_rejection(void) {
    printf("\n[3/3] Testing CRC Tamper Rejection, ABI v3 Check & Lock Bounds...\n");

    s_uart_rx_head = 0;
    s_uart_rx_tail = 0;
    s_uart_tx_len = 0;
    s_lock_flash_calls = 0U;
    s_wal_init_calls = 0U;
    s_wal_zeroize_calls = 0U;
    s_wal_init_result = BOOT_OK;

    keystore_hal_t mock_keystore = {
        .abi_version = TOOB_HAL_ABI_V3,
        .read_pubkey = esp_efuse_read_pubkey,
        .read_chip_uid = esp_efuse_read_chip_uid,
        .read_dslc = esp_efuse_read_dslc,
        .write_dslc = esp_efuse_write_dslc,
        .read_monotonic_counter = esp_efuse_read_monotonic,
        .advance_monotonic_counter = esp_efuse_advance_monotonic
    };

    provisioning_hal_t mock_prov = {
        .abi_version = TOOB_HAL_ABI_V3,
        .burn_pubkey = esp_efuse_burn_pubkey,
        .write_dslc = esp_efuse_write_dslc,
        .set_protection_bits = esp_efuse_set_protection_bits,
        .enable_secure_boot = esp_efuse_enable_secure_boot,
        .enable_flash_encryption = esp_efuse_enable_flash_encryption,
        .lock_immutable_flash = mock_lock_immutable_flash
    };

    boot_platform_t platform = {
        .console = &s_mock_console_hal,
        .keystore = &mock_keystore,
        .provisioning = &mock_prov,
        .wdt = NULL
    };

    /* 0. Verify wrong provisioning ABI version fails closed immediately */
    uint8_t arena[ARENA_SIZE];
    mock_prov.abi_version = TOOB_HAL_ABI_V2;
    s_halt_expected = true;
    s_last_halt_reason = BOOT_OK;
    if (setjmp(s_halt_jmp) == 0) {
        boot_provisioning_run(&platform, arena, sizeof(arena));
    }
    s_halt_expected = false;
    assert(s_last_halt_reason == BOOT_ERR_INVALID_ARG);
    mock_prov.abi_version = TOOB_HAL_ABI_V3;

    /* 1. Send corrupted CRC command */
    uint8_t cmd_bad_crc[] = { PROV_CMD_READ_ID };
    queue_corrupted_cobs_frame(cmd_bad_crc, sizeof(cmd_bad_crc));

    /* 2. Send unknown command opcode 0x77 */
    uint8_t cmd_unknown[] = { 0x77, 0x11, 0x22 };
    queue_cobs_frame(cmd_unknown, sizeof(cmd_unknown));

    /* 3. Send invalid PROV_CMD_LOCK_BOOT_FLASH payloads (size == 0, wrap overflow, bad len) */
    uint8_t cmd_lock_zero[] = {
        PROV_CMD_LOCK_BOOT_FLASH,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    queue_cobs_frame(cmd_lock_zero, sizeof(cmd_lock_zero));

    uint8_t cmd_lock_wrap[] = {
        PROV_CMD_LOCK_BOOT_FLASH,
        0x00, 0xF0, 0xFF, 0xFF, /* offset = 0xFFFFF000 */
        0x00, 0x20, 0x00, 0x00  /* size   = 0x00002000 (wraps u32) */
    };
    queue_cobs_frame(cmd_lock_wrap, sizeof(cmd_lock_wrap));

    uint8_t cmd_lock_badlen[] = { PROV_CMD_LOCK_BOOT_FLASH, 0x01, 0x02, 0x03 };
    queue_cobs_frame(cmd_lock_badlen, sizeof(cmd_lock_badlen));

    /* 3b. CRIT-31: Reject illegal DSLC values 0x00 (unprovisioned) and 0xFF (permanently locked) */
    uint8_t cmd_dslc_zero[] = { PROV_CMD_SET_DSLC, 0x00U };
    queue_cobs_frame(cmd_dslc_zero, sizeof(cmd_dslc_zero));
    uint8_t cmd_dslc_lock[] = { PROV_CMD_SET_DSLC, 0xFFU };
    queue_cobs_frame(cmd_dslc_lock, sizeof(cmd_dslc_lock));

    /* 4. Send valid reboot command to exit */
    uint8_t cmd_reboot[] = { PROV_CMD_REBOOT };
    queue_cobs_frame(cmd_reboot, sizeof(cmd_reboot));

    s_halt_expected = true;
    if (setjmp(s_halt_jmp) == 0) {
        boot_provisioning_run(&platform, arena, sizeof(arena));
    }
    s_halt_expected = false;

    assert(s_last_halt_reason == BOOT_OK);
    assert(s_lock_flash_calls == 0U);
    assert(s_wal_init_calls == 0U);
    assert(s_wal_zeroize_calls == 0U);
    printf("  [PASS] Corrupted CRC, ABI check, and invalid lock bounds handled safely\n");
}

static void test_provisioning_wal_init_fail_closed(void) {
    printf("\n[4/4] Testing Genesis WAL Failure Prevents DSLC Transition...\n");
    esp_efuse_mock_reset();
    s_uart_rx_head = 0;
    s_uart_rx_tail = 0;
    s_uart_tx_len = 0;
    s_wal_init_calls = 0U;
    s_wal_zeroize_calls = 0U;
    s_wal_init_result = BOOT_ERR_FLASH_HW;

    keystore_hal_t mock_keystore = {
        .abi_version = TOOB_HAL_ABI_V3,
        .read_pubkey = esp_efuse_read_pubkey,
        .read_chip_uid = esp_efuse_read_chip_uid,
        .read_dslc = esp_efuse_read_dslc,
        .write_dslc = esp_efuse_write_dslc,
        .read_monotonic_counter = esp_efuse_read_monotonic,
        .advance_monotonic_counter = esp_efuse_advance_monotonic
    };

    provisioning_hal_t mock_prov = {
        .abi_version = TOOB_HAL_ABI_V3,
        .burn_pubkey = esp_efuse_burn_pubkey,
        .write_dslc = esp_efuse_write_dslc,
        .set_protection_bits = esp_efuse_set_protection_bits,
        .enable_secure_boot = esp_efuse_enable_secure_boot,
        .enable_flash_encryption = esp_efuse_enable_flash_encryption,
        .lock_immutable_flash = mock_lock_immutable_flash
    };

    boot_platform_t platform = {
        .console = &s_mock_console_hal,
        .keystore = &mock_keystore,
        .provisioning = &mock_prov,
        .wdt = NULL
    };

    uint8_t initial_dslc = 0U;
    size_t dlen = 1U;
    assert(mock_keystore.read_dslc(&initial_dslc, &dlen) == BOOT_OK);

    uint8_t cmd_dslc_fail[] = { PROV_CMD_SET_DSLC, 0x03U };
    queue_cobs_frame(cmd_dslc_fail, sizeof(cmd_dslc_fail));
    uint8_t cmd_reboot[] = { PROV_CMD_REBOOT };
    queue_cobs_frame(cmd_reboot, sizeof(cmd_reboot));

    uint8_t arena[ARENA_SIZE];
    s_halt_expected = true;
    if (setjmp(s_halt_jmp) == 0) {
        boot_provisioning_run(&platform, arena, sizeof(arena));
    }
    s_halt_expected = false;

    assert(s_last_halt_reason == BOOT_OK);
    assert(s_wal_init_calls == 1U);
    assert(s_wal_zeroize_calls == 1U);
    uint8_t after_dslc = 0U;
    dlen = 1U;
    assert(mock_keystore.read_dslc(&after_dslc, &dlen) == BOOT_OK);
    assert(after_dslc == initial_dslc);
    s_wal_init_result = BOOT_OK;
    printf("  [PASS] Genesis WAL failure aborted DSLC write & wiped secrets\n");
}

int main(void) {
    printf("==================================================\n");
    printf("   Factory Provisioning & eFuse Unit Test Suite\n");
    printf("==================================================\n\n");

    test_efuse_mock_primitives();
    test_provisioning_protocol_loop();
    test_provisioning_tamper_rejection();
    test_provisioning_wal_init_fail_closed();

    printf("\n==================================================\n");
    printf("   ALL PROVISIONING TESTS PASSED\n");
    printf("==================================================\n");
    return 0;
}
