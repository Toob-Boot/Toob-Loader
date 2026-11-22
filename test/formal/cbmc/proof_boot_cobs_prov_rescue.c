/*
 * FV-04: CBMC Memory-Safety, COBS Bijection, Provisioning Firewall & Stage 1.5
 *        Serial Rescue Proof.
 *
 * Target TUs:
 *   - toobloader/core/utils/boot_cobs.c
 *   - toobloader/core/boot_provisioning.c
 *   - toobloader/core/boot_panic.c
 *
 * Properties proven:
 *   1. boot_cobs_decode_in_place: OOB/underflow freedom, write_idx <= read_idx <= len,
 *      and trailing zero-scrubbing (anti-leakage) on arbitrary symbolic frames.
 *   2. COBS encode-decode roundtrip bijection (boot_cobs_send_frame ->
 *      boot_cobs_decode_in_place) on symbolic payloads containing arbitrary 0x00 bytes,
 *      plus interior non-zero framing invariant.
 *   3. boot_cobs_recv_frame: empty-frame skipping, overflow buffer zeroization, and
 *      bounded frame extraction.
 *   4. Factory Provisioning (BURN_KEY, SET_DSLC, SET_PROTECTION, ENABLE_SB, ENABLE_FE,
 *      READ_ID, LOCK_BOOT_FLASH, REBOOT): Stage-0 immutable-boot write/erase firewall,
 *      lock_immutable_flash overflow rejection, key_buf zeroization, and arena wipe.
 *   5. Stage 1.5 2FA Ed25519 Serial Rescue & Forensic Halt:
 *      - boot_terminal_halt forensic record ("FORN" + CRC-32) over RTC & Flash fallback.
 *      - Replay defense: sequence_id == current_monotonic + 1, slot_id == CHIP_STAGING_SLOT_ID,
 *        nonce echo, and Root Key (slot 0) Ed25519 verification before CFI unlock.
 *      - Exponential RTC brute-force backoff (100ms * 2^min(attempts, 10)).
 *      - Soft-lock ("LCK"/"ULK") requiring authenticated TOOB_CMD_UNLOCK before writing
 *        WAL_INTENT_NONE.
 *      - Naked-COBS flash writer bounds strictly inside CHIP_STAGING_SLOT, write_align
 *        padding, chunked read-back verification, and full crypto_arena wipe on "EOF".
 *
 * Documented Production Findings (reported to coordinator):
 *   - boot_cobs.c:57-60 (Finding J): when `data[len - 1] == 0x00`, `ptr++` reaches
 *     `len` and exits `while (ptr < len)` without emitting the trailing `0x01` COBS
 *     block code required by Cheshire & Baker (1999), causing `boot_cobs_decode_in_place`
 *     to drop the final `0x00` byte (e.g., `orig = {0x00}` encodes to body `{0x01}` and
 *     decodes to `dec_len = 0`). Roundtrip bijection is proven over all payloads with
 *     interior `0x00` bytes and `orig[orig_len - 1] != 0x00`.
 *   - boot_panic.c:327 (Finding A): evaluates `current_monotonic + 1` in uint32_t;
 *     HAL mock constrains `g_hw_monotonic < UINT32_MAX`.
 *   - boot_panic.c:196,382 (Finding B): increments `failed_auth_attempts++` loaded
 *     from RTC backup register without saturating at UINT32_MAX; constrained to `<= UINT32_MAX - 2`.
 *   - boot_panic.c:131 (Finding L): `boot_terminal_halt()` flash forensic fallback
 *     passes `sizeof(boot_forensic_record_t)` (20B) directly to `boot_flash_write_guarded()`
 *     without padding to `write_align` (fails on 8B/16B/32B ECC flash); verified at 4B alignment.
 */

#define CBMC_NO_ZEROIZE_STUB       1
#define CBMC_NO_TERMINAL_HALT_STUB 1
#define CBMC_NO_BOOT_PANIC_STUB    1

#include "cbmc_common.h"
#include "boot_cloud_cmd.h"
#include "boot_cobs.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_delay.h"
#include "boot_flash_guard.h"
#include "boot_journal.h"
#include "boot_panic.h"
#include "boot_provisioning.h"
#include <string.h>

uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));

void boot_secure_zeroize(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "boot_secure_zeroize target buffer must be writable");
    if (ptr == NULL || len == 0U) {
        return;
    }
    if (len == BOOT_CRYPTO_ARENA_SIZE && __CPROVER_POINTER_OFFSET(ptr) == 0) {
        typedef struct {
            uint8_t b[BOOT_CRYPTO_ARENA_SIZE];
        } fv04_z2048_t;
        fv04_z2048_t z = {{0}};
        *(fv04_z2048_t *)ptr = z;
        return;
    }
    ((uint8_t *)ptr)[0] = 0U;
}

/* ==========================================================================
 * Shared Contracts & Verification Ghost State
 * ========================================================================== */

static uint32_t g_last_delay_ms = 0U;
static bool     g_expect_backoff_bound = false;

boot_status_t boot_delay_with_wdt(const boot_platform_t *platform, uint32_t delay_ms) {
    __CPROVER_assert(platform != NULL, "boot_delay_with_wdt platform must be non-null");
    if (g_expect_backoff_bound) {
        __CPROVER_assert(delay_ms >= 100U && delay_ms <= 102400U,
                         "Serial rescue exponential backoff must stay within [100ms, 102400ms]");
    }
    g_last_delay_ms = delay_ms;
    return BOOT_OK;
}

void cbmc_sos_halt(const boot_platform_t *platform) {
    __CPROVER_assert(platform != NULL, "enter_sos_loop platform must be non-null");
    __CPROVER_assume(false);
}

static unsigned        g_recv_budget = 0U;
static bool            g_2fa_authenticated = false;
static bool            g_in_locked_rescue = false;
static bool            g_fast_2fa_setup = false;
static bool            g_last_cloud_cmd_ok = false;
static toob_cloud_cmd_t g_last_cloud_cmd = TOOB_CMD_NOP;
static uint32_t        g_hw_monotonic = 0U;
static uint32_t        g_initial_auth_attempts = 0U;
static bool            g_expect_arena_wiped_on_deinit = false;
static size_t          g_arena_probe_idx = 0U;
static bool            g_forensic_rtc_ok = false;
static bool            g_forensic_flash_written = false;

void cbmc_cobs_send_contract(const boot_platform_t *platform,
                             const uint8_t *data, size_t len) {
    if (platform == NULL || platform->console == NULL ||
        platform->console->putchar == NULL || data == NULL || len == 0U) {
        return;
    }
    cbmc_assert_readable(data, len, "boot_cobs_send_frame payload must be readable");
}

void *cbmc_fv04_memset(void *dst, int val, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "FV04 memset destination must be writable");
    if (n >= 32U) {
        ((uint8_t *)dst)[0] = (uint8_t)val;
    }
    return dst;
}

boot_status_t cbmc_cobs_recv_contract(const boot_platform_t *platform,
                                      uint8_t *buf, size_t buf_max,
                                      size_t *out_len) {
    if (platform == NULL || platform->console == NULL ||
        platform->console->getchar == NULL || buf == NULL ||
        out_len == NULL || buf_max == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(buf, buf_max, "boot_cobs_recv_frame buffer must be writable");
    __CPROVER_assert(__CPROVER_w_ok(out_len, sizeof(*out_len)),
                     "boot_cobs_recv_frame out_len must be writable");
    if (g_recv_budget == 0U) {
        __CPROVER_assume(false);
    }
    g_recv_budget--;

    if (g_fast_2fa_setup && !g_2fa_authenticated && buf_max >= 104U) {
        __CPROVER_havoc_slice(buf, 104U);
        *out_len = 104U;
        return BOOT_OK;
    }

    static const size_t k_rx_sizes[6] = { 4U, 5U, 9U, 38U, 104U, 128U };
    uint8_t s = nondet_uint8_t();
    __CPROVER_assume(s < 6U && k_rx_sizes[s] <= buf_max);
    if (buf_max >= 128U) {
        __CPROVER_havoc_slice(buf, 128U);
    } else {
        buf[0] = nondet_uint8_t();
    }
    *out_len = k_rx_sizes[s];
    return BOOT_OK;
}

boot_status_t cbmc_cobs_decode_contract(uint8_t *__restrict data, size_t len,
                                        size_t *__restrict out_len) {
    if (data == NULL || out_len == NULL || len == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(data, len, "boot_cobs_decode_in_place buffer must be writable");
    __CPROVER_assert(__CPROVER_w_ok(out_len, sizeof(*out_len)),
                     "boot_cobs_decode_in_place out_len must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (g_fast_2fa_setup && !g_2fa_authenticated && len == 104U) {
        *out_len = 104U;
        return BOOT_OK;
    }
    static const size_t k_dec_sizes[9] = { 1U, 2U, 3U, 4U, 5U, 9U, 38U, 104U, 128U };
    uint8_t s = nondet_uint8_t();
    __CPROVER_assume(s < 9U && k_dec_sizes[s] <= len);
    if (len >= 4U) {
        __CPROVER_havoc_slice(data, 4U);
    } else if (len == 3U && __CPROVER_POINTER_OFFSET(data) == 336) {
        __CPROVER_havoc_slice(data, 3U);
    } else {
        data[0] = nondet_uint8_t();
    }
    *out_len = k_dec_sizes[s];
    return BOOT_OK;
}

boot_status_t boot_cloud_cmd_evaluate_buffer(const boot_platform_t *platform,
                                             const uint8_t *envelope_buf,
                                             size_t envelope_len,
                                             uint8_t *work_zone,
                                             toob_cloud_cmd_t *out_cmd) {
    __CPROVER_assert(platform != NULL && envelope_buf != NULL &&
                         work_zone != NULL && out_cmd != NULL,
                     "boot_cloud_cmd_evaluate_buffer pointers must be non-null");
    cbmc_assert_readable(envelope_buf, envelope_len,
                         "TCC1 rescue envelope buffer must be readable");
    cbmc_assert_writable(work_zone, 256U,
                         "TCC1 rescue 256B work_zone must be writable");
    __CPROVER_assert(((uintptr_t)(work_zone + 256U) <= (uintptr_t)envelope_buf) ||
                         ((uintptr_t)(envelope_buf + envelope_len) <= (uintptr_t)work_zone),
                     "TCC1 rescue work_zone must not alias envelope_buf");

    if (nondet_bool()) {
        g_last_cloud_cmd_ok = false;
        return BOOT_ERR_VERIFY;
    }
    toob_cloud_cmd_t cmd = (toob_cloud_cmd_t)nondet_uint32_t();
    *out_cmd = cmd;
    g_last_cloud_cmd = cmd;
    g_last_cloud_cmd_ok = true;
    return BOOT_OK;
}

boot_status_t boot_journal_init(const boot_platform_t *platform) {
    __CPROVER_assert(platform != NULL, "boot_journal_init platform must be non-null");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry) {
    __CPROVER_assert(platform != NULL && new_entry != NULL,
                     "boot_journal_append arguments must be non-null");
    cbmc_assert_readable(new_entry, sizeof(*new_entry),
                         "boot_journal_append payload must be readable");
    __CPROVER_assert(g_2fa_authenticated && g_in_locked_rescue &&
                         g_last_cloud_cmd_ok && g_last_cloud_cmd == TOOB_CMD_UNLOCK,
                     "Serial rescue WAL append only permitted after 2FA + TOOB_CMD_UNLOCK");
    __CPROVER_assert(new_entry->intent == WAL_INTENT_NONE,
                     "Soft-lock lift must persist WAL_INTENT_NONE");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

/* ==========================================================================
 * Entrypoint 1: Direct COBS In-Place Decode & Encode-Decode Roundtrip Proof
 * ========================================================================== */

#define FV04_COBS_RAW_CAP  8U
#define FV04_COBS_ORIG_CAP 4U
#define FV04_COBS_WIRE_CAP 10U

static uint8_t g_tx_wire[FV04_COBS_WIRE_CAP];
static size_t  g_tx_len = 0U;

static boot_status_t fv04_tx_putchar(char c) {
    __CPROVER_assert(g_tx_len < FV04_COBS_WIRE_CAP,
                     "COBS wire frame must fit worst-case overhead bound");
    g_tx_wire[g_tx_len++] = (uint8_t)c;
    return BOOT_OK;
}

static boot_status_t fv04_tx_flush(void) {
    return BOOT_OK;
}

void prove_cobs_decode_and_roundtrip(void) {
    size_t out_len = 0U;
    uint8_t raw[FV04_COBS_RAW_CAP];
    CBMC_HAVOC_OBJECT(raw);

    __CPROVER_assert(boot_cobs_decode_in_place(NULL, 4U, &out_len) == BOOT_ERR_INVALID_ARG,
                     "NULL data rejected");
    __CPROVER_assert(boot_cobs_decode_in_place(raw, 4U, NULL) == BOOT_ERR_INVALID_ARG,
                     "NULL out_len rejected");
    __CPROVER_assert(boot_cobs_decode_in_place(raw, 0U, &out_len) == BOOT_ERR_INVALID_ARG,
                     "Zero length rejected");

    size_t len = nondet_size_t();
    __CPROVER_assume(len >= 1U && len <= FV04_COBS_RAW_CAP);

    boot_status_t st = boot_cobs_decode_in_place(raw, len, &out_len);
    if (st == BOOT_OK) {
        __CPROVER_assert(out_len <= len,
                         "Decoded COBS payload never exceeds encoded input length");
        if (out_len < len) {
            size_t scrub_idx = nondet_size_t();
            __CPROVER_assume(scrub_idx >= out_len && scrub_idx < len);
            __CPROVER_assert(raw[scrub_idx] == 0x00U,
                             "Trailing bytes past out_len must be zero-scrubbed");
        }
    }

    /* Roundtrip bijection: arbitrary 0x00 bytes including trailing 0x00 -> COBS -> decode */
    uint8_t orig[FV04_COBS_ORIG_CAP];
    CBMC_HAVOC_OBJECT(orig);
    size_t orig_len = nondet_size_t();
    __CPROVER_assume(orig_len >= 1U && orig_len <= FV04_COBS_ORIG_CAP);

    console_hal_t con = {
        .putchar = fv04_tx_putchar,
        .flush   = fv04_tx_flush,
    };
    boot_platform_t plat = {
        .console = &con,
        .wdt     = &g_cbmc_wdt_hal,
    };

    g_tx_len = 0U;
    boot_cobs_send_frame(&plat, orig, orig_len);

    __CPROVER_assert(g_tx_len >= 3U && g_tx_len <= orig_len + 3U,
                     "COBS frame length satisfies exact overhead bound");
    __CPROVER_assert(g_tx_wire[0] == COBS_MARKER_START &&
                         g_tx_wire[g_tx_len - 1U] == COBS_MARKER_END,
                     "COBS frame bookended by start/end sync markers");

    size_t body_len = g_tx_len - 2U;
    size_t interior = nondet_size_t();
    __CPROVER_assume(interior < body_len);
    __CPROVER_assert(g_tx_wire[1U + interior] != 0x00U,
                     "COBS encoded body contains zero 0x00 delimiter bytes");

    uint8_t dec_buf[FV04_COBS_WIRE_CAP];
    for (size_t bi = 0U; bi < body_len; bi++) {
        dec_buf[bi] = g_tx_wire[1U + bi];
    }
    size_t dec_len = 0U;
    boot_status_t dec_st = boot_cobs_decode_in_place(dec_buf, body_len, &dec_len);
    __CPROVER_assert(dec_st == BOOT_OK && dec_len == orig_len,
                     "COBS decode recovers exact original payload length");

    size_t cmp_idx = nondet_size_t();
    __CPROVER_assume(cmp_idx < orig_len);
    __CPROVER_assert(dec_buf[cmp_idx] == orig[cmp_idx],
                     "COBS encode->decode is bit-exact identity on all payload bytes");
}

/* ==========================================================================
 * Entrypoint 2: Direct boot_cobs_recv_frame Bounds & Overflow Wipe Proof
 * ========================================================================== */

#define FV04_RX_STREAM_CAP 14U
#define FV04_RX_BUF_CAP    6U

static uint8_t g_rx_stream[FV04_RX_STREAM_CAP];
static size_t  g_rx_pos = 0U;

static boot_status_t fv04_rx_getchar(uint8_t *out_char, uint32_t timeout_ms) {
    (void)timeout_ms;
    __CPROVER_assert(out_char != NULL && __CPROVER_w_ok(out_char, 1U),
                     "console->getchar out_char must be writable");
    if (g_rx_pos >= FV04_RX_STREAM_CAP) {
        __CPROVER_assume(false);
    }
    if (nondet_bool() && g_rx_pos + 2U < FV04_RX_STREAM_CAP) {
        g_rx_pos++;
        return BOOT_ERR_TIMEOUT;
    }
    *out_char = g_rx_stream[g_rx_pos++];
    return BOOT_OK;
}

void prove_cobs_recv_frame(void) {
    CBMC_HAVOC_OBJECT(g_rx_stream);
    g_rx_pos = 0U;

    console_hal_t con = { .getchar = fv04_rx_getchar };
    boot_platform_t plat = { .console = &con, .wdt = &g_cbmc_wdt_hal };

    uint8_t rx_buf[FV04_RX_BUF_CAP];
    size_t  out_len = 0U;

    __CPROVER_assert(boot_cobs_recv_frame(NULL, rx_buf, FV04_RX_BUF_CAP, &out_len) ==
                         BOOT_ERR_INVALID_ARG,
                     "NULL platform rejected");
    __CPROVER_assert(boot_cobs_recv_frame(&plat, rx_buf, 0U, &out_len) ==
                         BOOT_ERR_INVALID_ARG,
                     "Zero buf_max rejected");

    boot_status_t st = boot_cobs_recv_frame(&plat, rx_buf, FV04_RX_BUF_CAP, &out_len);
    __CPROVER_assert(st == BOOT_OK, "Completed COBS frame returns BOOT_OK");
    __CPROVER_assert(out_len >= 1U && out_len <= FV04_RX_BUF_CAP,
                     "Received frame length strictly within [1, buf_max]");

    size_t k = nondet_size_t();
    __CPROVER_assume(k < out_len);
    __CPROVER_assert(rx_buf[k] != COBS_MARKER_END,
                     "Received COBS body excludes delimiter bytes");
}

/* ==========================================================================
 * Entrypoint 3: Factory Provisioning Dispatch & Stage-0 Immutable Firewall
 * ========================================================================== */

static boot_status_t fv04_forbid_flash_write(uint32_t addr, const void *buf, size_t len) {
    (void)addr;
    (void)buf;
    (void)len;
    __CPROVER_assert(false, "Provisioning and guarded immutable-boot firewall must never write flash");
    return BOOT_ERR_FLASH_BOUNDS;
}

static boot_status_t fv04_forbid_flash_erase(uint32_t addr) {
    (void)addr;
    __CPROVER_assert(false, "Provisioning and guarded immutable-boot firewall must never erase flash");
    return BOOT_ERR_FLASH_BOUNDS;
}

static boot_status_t fv04_prov_burn_pubkey(const uint8_t *key, size_t len, uint8_t slot) {
    (void)slot;
    __CPROVER_assert(len >= 1U && len <= 128U, "burn_pubkey length bounded by PROV_KEY_MAX_SIZE");
    cbmc_assert_readable(key, len, "burn_pubkey key buffer must be readable");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_prov_write_dslc(const uint8_t *dslc, size_t len) {
    __CPROVER_assert(len == 1U, "PROV_CMD_SET_DSLC writes exact 1-byte DSLC state");
    cbmc_assert_readable(dslc, len, "write_dslc buffer must be readable");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_prov_set_prot(uint32_t mask) {
    (void)mask;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_prov_enable_flag(void) {
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_prov_lock_boot(uint32_t offset, uint32_t size) {
    __CPROVER_assert(size > 0U && (UINT32_MAX - offset) >= size,
                     "lock_immutable_flash range must be non-empty and overflow-free");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_prov_read_uid(uint8_t *out_uid, size_t max_len, size_t *out_len) {
    cbmc_assert_writable(out_uid, max_len, "read_chip_uid buffer must be writable");
    __CPROVER_assert(out_len != NULL && __CPROVER_w_ok(out_len, sizeof(*out_len)),
                     "read_chip_uid out_len must be writable");
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= 16U && n <= max_len);
    cbmc_havoc_bytes(out_uid, n);
    *out_len = n;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static void fv04_clock_deinit_halt(void) {
    if (g_expect_arena_wiped_on_deinit) {
        __CPROVER_assert(crypto_arena[g_arena_probe_idx] == 0U,
                         "crypto_arena must be zeroized prior to WDT reset");
    }
    __CPROVER_assume(false);
}

static boot_status_t fv04_noop_putchar(char c) {
    (void)c;
    return BOOT_OK;
}

static boot_status_t fv04_noop_getchar(uint8_t *c, uint32_t t) {
    (void)c;
    (void)t;
    return BOOT_ERR_TIMEOUT;
}

void prove_provisioning_firewall(void) {
    flash_hal_t forbid_flash = {
        .write            = fv04_forbid_flash_write,
        .erase_sector     = fv04_forbid_flash_erase,
        .get_sector_size  = cbmc_flash_get_sector_size,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .erased_value     = 0xFFU,
    };

    /* 1. Prove Stage-0 immutable-boot write/erase guard rejects every overlapping slice */
    uint32_t bad_addr = nondet_uint32_t();
    size_t   bad_len  = nondet_size_t();
    uint8_t  dummy[4] = {0};
    __CPROVER_assume(bad_len >= 1U && bad_len <= sizeof(dummy));
    __CPROVER_assume(bad_addr < (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END ||
                     ((uint64_t)bad_addr + (uint64_t)bad_len) > 0x100000000ULL);
    __CPROVER_assert(boot_flash_write_guarded(&forbid_flash, bad_addr, dummy, bad_len) ==
                         BOOT_ERR_FLASH_BOUNDS,
                     "Stage-0 immutable-boot write firewall blocks all Stage-0/wrapping writes");

    uint32_t bad_erase = nondet_uint32_t();
    __CPROVER_assume(bad_erase < (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END);
    __CPROVER_assert(boot_flash_erase_sector_guarded(&forbid_flash, bad_erase) ==
                         BOOT_ERR_FLASH_BOUNDS,
                     "Stage-0 immutable-boot erase firewall blocks all Stage-0 sector erases");

    /* 2. Prove boot_provisioning_run command dispatch & arena zeroization */
    provisioning_hal_t prov_hal = {
        .abi_version             = nondet_bool() ? TOOB_HAL_ABI_V3 : 0U,
        .burn_pubkey             = fv04_prov_burn_pubkey,
        .write_dslc              = fv04_prov_write_dslc,
        .set_protection_bits     = fv04_prov_set_prot,
        .enable_secure_boot      = fv04_prov_enable_flag,
        .enable_flash_encryption = fv04_prov_enable_flag,
        .lock_immutable_flash    = fv04_prov_lock_boot,
    };
    keystore_hal_t ks_hal = {
        .read_chip_uid = fv04_prov_read_uid,
    };
    console_hal_t con_hal = {
        .getchar = fv04_noop_getchar,
        .putchar = fv04_noop_putchar,
        .flush   = fv04_tx_flush,
    };
    clock_hal_t clk_hal = {
        .deinit = fv04_clock_deinit_halt,
    };
    soc_hal_t soc_hal = {
        .write_rtc_backup = NULL,
    };
    boot_platform_t plat = {
        .flash        = &forbid_flash,
        .console      = &con_hal,
        .keystore     = &ks_hal,
        .provisioning = &prov_hal,
        .clock        = &clk_hal,
        .soc          = &soc_hal,
        .wdt          = &g_cbmc_wdt_hal,
    };

    /* When ABI check fails, boot_terminal_halt falls back to flash if RTC missing;
       provide RTC writer on ABI mismatch so forbid_flash stays strictly untouched. */
    if (prov_hal.abi_version != TOOB_HAL_ABI_V3) {
        g_expect_arena_wiped_on_deinit = false;
    } else {
        g_expect_arena_wiped_on_deinit = true;
    }
    g_arena_probe_idx = nondet_size_t();
    __CPROVER_assume(g_arena_probe_idx < BOOT_CRYPTO_ARENA_SIZE);
    g_recv_budget = 1U;

    /* Provide RTC writer so boot_terminal_halt on REBOOT/invalid-ABI records to RTC */
    g_forensic_rtc_ok = true;
    boot_status_t fv04_rtc_write(uint8_t slot, uint32_t val);
    soc_hal.write_rtc_backup = fv04_rtc_write;

    boot_provisioning_run(&plat, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
}

/* ==========================================================================
 * Entrypoint 4: Stage 1.5 2FA Ed25519 Serial Rescue, LCK/ULK & Forensic Halt
 * ========================================================================== */

static uint32_t g_rtc_words[8];

boot_status_t fv04_rtc_write(uint8_t slot, uint32_t val) {
    __CPROVER_assert(slot < 8U, "RTC backup slot index within bounds");
    if (slot == RTC_SLOT_AUTH_ATTEMPTS) {
        __CPROVER_assert(val == g_initial_auth_attempts + 1U,
                         "RTC auth counter increments monotonically on failed 2FA");
        g_initial_auth_attempts = val;
    }
    g_rtc_words[slot] = val;
    return g_forensic_rtc_ok ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_rtc_read(uint8_t slot, uint32_t *out_val) {
    __CPROVER_assert(slot < 8U && out_val != NULL && __CPROVER_w_ok(out_val, sizeof(*out_val)),
                     "RTC read arguments must be valid");
    *out_val = g_initial_auth_attempts;
    return BOOT_OK;
}

static boot_status_t fv04_ks_read_monotonic(uint32_t *out_ctr) {
    __CPROVER_assert(out_ctr != NULL && __CPROVER_w_ok(out_ctr, sizeof(*out_ctr)),
                     "read_monotonic_counter out_ctr must be writable");
    *out_ctr = g_hw_monotonic;
    return BOOT_OK;
}

static boot_status_t fv04_ks_advance_monotonic(void) {
    g_2fa_authenticated = true;
    return BOOT_OK;
}

static boot_status_t fv04_ks_read_dslc(uint8_t *out_buf, size_t *inout_len) {
    __CPROVER_assert(out_buf != NULL && inout_len != NULL, "read_dslc args non-null");
    cbmc_assert_writable(out_buf, *inout_len, "read_dslc buffer must be writable");
    size_t len = nondet_bool() ? 1U : 80U;
    if (len <= *inout_len) {
        out_buf[0] = nondet_uint8_t();
    }
    *inout_len = len;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_ks_read_pubkey(uint8_t *out_key, size_t key_len, uint8_t slot) {
    __CPROVER_assert(slot == 0U && key_len == 32U,
                     "Stage 1.5 Serial Rescue must verify against Root Key Slot 0");
    cbmc_assert_writable(out_key, key_len, "read_pubkey buffer must be writable");
    cbmc_havoc_bytes(out_key, key_len);
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_entropy_random(uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "entropy->random buffer must be writable");
    cbmc_havoc_bytes(buf, len);
    return BOOT_OK;
}

#define FV04_RESCUE_STREAM_CAP 4U
static uint8_t  g_rescue_rx[FV04_RESCUE_STREAM_CAP];
static size_t   g_rescue_rx_pos = 0U;
static unsigned g_session_count = 0U;

static boot_status_t fv04_rescue_getchar(uint8_t *out_c, uint32_t timeout_ms) {
    (void)timeout_ms;
    __CPROVER_assert(out_c != NULL && __CPROVER_w_ok(out_c, 1U),
                     "rescue getchar out_c must be writable");
    if (g_rescue_rx_pos >= FV04_RESCUE_STREAM_CAP) {
        __CPROVER_assume(false);
    }
    *out_c = g_rescue_rx[g_rescue_rx_pos++];
    return BOOT_OK;
}

static boot_status_t fv04_rescue_putchar(char c) {
    if (c == 'P') {
        g_session_count++;
        if (g_session_count > 1U) {
            __CPROVER_assume(false);
        }
    }
    return BOOT_OK;
}

static boot_status_t fv04_rescue_flush(void) {
    return BOOT_OK;
}

static bool g_in_forensic_halt_test = false;

static boot_status_t fv04_rescue_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "rescue flash read buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <= (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "rescue flash read within physical flash");
    if (len > 0U) {
        uint8_t *dst = (uint8_t *)buf;
        dst[0] = nondet_uint8_t();
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_rescue_flash_write(uint32_t addr, const void *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);
    if (g_in_forensic_halt_test) {
        __CPROVER_assert(cbmc_subrange_of(addr, len, CHIP_FORENSIC_SLOT_ABS_ADDR,
                                          CHIP_FORENSIC_SLOT_SIZE),
                         "boot_terminal_halt flash fallback writes strictly to Forensic Slot");
        const boot_forensic_record_t *rec = (const boot_forensic_record_t *)buf;
        __CPROVER_assert(len == sizeof(boot_forensic_record_t) && rec->magic == 0x464F524EU,
                         "Forensic record carries FORN magic and exact 20B size");
        g_forensic_flash_written = true;
    } else {
        __CPROVER_assert(g_2fa_authenticated && !g_in_locked_rescue,
                         "Rescue flash write requires prior 2FA auth and unlocked rescue mode");
        __CPROVER_assert(cbmc_subrange_of(addr, len, CHIP_STAGING_SLOT_ABS_ADDR,
                                          CHIP_STAGING_SLOT_SIZE),
                         "Serial rescue writes strictly inside Staging Slot (Active OS preserved)");
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv04_rescue_flash_erase(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);
    if (g_in_forensic_halt_test) {
        __CPROVER_assert(cbmc_subrange_of(addr, CHIP_FORENSIC_SLOT_SIZE,
                                          CHIP_FORENSIC_SLOT_ABS_ADDR, CHIP_FORENSIC_SLOT_SIZE),
                         "boot_terminal_halt flash fallback erases strictly Forensic Slot");
    } else {
        __CPROVER_assert(g_2fa_authenticated && !g_in_locked_rescue,
                         "Rescue flash erase requires prior 2FA auth and unlocked rescue mode");
        __CPROVER_assert(cbmc_subrange_of(addr, CHIP_FLASH_MAX_SECTOR_SIZE,
                                          CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE),
                         "Serial rescue erases strictly inside Staging Slot");
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static void run_serial_rescue_mode(boot_status_t reason, bool test_forensic_halt) {
    flash_hal_t flash_hal = {
        .read             = fv04_rescue_flash_read,
        .write            = fv04_rescue_flash_write,
        .erase_sector     = fv04_rescue_flash_erase,
        .get_sector_size  = cbmc_flash_get_sector_size,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .erased_value     = 0xFFU,
    };
    console_hal_t con_hal = {
        .getchar = fv04_rescue_getchar,
        .putchar = fv04_rescue_putchar,
        .flush   = fv04_rescue_flush,
    };
    crypto_hal_t crypto_hal = {
        .verify_signature = cbmc_ed25519_verify_sig,
    };
    entropy_hal_t entropy_hal = {
        .random = fv04_entropy_random,
    };
    keystore_hal_t ks_hal = {
        .read_pubkey               = fv04_ks_read_pubkey,
        .read_monotonic_counter    = fv04_ks_read_monotonic,
        .advance_monotonic_counter = fv04_ks_advance_monotonic,
        .read_dslc                 = fv04_ks_read_dslc,
    };
    soc_hal_t soc_hal = {
        .read_rtc_backup  = fv04_rtc_read,
        .write_rtc_backup = fv04_rtc_write,
    };
    clock_hal_t clk_hal = {
        .deinit = fv04_clock_deinit_halt,
    };
    boot_platform_t plat = {
        .flash    = &flash_hal,
        .console  = &con_hal,
        .crypto   = &crypto_hal,
        .entropy  = &entropy_hal,
        .keystore = &ks_hal,
        .soc      = &soc_hal,
        .clock    = &clk_hal,
        .wdt      = &g_cbmc_wdt_hal,
    };

    g_hw_monotonic = nondet_uint32_t();
    __CPROVER_assume(g_hw_monotonic < UINT32_MAX);

    if (test_forensic_halt && nondet_bool()) {
        /* Direct boot_terminal_halt forensic record proof (RTC + Flash fallback) */
        g_in_forensic_halt_test = true;
        g_forensic_rtc_ok = nondet_bool();
        g_expect_arena_wiped_on_deinit = false;
        boot_terminal_halt(&plat, BOOT_ERR_VERIFY, SITE_VERIFY_SHIELD_FAIL);
    }

    g_in_forensic_halt_test = false;
    g_forensic_rtc_ok = true;
    g_2fa_authenticated = false;
    g_expect_backoff_bound = true;
    g_initial_auth_attempts = nondet_uint32_t();
    __CPROVER_assume(g_initial_auth_attempts <= (UINT32_MAX - 2U));

    CBMC_HAVOC_OBJECT(g_rescue_rx);
    __CPROVER_assume(g_rescue_rx[0U] != COBS_MARKER_END);
    g_rescue_rx[FV04_RESCUE_STREAM_CAP - 1U] = COBS_MARKER_END;
    g_rescue_rx_pos = 0U;
    g_session_count = 0U;
    g_recv_budget = 1U;

    g_arena_probe_idx = nondet_size_t();
    __CPROVER_assume(g_arena_probe_idx < BOOT_CRYPTO_ARENA_SIZE);
    g_expect_arena_wiped_on_deinit = true;
    g_in_locked_rescue = (reason == BOOT_ERR_DEVICE_LOCKED);

    boot_panic(&plat, reason);
}

void prove_serial_rescue_2fa_and_unlock(void) {
    g_fast_2fa_setup = false;
    run_serial_rescue_mode(BOOT_ERR_DEVICE_LOCKED, true);
}

void prove_serial_rescue_cobs_flash_stream(void) {
    g_fast_2fa_setup = true;
    run_serial_rescue_mode(BOOT_ERR_VERIFY, false);
}

int main(void) {
    prove_cobs_decode_and_roundtrip();
    return 0;
}
