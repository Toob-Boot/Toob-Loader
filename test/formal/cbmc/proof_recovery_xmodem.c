/*
 * FV-05: CBMC Memory-Safety, XMODEM-CRC Streaming, Split-Trailer Locator &
 *        Active-OS Slot Preservation Proof for Recovery OS.
 *
 * Target TUs:
 *   - recovery/main.c
 *   - recovery/recovery_port.c
 *   - sdk/libtoob/{toob_ota.c,toob_handoff.c,toob_mailbox.c,toob_update.c,toob_confirm.c}
 *
 * Parameterized across:
 *   - TOOB_TRANSPORT_PROVIDER in {TOOB_TRANSPORT_SWAPSCRATCH, TOOB_TRANSPORT_POINTER}
 *
 * Properties proven:
 *   1. XMODEM-CRC state machine memory safety, sequence/complement/CRC-16 gating,
 *      duplicate-block ACK idempotence, NAK recovery, and CAN abort.
 *   2. Zero OOB across rx_stage.manifest_buf[640] and rx_stage.tail_window[256]
 *      across short (<640B), exact (640B), and multi-block (>640B) streams + EOT.
 *   3. Exact 16-byte toob_tbm1_trailer_locator_t backwards scan across the 256B
 *      two-block sliding window (catching trailers split across 128B XMODEM block
 *      boundaries) + toob_ota_trim_total_size() + cumulative mailbox finalize &
 *      toob_recovery_resolved().
 *   4. Strict preservation of the active OS slot under both SWAPSCRATCH (writes/erases
 *      confined to Staging + Mailbox) and POINTER (active_slot==0 -> Staging only;
 *      active_slot==1 -> App Slot A only; active_slot>1 -> fail-closed trap with zero
 *      flash writes/erases).
 *   5. Fail-fast get_sector_size() enforcement, WDT-sliced recovery_serial_getchar(),
 *      and Stage-0 immutable-boot firewall in recovery_port.c.
 */

#define CBMC_NO_TERMINAL_HALT_STUB 1
#define CBMC_NO_BOOT_PANIC_STUB    1

#include "cbmc_common.h"
#include "boot_main.h"
#include "boot_tbm1.h"
#include "libtoob.h"
#include "recovery_port.h"
#include "toob_internal.h"
#include <string.h>

extern boot_status_t boot_main(const boot_platform_t *platform,
                               boot_target_config_t *target,
                               const uint32_t seal_key[4]);

/* ==========================================================================
 * Shared Contracts & Security Ghost State
 * ========================================================================== */

static uint32_t g_flash_writes = 0U;
static uint32_t g_flash_erases = 0U;
static uint8_t  g_expected_active_slot = 0U;
static bool     g_handoff_valid_boot = false;
static bool     g_run_port_unit_on_reboot = false;
static bool     g_force_bad_sector_size = false;
static size_t   g_forced_sector_size = 0U;

void cbmc_hardware_trap_halt(void) {
    __CPROVER_assert(g_flash_writes == 0U && g_flash_erases == 0U,
                     "Fail-closed TOOB_TRAP() must halt before any flash write or erase");
    __CPROVER_assume(false);
}

toob_status_t cbmc_toob_ct_memcmp_contract(const uint8_t *a,
                                           const uint8_t *b,
                                           size_t len) {
    if (len == 0U) {
        return TOOB_ERR_VERIFY;
    }
    cbmc_assert_readable(a, len, "toob_ct_memcmp_glitch_safe buffer a must be readable");
    cbmc_assert_readable(b, len, "toob_ct_memcmp_glitch_safe buffer b must be readable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_VERIFY;
}

uint32_t toob_lib_crc32(const uint8_t *data, size_t length) {
    cbmc_assert_readable(data, length, "toob_lib_crc32 input slice must be readable");
    uint32_t c = nondet_uint32_t();
    return (length == 12U) ? (c & 0x0FFFFFFFU) : c;
}

void cbmc_snapshot_handoff_rec(toob_handoff_t *dst) {
    cbmc_assert_writable(dst, sizeof(*dst), "_volatile_snapshot_handoff dst must be writable");
    *dst = toob_handoff_state;
}

void cbmc_snapshot_resume_rec(toob_ota_resume_state_t *dst) {
    cbmc_assert_writable(dst, sizeof(*dst), "_volatile_snapshot_resume dst must be writable");
    *dst = g_toob_ota_resume_state;
}

void cbmc_ota_ctx_reset_rec(toob_ota_ctx_t *ctx) {
    cbmc_assert_writable(ctx, sizeof(*ctx), "_ctx_reset ctx must be writable");
    *ctx = (toob_ota_ctx_t){0};
}

toob_status_t cbmc_fv05_get_handoff_contract(toob_handoff_t *out_handoff) {
    if (out_handoff == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(out_handoff, sizeof(*out_handoff), "toob_get_handoff out writable");
    if (!g_handoff_valid_boot) {
        return TOOB_ERR_VERIFY;
    }
    *out_handoff = toob_handoff_state;
    return TOOB_OK;
}

toob_status_t cbmc_fv05_mailbox_put_contract(toob_req_t req, uint32_t tbm1_addr, uint64_t nonce) {
    (void)tbm1_addr;
    (void)nonce;
    if (req == TOOB_REQ_NONE || (req & (toob_req_t)(~TOOB_REQ_ALL_MASK)) != 0U) {
        return TOOB_ERR_INVALID_ARG;
    }
    toob_mailbox_t mbx = {0};
    toob_status_t er = toob_os_flash_erase(CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SLOT_SIZE);
    if (er != TOOB_OK) {
        return er;
    }
    return toob_os_flash_write(CHIP_MAILBOX_ABS_ADDR, (const uint8_t *)&mbx, sizeof(mbx));
}

void cbmc_fv05_zeroize_fast(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "toob_secure_zeroize target buffer must be writable");
    if (ptr != NULL && len > 0U) {
        ((uint8_t *)ptr)[0] = 0U;
    }
}

void *cbmc_fv05_memset(void *dst, int val, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "memset destination must be writable");
    if (n == 640U && val == 0 && __CPROVER_POINTER_OFFSET(dst) == 0) {
        typedef struct {
            uint8_t b[640];
        } fv05_z640_t;
        fv05_z640_t z = {{0}};
        *(fv05_z640_t *)dst = z;
        return dst;
    }
    ((uint8_t *)dst)[0] = (uint8_t)val;
    return dst;
}

void cbmc_recovery_print_noop(const char *str) {
    __CPROVER_assert(str != NULL && __CPROVER_r_ok(str, 1U),
                     "recovery_serial_print string must be non-null");
}

static bool     g_deterministic_framing = false;
static bool     g_head_tbm1_mode        = false;
static bool     g_forbid_trailer_magic  = false;
static uint8_t  g_trailer_case          = 0U;
static toob_tbm1_trailer_locator_t g_cand_loc;
static uint8_t  g_det_pkt_seq           = 0U;
static uint16_t g_det_last_crc          = 0U;

uint16_t cbmc_crc16_ccitt_contract(const uint8_t *data, size_t length) {
    cbmc_assert_readable(data, length, "crc16_ccitt payload must be readable");
    if (g_deterministic_framing) {
        return g_det_last_crc;
    }
    return nondet_uint16_t();
}

toob_status_t cbmc_fv05_flush_buffer_contract(toob_ota_ctx_t *ctx, uint32_t write_len) {
    __CPROVER_assert(ctx != NULL && __CPROVER_w_ok(ctx, sizeof(*ctx)),
                     "_flush_buffer ctx must be writable");
    if (write_len == 0U || write_len > TOOB_OTA_BUF_SIZE || ctx->bytes_queued < ctx->buf_len) {
        return TOOB_ERR_INVALID_ARG;
    }
    uint32_t flushed_so_far = ctx->bytes_queued - ctx->buf_len;
    if (ctx->write_cursor < flushed_so_far) {
        return TOOB_ERR_STATE;
    }
    uint32_t target_addr = ctx->write_cursor - flushed_so_far;
    if (ctx->erased_sectors == 0U) {
        toob_status_t er = toob_os_flash_erase(target_addr, CHIP_FLASH_MAX_SECTOR_SIZE);
        if (er != TOOB_OK) {
            return er;
        }
        ctx->erased_sectors = 1U;
    }
    if ((uint64_t)(ctx->write_cursor - target_addr) + (uint64_t)write_len > 0x2000ULL) {
        return TOOB_ERR_FLASH;
    }
    toob_status_t wr = toob_os_flash_write(ctx->write_cursor, ctx->align_buf, write_len);
    if (wr != TOOB_OK) {
        return wr;
    }
    ctx->write_cursor += write_len;
    return TOOB_OK;
}

toob_status_t cbmc_fv05_ota_process_chunk_contract(toob_ota_ctx_t *ctx,
                                                   const uint8_t *chunk,
                                                   uint32_t len) {
    enum {
        FV05_OTA_RECEIVING = 0x5AU,
        FV05_OTA_DONE      = 0xA5U,
        FV05_OTA_ERROR     = 0xFFU
    };
    if (ctx == NULL || ctx->state != FV05_OTA_RECEIVING ||
        chunk == NULL || len == 0U) {
        return TOOB_ERR_INVALID_ARG;
    }
    cbmc_assert_readable(chunk, len, "toob_ota_process_chunk input slice must be readable");
    if (len > (ctx->total_size - ctx->bytes_queued)) {
        return TOOB_ERR_INVALID_ARG;
    }
    uint32_t flushed_before = ctx->bytes_queued - ctx->buf_len;
    uint32_t target_addr = ctx->write_cursor - flushed_before;
    ctx->bytes_queued += len;
    uint32_t total_avail = ctx->buf_len + len;
    uint32_t flushes = total_avail / TOOB_OTA_BUF_SIZE;
    ctx->buf_len = total_avail % TOOB_OTA_BUF_SIZE;
    if (flushes > 0U) {
        if (ctx->erased_sectors == 0U) {
            toob_status_t er = toob_os_flash_erase(target_addr, CHIP_FLASH_MAX_SECTOR_SIZE);
            if (er != TOOB_OK) {
                ctx->state = FV05_OTA_ERROR;
                return er;
            }
            ctx->erased_sectors = 1U;
        }
        uint32_t write_bytes = flushes * TOOB_OTA_BUF_SIZE;
        toob_status_t wr = toob_os_flash_write(ctx->write_cursor, chunk,
                                               TOOB_OTA_BUF_SIZE <= len ? TOOB_OTA_BUF_SIZE : CHIP_FLASH_WRITE_ALIGNMENT);
        if (wr != TOOB_OK) {
            ctx->state = FV05_OTA_ERROR;
            return wr;
        }
        ctx->write_cursor += write_bytes;
    }
    if (ctx->bytes_queued == ctx->total_size) {
        ctx->state = FV05_OTA_DONE;
    }
    return TOOB_OK;
}

void *cbmc_fv05_memcpy(void *dst, const void *src, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "FV05 memcpy dst must be writable");
    cbmc_assert_readable(src, n, "FV05 memcpy src must be readable");
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (n == 4U) {
        cbmc_cpy4(d, s);
    } else if (n == 16U) {
        cbmc_cpy16(d, s);
    } else if (n == 44U) {
        cbmc_cpy32(d, s); cbmc_cpy4(d + 32U, s + 32U); cbmc_cpy4(d + 36U, s + 36U); cbmc_cpy4(d + 40U, s + 40U);
    } else if (n == 128U) {
        cbmc_cpy64(d, s); cbmc_cpy64(d + 64U, s + 64U);
    } else {
        d[0] = s[0];
    }
    return dst;
}

void *cbmc_fv05_memmove(void *dst, const void *src, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "FV05 memmove dst must be writable");
    cbmc_assert_readable(src, n, "FV05 memmove src must be readable");
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (n == 128U) {
        uint8_t tmp[128];
        cbmc_cpy64(tmp, s); cbmc_cpy64(tmp + 64U, s + 64U);
        cbmc_cpy64(d, tmp); cbmc_cpy64(d + 64U, tmp + 64U);
    } else if (n == 256U) {
        uint8_t tmp[256];
        cbmc_cpy64(tmp, s); cbmc_cpy64(tmp + 64U, s + 64U);
        cbmc_cpy64(tmp + 128U, s + 128U); cbmc_cpy64(tmp + 192U, s + 192U);
        cbmc_cpy64(d, tmp); cbmc_cpy64(d + 64U, tmp + 64U);
        cbmc_cpy64(d + 128U, tmp + 128U); cbmc_cpy64(d + 192U, tmp + 192U);
    } else {
        d[0] = s[0];
    }
    return dst;
}

toob_status_t cbmc_xmodem_read_bytes_contract(uint8_t *buf, uint32_t len, uint32_t timeout_ms) {
    (void)timeout_ms;
    cbmc_assert_writable(buf, len, "XMODEM read_bytes destination must be writable");
    if (!g_run_port_unit_on_reboot && !g_deterministic_framing && nondet_bool()) {
        return TOOB_ERR_TIMEOUT;
    }
    if (g_run_port_unit_on_reboot && len == 132U) {
        /* Scalar zeroing enables symex constant-folding across the 128B crc16_ccitt loop */
        cbmc_set64(buf, 0U);
        cbmc_set64(buf + 64U, 0U);
        cbmc_set4(buf + 128U, 0U);
        buf[0] = 0x02U;
        buf[1] = 0x00U;
        buf[2] = nondet_uint8_t();
        buf[3] = nondet_uint8_t();
        buf[130] = nondet_uint8_t();
        buf[131] = nondet_uint8_t();
    } else if (g_deterministic_framing && len == 132U) {
        typedef struct {
            uint8_t b[132];
        } fv05_z132_t;
        fv05_z132_t z132 = {{0}};
        *(fv05_z132_t *)buf = z132;
        g_det_pkt_seq++;
        buf[0] = g_det_pkt_seq;
        buf[1] = (uint8_t)(0xFFU - g_det_pkt_seq);
        if (g_head_tbm1_mode) {
            if (g_det_pkt_seq == 1U) {
                __CPROVER_havoc_slice(&buf[2], 128U);
                if (nondet_bool()) {
                    uint32_t hdr_magic = TBM1_MAGIC;
                    memcpy(&buf[2], &hdr_magic, sizeof(hdr_magic));
                } else {
                    uint32_t m = 0U;
                    memcpy(&m, &buf[2], sizeof(m));
                    __CPROVER_assume(m != TOOB_MAGIC_HEADER);
                }
            } else {
                buf[2]   = nondet_uint8_t();
                buf[129] = nondet_uint8_t();
            }
        } else if (g_det_pkt_seq == 1U) {
            uint32_t hdr_magic = TOOB_MAGIC_HEADER;
            memcpy(&buf[2], &hdr_magic, sizeof(hdr_magic));
        } else if (g_det_pkt_seq == 5U) {
            if (g_trailer_case == 0U) {
                /* First 8 bytes of 16B trailer at end of block 5 (tail_window[120..127]) */
                memcpy(&buf[122], &g_cand_loc, 8U);
            }
        } else if (g_det_pkt_seq == 6U) {
            if (g_trailer_case == 0U) {
                /* Remaining 8 bytes of split trailer at start of block 6 (tail_window[128..135]) + 0x1A pad */
                memcpy(&buf[2], ((const uint8_t *)&g_cand_loc) + 8U, 8U);
                buf[10] = 0x1AU;
            } else if (g_trailer_case == 1U) {
                /* Odd unaligned trailer at tail_window[239..254] + 1B 0x1A XMODEM pad */
                memcpy(&buf[113], &g_cand_loc, 16U);
                buf[129] = 0x1AU;
            } else {
                /* Exact end-of-stream trailer at tail_window[240..255] */
                memcpy(&buf[114], &g_cand_loc, 16U);
            }
        }
        g_det_last_crc = (uint16_t)(((uint16_t)buf[130] << 8U) | buf[131]);
    } else {
        cbmc_havoc_bytes(buf, len);
        if (g_forbid_trailer_magic && len == 132U) {
            uint32_t m = 0U;
            memcpy(&m, &buf[2], sizeof(m));
            __CPROVER_assume(m != TOOB_MAGIC_HEADER);
        }
    }
    return TOOB_OK;
}

/* ==========================================================================
 * Flash & Console HAL Oracles Enforcing Active-OS Slot Preservation
 * ========================================================================== */

static bool fv05_allowed_image_target(uint32_t addr, size_t len) {
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    __CPROVER_assert(g_handoff_valid_boot && g_expected_active_slot <= 1U,
                     "POINTER recovery flash mutation requires validated active_slot in {0, 1}");
    if (g_expected_active_slot == 0U) {
        /* Slot A (App) is active -> only Slot B (Staging) may be erased/written */
        return cbmc_subrange_of(addr, len, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE);
    }
    /* Slot B (Staging) is active -> only Slot A (App) may be erased/written */
    return cbmc_subrange_of(addr, len, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE);
#else
    /* Fixed-staging providers -> Active App Slot A is strictly untouchable */
    __CPROVER_assert(g_handoff_valid_boot,
                     "Recovery flash mutation requires validated Recovery OS handoff");
    return cbmc_subrange_of(addr, len, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE);
#endif
}

static boot_status_t fv05_flash_get_sector_size(uint32_t addr, size_t *out_size) {
    if (g_force_bad_sector_size) {
        if (nondet_bool()) {
            return BOOT_ERR_FLASH_BOUNDS;
        }
        *out_size = g_forced_sector_size;
        return BOOT_OK;
    }
    return cbmc_flash_get_sector_size(addr, out_size);
}

static boot_status_t fv05_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "recovery flash read destination must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <= (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "recovery flash read within physical flash");
    if (len > 0U) {
        if (cbmc_subrange_of(addr, len, CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE) &&
            len <= sizeof(toob_mailbox_t)) {
            __CPROVER_havoc_slice(buf, sizeof(toob_mailbox_t));
        } else {
            uint8_t *dst = (uint8_t *)buf;
            dst[0] = nondet_uint8_t();
        }
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv05_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (g_force_bad_sector_size) {
        __CPROVER_assert(false, "Guarded/invalid flash operation must fail before HAL write");
    }
    cbmc_assert_flash_write_invariants(addr, buf, len);
    bool in_mbx = cbmc_subrange_of(addr, len, CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE);
    bool in_img = fv05_allowed_image_target(addr, len);
    __CPROVER_assert(in_mbx || in_img,
                     "Recovery OS writes strictly to inactive OTA target slot or Mailbox (Active OS preserved)");
    g_flash_writes++;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv05_flash_erase_sector(uint32_t addr) {
    if (g_force_bad_sector_size) {
        __CPROVER_assert(false, "Fail-fast get_sector_size() must abort before erase_sector");
    }
    cbmc_assert_flash_erase_sector_invariants(addr);
    size_t sec_sz = 0U;
    uint32_t sec_base = 0U;
    (void)cbmc_sector_info(addr, &sec_base, &sec_sz);
    bool in_mbx = cbmc_subrange_of(addr, sec_sz, CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE);
    bool in_img = fv05_allowed_image_target(addr, sec_sz);
    __CPROVER_assert(in_mbx || in_img,
                     "Recovery OS erases strictly inactive OTA target slot or Mailbox (Active OS preserved)");
    g_flash_erases++;
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t fv05_putchar(char c) {
    (void)c;
    return BOOT_OK;
}

static boot_status_t fv05_flush(void) {
    return BOOT_OK;
}

/* ==========================================================================
 * Reboot Intercept & Post-Init recovery_port.c Direct Unit Checks
 * ========================================================================== */

static void fv05_run_port_direct_checks(void) {
    uint8_t tmp[16] = {0};

    /* 1. Stage-0 immutable-boot firewall in toob_os_flash_write / toob_os_flash_erase */
    g_force_bad_sector_size = true;
    uint32_t s0_addr = nondet_uint32_t();
    uint32_t s0_len  = nondet_uint32_t();
    __CPROVER_assume(s0_len >= 1U && s0_len <= sizeof(tmp));
    __CPROVER_assume(s0_addr < (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END);
    __CPROVER_assert(toob_os_flash_write(s0_addr, tmp, s0_len) == TOOB_ERR_FLASH,
                     "toob_os_flash_write blocks Stage-0 immutable boot range");
    __CPROVER_assert(toob_os_flash_erase(s0_addr, CHIP_FLASH_MAX_SECTOR_SIZE) == TOOB_ERR_FLASH,
                     "toob_os_flash_erase blocks Stage-0 immutable boot range");

    /* 2. Fail-fast get_sector_size() enforcement (error or sector_size == 0) */
    g_forced_sector_size = 0U;
    __CPROVER_assert(toob_os_flash_erase(CHIP_STAGING_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE) ==
                         TOOB_ERR_FLASH,
                     "toob_os_flash_erase fails fast without calling erase_sector when get_sector_size fails/0");

    /* 3. uint32_t address wrap rejection in toob_os_flash_erase */
    __CPROVER_assert(toob_os_flash_erase(0xFFFFF000U, 0x2000U) == TOOB_ERR_FLASH,
                     "toob_os_flash_erase rejects wrapping [addr, addr + len)");
    g_force_bad_sector_size = false;

    /* 4. Streaming SHA-256 port hooks */
    toob_os_sha256_ctx_t sha_ctx;
    uint8_t digest[32];
    __CPROVER_assert(toob_os_sha256_init(NULL) == TOOB_ERR_INVALID_ARG,
                     "SHA-256 init rejects NULL");
    if (toob_os_sha256_init(&sha_ctx) == TOOB_OK) {
        (void)toob_os_sha256_update(&sha_ctx, tmp, sizeof(tmp));
        (void)toob_os_sha256_finalize(&sha_ctx, digest);
    }
}

#define FV05_UNIT_UART_CAP 2U
static uint8_t  g_unit_uart[FV05_UNIT_UART_CAP];
static size_t   g_unit_uart_pos = 0U;
static unsigned g_unit_timeout_slices = 0U;

void cbmc_recovery_reboot_halt(void) {
    if (g_run_port_unit_on_reboot && g_unit_uart_pos >= 2U) {
        g_run_port_unit_on_reboot = false;
        fv05_run_port_direct_checks();
    }
    __CPROVER_assume(false);
}

static boot_status_t fv05_unit_getchar(uint8_t *out_c, uint32_t timeout_ms) {
    __CPROVER_assert(out_c != NULL && __CPROVER_w_ok(out_c, 1U),
                     "console->getchar out_c must be writable");
    __CPROVER_assert(timeout_ms <= 250U,
                     "recovery_serial_getchar must slice timeouts to <= REC_GETCHAR_SLICE_MS (250ms)");
    if (g_unit_uart_pos == 0U && g_unit_timeout_slices < 4U && nondet_bool()) {
        g_unit_timeout_slices++;
        return BOOT_ERR_TIMEOUT;
    }
    if (g_unit_uart_pos >= FV05_UNIT_UART_CAP) {
        __CPROVER_assume(false);
    }
    *out_c = g_unit_uart[g_unit_uart_pos++];
    return BOOT_OK;
}

void prove_xmodem_crc16_and_port_erase(void) {
    g_flash_writes = 0U;
    g_flash_erases = 0U;
    g_force_bad_sector_size = false;
    g_run_port_unit_on_reboot = true;

    /* Valid Recovery OS handoff so boot_main reaches sync + 1 XMODEM packet + CAN */
    CBMC_HAVOC_OBJECT(toob_handoff_state);
    toob_handoff_state.magic            = TOOB_STATE_COMMITTED;
    toob_handoff_state.struct_version   = TOOB_HANDOFF_STRUCT_VERSION;
    toob_handoff_state.booted_partition = TOOB_PARTITION_RECOVERY;
    toob_handoff_state.active_slot      = 0U;
    memset(toob_handoff_state._padding, 0, sizeof(toob_handoff_state._padding));
    g_expected_active_slot = 0U;
    g_handoff_valid_boot   = true;

    /* Byte 0: SOH (0x01) -> full 128B symbolic crc16_ccitt; Byte 1: CAN (0x18) -> reboot & port checks */
    CBMC_HAVOC_OBJECT(g_unit_uart);
    g_unit_uart[0]        = 0x01U; /* SOH */
    g_unit_uart[1]        = 0x18U; /* CAN */
    g_unit_uart_pos       = 0U;
    g_unit_timeout_slices = 0U;

    flash_hal_t flash_hal = {
        .read             = fv05_flash_read,
        .write            = fv05_flash_write,
        .erase_sector     = fv05_flash_erase_sector,
        .get_sector_size  = fv05_flash_get_sector_size,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .erased_value     = 0xFFU,
    };
    console_hal_t con_hal = {
        .getchar = fv05_unit_getchar,
        .putchar = fv05_putchar,
        .flush   = fv05_flush,
    };
    crypto_hal_t crypto_hal = {
        .hash_init   = cbmc_hash_init,
        .hash_update = cbmc_hash_update,
        .hash_finish = cbmc_hash_finish,
    };
    boot_platform_t plat = {
        .flash   = &flash_hal,
        .console = &con_hal,
        .crypto  = &crypto_hal,
        .wdt     = &g_cbmc_wdt_hal,
    };

    boot_target_config_t target = {0};
    uint32_t seal_key[4] = {0};
    (void)boot_main(&plat, &target, seal_key);
}

/* ==========================================================================
 * Entrypoint 2: Multi-Block Head & Split-Trailer XMODEM Streaming + Slot Guard
 * ========================================================================== */

static unsigned g_sync_calls = 0U;
static unsigned g_ctrl_packets_sent = 0U;
static unsigned g_target_packets = 0U;
static unsigned g_nak_budget = 0U;

toob_status_t cbmc_fv05_stream_getchar_contract(uint8_t *out_c, uint32_t timeout_ms) {
    (void)timeout_ms;
    __CPROVER_assert(out_c != NULL && __CPROVER_w_ok(out_c, 1U),
                     "stream getchar out_c must be writable");

    if (g_sync_calls == 0U && !g_deterministic_framing) {
        g_sync_calls++;
        if (nondet_bool()) {
            *out_c = nondet_uint8_t();
            return nondet_bool() ? TOOB_OK : TOOB_ERR_TIMEOUT;
        }
    }
    if (g_sync_calls <= 1U) {
        g_sync_calls = 2U;
        /* Sync immediately on SOH, EOT, or CAN */
        if (g_target_packets == 0U) {
            *out_c = nondet_bool() ? 0x04U : 0x18U;
        } else {
            *out_c = 0x01U; /* SOH for packet 1 */
            g_ctrl_packets_sent = 1U;
        }
        return TOOB_OK;
    }

    /* Optional single timeout / stray control byte to exercise NAK loop */
    if (g_nak_budget > 0U && nondet_bool()) {
        g_nak_budget--;
        if (nondet_bool()) {
            return TOOB_ERR_TIMEOUT;
        }
        *out_c = 0xFFU;
        return TOOB_OK;
    }

    if (g_ctrl_packets_sent < g_target_packets) {
        g_ctrl_packets_sent++;
        *out_c = 0x01U; /* SOH */
        return TOOB_OK;
    }

    *out_c = g_deterministic_framing ? 0x04U : (nondet_bool() ? 0x04U : 0x18U);
    return TOOB_OK;
}

static void run_xmodem_streaming_case(uint8_t stream_mode) {
    g_flash_writes = 0U;
    g_flash_erases = 0U;
    g_force_bad_sector_size = false;
    g_run_port_unit_on_reboot = false;

    /* Fully symbolic .noinit handoff (covers corrupt CRC, APP partition, active_slot > 1,
       and valid Recovery OS boots across active_slot in {0, 1}) */
    CBMC_HAVOC_OBJECT(toob_handoff_state);
    CBMC_HAVOC_OBJECT(g_toob_ota_resume_state);

    g_expected_active_slot = toob_handoff_state.active_slot;
    g_handoff_valid_boot =
        (toob_handoff_state.booted_partition == TOOB_PARTITION_RECOVERY) &&
        (toob_handoff_state.magic == TOOB_STATE_TENTATIVE ||
         toob_handoff_state.magic == TOOB_STATE_COMMITTED) &&
        (toob_handoff_state.struct_version == TOOB_HANDOFF_STRUCT_VERSION);

    g_sync_calls = 0U;
    g_ctrl_packets_sent = 0U;
    g_det_pkt_seq = 0U;
    if (stream_mode == 0U) {
        uint8_t s = nondet_uint8_t();
        __CPROVER_assume(s < 2U);
        g_deterministic_framing = false;
        g_head_tbm1_mode        = false;
        g_forbid_trailer_magic  = true;
        g_nak_budget            = 1U;
        g_target_packets        = (unsigned)s;
    } else if (stream_mode == 1U) {
        g_deterministic_framing = true;
        g_head_tbm1_mode        = true;
        g_forbid_trailer_magic  = true;
        g_nak_budget            = 0U;
        g_target_packets        = 6U;
    } else {
        toob_handoff_state.magic            = TOOB_STATE_COMMITTED;
        toob_handoff_state.struct_version   = TOOB_HANDOFF_STRUCT_VERSION;
        toob_handoff_state.booted_partition = TOOB_PARTITION_RECOVERY;
        __CPROVER_assume(toob_handoff_state.active_slot <= 1U);
        g_expected_active_slot = toob_handoff_state.active_slot;
        g_handoff_valid_boot   = true;
        if (stream_mode == 2U) {
            g_trailer_case = 0U;
        } else {
            g_trailer_case = nondet_bool() ? 1U : 2U;
        }
        g_cand_loc.magic    = nondet_bool() ? TOOB_TBM1_TRAILER_MAGIC : 0U;
        g_cand_loc.tbm1_off = nondet_uint32_t();
        g_cand_loc.tbm1_len = nondet_uint32_t();
        g_cand_loc.crc32    = nondet_uint32_t();
        __CPROVER_assume(g_cand_loc.tbm1_off <= 0x4000U);
        __CPROVER_assume(g_cand_loc.tbm1_len <= 0x4000U);
        __CPROVER_assume(g_cand_loc.crc32 < 0x10000000U);
        g_deterministic_framing = true;
        g_head_tbm1_mode        = false;
        g_forbid_trailer_magic  = false;
        g_nak_budget            = 0U;
        g_target_packets        = 6U;
    }

    flash_hal_t flash_hal = {
        .read             = fv05_flash_read,
        .write            = fv05_flash_write,
        .erase_sector     = fv05_flash_erase_sector,
        .get_sector_size  = fv05_flash_get_sector_size,
        .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
        .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
        .total_size       = CHIP_FLASH_TOTAL_SIZE,
        .erased_value     = 0xFFU,
    };
    console_hal_t con_hal = {
        .getchar = fv05_unit_getchar,
        .putchar = fv05_putchar,
        .flush   = fv05_flush,
    };
    crypto_hal_t crypto_hal = {
        .hash_init   = cbmc_hash_init,
        .hash_update = cbmc_hash_update,
        .hash_finish = cbmc_hash_finish,
    };
    boot_platform_t plat = {
        .flash   = &flash_hal,
        .console = &con_hal,
        .crypto  = &crypto_hal,
        .wdt     = &g_cbmc_wdt_hal,
    };

    boot_target_config_t target = {0};
    uint32_t seal_key[4] = {0};
    (void)boot_main(&plat, &target, seal_key);
}

void prove_xmodem_short_and_nak_stream(void) {
    run_xmodem_streaming_case(0U);
}

void prove_xmodem_head_tbm1_stream(void) {
    run_xmodem_streaming_case(1U);
}

void prove_xmodem_split_trailer_stream(void) {
    run_xmodem_streaming_case(2U);
}

void prove_xmodem_unaligned_trailer_stream(void) {
    run_xmodem_streaming_case(3U);
}

int main(void) {
    prove_xmodem_short_and_nak_stream();
    return 0;
}
