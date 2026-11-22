/**
 * @file main.c
 * @brief Multi-threaded Zephyr RTOS + sdk/libtoob + sdk/os_client E2E Guest App.
 *
 * Exercises on emulated Nordic nRF52840 (Cortex-M4F XIP at 0x00038100):
 *   - TOOB_OS_INIT_OR_PANIC() & SCB->VTOR == 0x00038100 verification
 *   - Multi-threaded execution: preemptive worker thread feeding NRF_WDT and
 *     contending on K_MUTEX_DEFINE(s_toob_mutex) via toob_os_lock/unlock
 *   - Persistent Flash NVS credentials (toob_os_nvs_write/read, toob_cred_*)
 *     backed by Zephyr subsys/fs/nvs on 'storage_partition' (0x000F8000)
 *   - Boot confirmation (toob_confirm_boot -> GPREGRET + retained SRAM + Mailbox)
 *   - Hardware BPROT Stage-0 Flash immutability check
 *   - Full OTA check-in & verified TBM1 streaming via sdk/os_client
 *     (toob_network_trigger_ota -> PSA SHA-256 -> Staging -> sys_reboot)
 *   - Unconfirmed bad_v3 WDT starvation triggering Stage 1 automatic rollback
 */

#include "libtoob.h"
#include "toob_device_cred.h"
#include "toob_network_client.h"

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/sys/ring_buffer.h>

#include <hal/nrf_power.h>
#include <soc.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#  if __has_include("app_variant_cfg.h")
#    include "app_variant_cfg.h"
#  endif
#endif

#ifndef APP_FW_VERSION_STR
#  ifdef DEFAULT_APP_FW_VERSION_STR
#    define APP_FW_VERSION_STR DEFAULT_APP_FW_VERSION_STR
#  else
#    define APP_FW_VERSION_STR "1.0.0"
#  endif
#endif

#ifndef APP_BAD_UNCONFIRMED
#  ifdef DEFAULT_APP_BAD_UNCONFIRMED
#    define APP_BAD_UNCONFIRMED DEFAULT_APP_BAD_UNCONFIRMED
#  else
#    define APP_BAD_UNCONFIRMED 0
#  endif
#endif

#define NRF_WDT_RELOAD_MAGIC      0x6E524635U
#define CONFIRM_SRAM_NONCE_ADDR   0x2003FFC0UL
#define STAGE0_PROBE_FLASH_ADDR   0x00001000UL
#define NRF_BPROT_CONFIG0_ADDR    0x40000600UL
#define UART_RX_RING_BYTES        2048U
#define HTTP_MAX_CHUNK_BYTES      256U
#define CMD_LINE_MAX_BYTES        192U

RING_BUF_DECLARE(s_uart_rx_rb, UART_RX_RING_BYTES);
static K_SEM_DEFINE(s_uart_rx_sem, 0, 1);

static const struct device *s_uart_dev;
static atomic_t s_worker_ticks = ATOMIC_INIT(0);

static void app_zeroize(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len > 0U) {
        *p++ = 0U;
        len--;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : : "g"(ptr) : "memory");
#endif
}

static inline void wdt_kick_hw(void)
{
#if (APP_BAD_UNCONFIRMED == 0)
    if ((NRF_WDT->RUNSTATUS & 1U) != 0U) {
        NRF_WDT->RR[0] = NRF_WDT_RELOAD_MAGIC;
    }
#endif
}

#if (APP_BAD_UNCONFIRMED == 0)

static void hex_encode_lower(const uint8_t *src, size_t len, char *dst)
{
    static const char k_hex[] = "0123456789abcdef";
    for (size_t i = 0U; i < len; i++) {
        dst[2U * i] = k_hex[(size_t)(src[i] >> 4U)];
        dst[(2U * i) + 1U] = k_hex[(size_t)(src[i] & 0x0FU)];
    }
    dst[2U * len] = '\0';
}

static bool hex_decode_bytes(const char *hex, uint8_t *out, size_t expected_bytes)
{
    if ((hex == NULL) || (out == NULL)) {
        return false;
    }
    for (size_t i = 0U; i < expected_bytes; i++) {
        char hi_c = hex[2U * i];
        char lo_c = hex[(2U * i) + 1U];
        uint8_t hi = 0U;
        uint8_t lo = 0U;

        if ((hi_c >= '0') && (hi_c <= '9')) {
            hi = (uint8_t)(hi_c - '0');
        } else if ((hi_c >= 'a') && (hi_c <= 'f')) {
            hi = (uint8_t)(10 + (hi_c - 'a'));
        } else if ((hi_c >= 'A') && (hi_c <= 'F')) {
            hi = (uint8_t)(10 + (hi_c - 'A'));
        } else {
            return false;
        }

        if ((lo_c >= '0') && (lo_c <= '9')) {
            lo = (uint8_t)(lo_c - '0');
        } else if ((lo_c >= 'a') && (lo_c <= 'f')) {
            lo = (uint8_t)(10 + (lo_c - 'a'));
        } else if ((lo_c >= 'A') && (lo_c <= 'F')) {
            lo = (uint8_t)(10 + (lo_c - 'A'));
        } else {
            return false;
        }

        out[i] = (uint8_t)((hi << 4U) | lo);
    }
    return (hex[2U * expected_bytes] == '\0');
}

#endif /* APP_BAD_UNCONFIRMED == 0 */

/* ============================================================================
 * Interrupt-Driven UART0 RX Ring Buffer
 * ============================================================================ */

static void uart_rx_isr_cb(const struct device *dev, void *user_data)
{
    (void)user_data;
    if (!uart_irq_update(dev)) {
        return;
    }
    if (uart_irq_rx_ready(dev)) {
        uint8_t tmp[32];
        int n = uart_fifo_read(dev, tmp, (int)sizeof(tmp));
        if (n > 0) {
            (void)ring_buf_put(&s_uart_rx_rb, tmp, (uint32_t)n);
            k_sem_give(&s_uart_rx_sem);
        }
    }
}

#if (APP_BAD_UNCONFIRMED == 0)

static void uart_tx_byte(uint8_t b)
{
    if (s_uart_dev != NULL) {
        uart_poll_out(s_uart_dev, b);
    }
}

static bool uart_rx_byte(uint8_t *out_byte, uint32_t timeout_ms)
{
    uint64_t deadline = k_uptime_get() + (uint64_t)timeout_ms;
    for (;;) {
        if (ring_buf_get(&s_uart_rx_rb, out_byte, 1U) == 1U) {
            return true;
        }
        wdt_kick_hw();
        int64_t rem = (int64_t)deadline - k_uptime_get();
        if (rem <= 0) {
            return false;
        }
        uint32_t wait_slice = (rem > 50) ? 50U : (uint32_t)rem;
        (void)k_sem_take(&s_uart_rx_sem, K_MSEC(wait_slice));
    }
}

static bool uart_rx_exact(uint8_t *dst, size_t len, uint32_t timeout_ms)
{
    for (size_t i = 0U; i < len; i++) {
        if (!uart_rx_byte(&dst[i], timeout_ms)) {
            return false;
        }
    }
    return true;
}

static bool uart_rx_line(char *line, size_t max_len, uint32_t timeout_ms)
{
    if ((line == NULL) || (max_len < 2U)) {
        return false;
    }
    size_t pos = 0U;
    for (;;) {
        uint8_t ch = 0U;
        if (!uart_rx_byte(&ch, timeout_ms)) {
            return false;
        }
        if (ch == '\r') {
            continue;
        }
        if (ch == '\n') {
            line[pos] = '\0';
            return true;
        }
        if ((pos + 1U) < max_len) {
            line[pos++] = (char)ch;
        }
    }
}

#endif /* APP_BAD_UNCONFIRMED == 0 */

/* ============================================================================
 * Preemptive Background Worker Thread (Proves Multi-Thread + K_MUTEX Safety)
 * ============================================================================ */

static void toob_worker_entry(void *p1, void *p2, void *p3)
{
    (void)p1;
    (void)p2;
    (void)p3;

    for (;;) {
        wdt_kick_hw();

        toob_boot_diag_t diag;
        toob_os_lock();
        toob_status_t st = toob_get_boot_diag(&diag);
        toob_os_unlock();
        if (st == TOOB_OK) {
            (void)atomic_inc(&s_worker_ticks);
        }
        app_zeroize(&diag, sizeof(diag));

        k_msleep(150);
    }
}

K_THREAD_DEFINE(toob_worker_tid, 4096, toob_worker_entry, NULL, NULL, NULL, 5, 0, 0);

/* ============================================================================
 * Deterministic Embedded UART HTTP Transport Override for sdk/os_client
 * ============================================================================ */

#if (APP_BAD_UNCONFIRMED == 0)

toob_status_t toob_network_init(void)
{
    return TOOB_OK;
}

toob_status_t rtos_http_request(
    toob_http_method_t method,
    const char *url,
    const char *const *headers, uint32_t header_count,
    const uint8_t *body, uint32_t body_len,
    uint32_t range_offset,
    toob_http_chunk_cb_t callback, void *ctx,
    uint16_t *out_status,
    uint32_t *out_retry_after_s)
{
    if ((url == NULL) || (callback == NULL) ||
        (out_status == NULL) || (out_retry_after_s == NULL)) {
        return TOOB_ERR_INVALID_ARG;
    }

    *out_status = 0U;
    *out_retry_after_s = 0U;

    const char *m_str = (method == TOOB_HTTP_POST) ? "POST" : "GET";
    printk("@@HTTP_BEGIN method=%s url=%s range=%u body_len=%u hdrs=%u\n",
           m_str, url, (unsigned)range_offset, (unsigned)body_len, (unsigned)header_count);

    if (headers != NULL) {
        for (uint32_t i = 0U; i < header_count; i++) {
            if (headers[i] != NULL) {
                char clean_hdr[192];
                size_t hlen = strlen(headers[i]);
                while ((hlen > 0U) &&
                       ((headers[i][hlen - 1U] == '\r') || (headers[i][hlen - 1U] == '\n'))) {
                    hlen--;
                }
                if (hlen >= sizeof(clean_hdr)) {
                    hlen = sizeof(clean_hdr) - 1U;
                }
                memcpy(clean_hdr, headers[i], hlen);
                clean_hdr[hlen] = '\0';
                printk("@@HDR %s\n", clean_hdr);
                app_zeroize(clean_hdr, sizeof(clean_hdr));
            }
        }
    }

    if ((body != NULL) && (body_len > 0U)) {
        printk("@@BODY_HEX ");
        char byte_hex[3];
        for (uint32_t i = 0U; i < body_len; i++) {
            hex_encode_lower(&body[i], 1U, byte_hex);
            uart_tx_byte((uint8_t)byte_hex[0]);
            uart_tx_byte((uint8_t)byte_hex[1]);
        }
        uart_tx_byte((uint8_t)'\n');
    }

    printk("@@HTTP_END\n");

    char rsp_line[96];
    if (!uart_rx_line(rsp_line, sizeof(rsp_line), 10000U)) {
        return TOOB_ERR_TIMEOUT;
    }
    if (strncmp(rsp_line, "@@RSP ", 6U) != 0) {
        return TOOB_ERR_VERIFY;
    }

    char *cursor = rsp_line + 6;
    char *endp = NULL;
    unsigned long st_code = strtoul(cursor, &endp, 10);
    if ((endp == cursor) || (st_code > 999UL)) {
        return TOOB_ERR_VERIFY;
    }
    cursor = endp;
    unsigned long retry_s = strtoul(cursor, &endp, 10);
    if (endp == cursor) {
        return TOOB_ERR_VERIFY;
    }
    cursor = endp;
    unsigned long total_bytes = strtoul(cursor, &endp, 10);
    if (endp == cursor) {
        return TOOB_ERR_VERIFY;
    }

    *out_status = (uint16_t)st_code;
    *out_retry_after_s = (uint32_t)retry_s;

    if (total_bytes == 0UL) {
        return TOOB_OK;
    }

    uart_tx_byte((uint8_t)'R');

    uint8_t chunk_buf[HTTP_MAX_CHUNK_BYTES];
    uint32_t received = 0U;
    while (received < (uint32_t)total_bytes) {
        uint8_t len_hdr[2];
        if (!uart_rx_exact(len_hdr, sizeof(len_hdr), 10000U)) {
            app_zeroize(chunk_buf, sizeof(chunk_buf));
            return TOOB_ERR_TIMEOUT;
        }
        uint16_t chunk_len = (uint16_t)len_hdr[0] | ((uint16_t)len_hdr[1] << 8U);
        if ((chunk_len == 0U) ||
            (chunk_len > HTTP_MAX_CHUNK_BYTES) ||
            (chunk_len > ((uint32_t)total_bytes - received))) {
            app_zeroize(chunk_buf, sizeof(chunk_buf));
            uart_tx_byte((uint8_t)'E');
            return TOOB_ERR_INVALID_ARG;
        }

        if (!uart_rx_exact(chunk_buf, chunk_len, 10000U)) {
            app_zeroize(chunk_buf, sizeof(chunk_buf));
            return TOOB_ERR_TIMEOUT;
        }

        wdt_kick_hw();
        toob_status_t cb_st = callback(chunk_buf, (uint32_t)chunk_len, ctx);
        if (cb_st != TOOB_OK) {
            app_zeroize(chunk_buf, sizeof(chunk_buf));
            uart_tx_byte((uint8_t)'E');
            return cb_st;
        }

        received += (uint32_t)chunk_len;
        uart_tx_byte((uint8_t)'K');
    }

    app_zeroize(chunk_buf, sizeof(chunk_buf));
    return TOOB_OK;
}

/* ============================================================================
 * Interactive UART Command Handlers (v1.0.0 & v2.0.0)
 * ============================================================================ */

static void handle_cmd_diag(void)
{
    if (atomic_get(&s_worker_ticks) == 0) {
        k_msleep(180);
    }

    toob_boot_diag_t diag;
    uint8_t dev_id[32];
    uint8_t wire_buf[TOOB_TDR1_MAX_SIZE];
    size_t wire_len = 0U;

    toob_status_t d_st = toob_get_boot_diag(&diag);
    toob_status_t i_st = toob_get_device_id(dev_id, sizeof(dev_id));
    toob_status_t w_st = toob_get_boot_diag_wire(wire_buf, sizeof(wire_buf), &wire_len);

    if ((d_st != TOOB_OK) || (i_st != TOOB_OK) || (w_st != TOOB_OK) ||
        (wire_len < TOOB_TDR1_MIN_FRAME_SIZE)) {
        printk("[ZEPHYR] DIAG status=ERR d=0x%08X i=0x%08X w=0x%08X\n",
               (unsigned)d_st, (unsigned)i_st, (unsigned)w_st);
        return;
    }

    char dev_hex[65];
    hex_encode_lower(dev_id, sizeof(dev_id), dev_hex);
    long wticks = atomic_get(&s_worker_ticks);

    printk("[ZEPHYR] DIAG status=OK wire_len=%u worker_ticks=%ld dev_id=%s\n",
           (unsigned)wire_len, wticks, dev_hex);

    app_zeroize(&diag, sizeof(diag));
    app_zeroize(dev_id, sizeof(dev_id));
    app_zeroize(wire_buf, sizeof(wire_buf));
}

static void handle_cmd_bprot_check(void)
{
    volatile uint32_t *probe_ptr = (volatile uint32_t *)STAGE0_PROBE_FLASH_ADDR;
    uint32_t before = *probe_ptr;
    uint32_t cfg0 = *(volatile uint32_t *)NRF_BPROT_CONFIG0_ADDR;

    /* Attempt direct NVMC page erase + zero-word overwrite against locked Stage 0 */
    NRF_NVMC->CONFIG = 2U; /* EEN */
    NRF_NVMC->ERASEPAGE = (uint32_t)STAGE0_PROBE_FLASH_ADDR;
    NRF_NVMC->CONFIG = 1U; /* WEN */
    *probe_ptr = 0x00000000U;
    NRF_NVMC->CONFIG = 0U; /* REN */

    uint32_t after = *probe_ptr;
    unsigned intact = ((after == before) && (after != 0xFFFFFFFFU) && (after != 0x00000000U))
                          ? 1U
                          : 0U;
    printk("[ZEPHYR] BPROT_CHECK config0=0x%08X intact=%u\n", (unsigned)cfg0, intact);
}

static void handle_cmd_enroll(const char *token_hex)
{
    uint8_t raw_tok[TOOB_DEVICE_TOKEN_LEN];
    app_zeroize(raw_tok, sizeof(raw_tok));

    if (!hex_decode_bytes(token_hex, raw_tok, TOOB_DEVICE_TOKEN_LEN)) {
        printk("[ZEPHYR] ENROLL status=INVALID_HEX\n");
        return;
    }

    toob_status_t w_st = toob_cred_enroll(raw_tok);
    app_zeroize(raw_tok, sizeof(raw_tok));
    if (w_st != TOOB_OK) {
        printk("[ZEPHYR] ENROLL status=ERR code=0x%08X\n", (unsigned)w_st);
        return;
    }

    toob_device_cred_t verify_cred;
    toob_status_t r_st = toob_cred_load(&verify_cred);
    if (r_st != TOOB_OK) {
        app_zeroize(&verify_cred, sizeof(verify_cred));
        printk("[ZEPHYR] ENROLL status=READBACK_ERR code=0x%08X\n", (unsigned)r_st);
        return;
    }

    char out_hex[(2U * TOOB_DEVICE_TOKEN_LEN) + 1U];
    hex_encode_lower(verify_cred.device_token, TOOB_DEVICE_TOKEN_LEN, out_hex);
    unsigned long long seq = (unsigned long long)verify_cred.checkin_seq;
    app_zeroize(&verify_cred, sizeof(verify_cred));

    printk("[ZEPHYR] ENROLL status=OK seq=%llu token=%s\n", seq, out_hex);
    app_zeroize(out_hex, sizeof(out_hex));
}

static void handle_cmd_cred(void)
{
    toob_device_cred_t cred;
    toob_status_t st = toob_cred_load(&cred);
    if (st == TOOB_ERR_NOT_FOUND) {
        printk("[ZEPHYR] CRED status=NOT_FOUND\n");
        return;
    }
    if (st != TOOB_OK) {
        printk("[ZEPHYR] CRED status=ERR code=0x%08X\n", (unsigned)st);
        return;
    }

    char out_hex[(2U * TOOB_DEVICE_TOKEN_LEN) + 1U];
    hex_encode_lower(cred.device_token, TOOB_DEVICE_TOKEN_LEN, out_hex);
    unsigned long long seq = (unsigned long long)cred.checkin_seq;
    app_zeroize(&cred, sizeof(cred));

    printk("[ZEPHYR] CRED status=OK seq=%llu token=%s\n", seq, out_hex);
    app_zeroize(out_hex, sizeof(out_hex));
}

static void handle_cmd_confirm(void)
{
    toob_handoff_t handoff;
    toob_status_t h_st = toob_get_handoff(&handoff);
    if (h_st != TOOB_OK) {
        printk("[ZEPHYR] CONFIRM status=HANDOFF_ERR code=0x%08X\n", (unsigned)h_st);
        return;
    }

    toob_status_t st = toob_confirm_boot();
    uint32_t gpreg = nrf_power_gpregret_get(NRF_POWER, 0U) & 0xFFU;
    uint64_t sram_nonce = *(volatile uint64_t *)CONFIRM_SRAM_NONCE_ADDR;
    unsigned sram_match = ((handoff.boot_nonce != 0ULL) && (sram_nonce == handoff.boot_nonce))
                              ? 1U
                              : 0U;

    app_zeroize(&handoff, sizeof(handoff));
    printk("[ZEPHYR] CONFIRM status=%s code=0x%08X gpreg=0x%02X sram_match=%u\n",
           (st == TOOB_OK) ? "OK" : "ERR",
           (unsigned)st,
           (unsigned)gpreg,
           sram_match);
}

#endif /* APP_BAD_UNCONFIRMED == 0 */

int main(void)
{
    wdt_kick_hw();

    /* Mandatory P10 fail-closed .noinit handoff validation */
    TOOB_OS_INIT_OR_PANIC();

    s_uart_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
    if (device_is_ready(s_uart_dev)) {
        (void)uart_irq_callback_user_data_set(s_uart_dev, uart_rx_isr_cb, NULL);
        uart_irq_rx_enable(s_uart_dev);
    }

    toob_handoff_t handoff;
    toob_boot_diag_t diag;
    if ((toob_get_handoff(&handoff) != TOOB_OK) || (toob_get_boot_diag(&diag) != TOOB_OK)) {
        printk("[ZEPHYR] FATAL handoff/diag read failure\n");
        while (true) {
            TOOB_TRAP();
        }
    }

    uint32_t gpreg_boot = nrf_power_gpregret_get(NRF_POWER, 0U) & 0xFFU;

#if (APP_BAD_UNCONFIRMED != 0)
    printk("[ZEPHYR] BOOT ver=%s vtor=0x%08X slot=%u tent=%u reset=%u fail=%u svn=%u key=%u outcome=%u gpreg=0x%02X handoff=OK mode=UNCONFIRMED_WDT_STARVE\n",
           APP_FW_VERSION_STR,
           (unsigned)SCB->VTOR,
           (unsigned)handoff.active_slot,
           (unsigned)((handoff.magic == TOOB_STATE_TENTATIVE) ? 1U : 0U),
           (unsigned)handoff.reset_reason,
           (unsigned)handoff.boot_failure_count,
           (unsigned)diag.current_svn,
           (unsigned)diag.active_key_index,
           (unsigned)diag.last_update_outcome,
           (unsigned)gpreg_boot);
    app_zeroize(&handoff, sizeof(handoff));
    app_zeroize(&diag, sizeof(diag));

    /* Intentionally skip toob_confirm_boot() and starve NRF_WDT to prove Stage 1 rollback */
    for (;;) {
        k_msleep(250);
    }
#else
    printk("[ZEPHYR] BOOT ver=%s vtor=0x%08X slot=%u tent=%u reset=%u fail=%u svn=%u key=%u outcome=%u gpreg=0x%02X handoff=OK\n",
           APP_FW_VERSION_STR,
           (unsigned)SCB->VTOR,
           (unsigned)handoff.active_slot,
           (unsigned)((handoff.magic == TOOB_STATE_TENTATIVE) ? 1U : 0U),
           (unsigned)handoff.reset_reason,
           (unsigned)handoff.boot_failure_count,
           (unsigned)diag.current_svn,
           (unsigned)diag.active_key_index,
           (unsigned)diag.last_update_outcome,
           (unsigned)gpreg_boot);
    app_zeroize(&handoff, sizeof(handoff));
    app_zeroize(&diag, sizeof(diag));

    char cmd[CMD_LINE_MAX_BYTES];
    for (;;) {
        wdt_kick_hw();
        if (!uart_rx_line(cmd, sizeof(cmd), 500U)) {
            continue;
        }
        if (cmd[0] == '\0') {
            continue;
        }

        if (strcmp(cmd, "DIAG") == 0) {
            handle_cmd_diag();
        } else if (strcmp(cmd, "BPROT_CHECK") == 0) {
            handle_cmd_bprot_check();
        } else if (strncmp(cmd, "ENROLL ", 7U) == 0) {
            handle_cmd_enroll(cmd + 7);
        } else if (strcmp(cmd, "CRED") == 0) {
            handle_cmd_cred();
        } else if (strcmp(cmd, "CONFIRM") == 0) {
            handle_cmd_confirm();
        } else if (strcmp(cmd, "OTA_CHECKIN") == 0) {
            toob_status_t ota_st = toob_network_trigger_ota("http://ota.toob.local");
            printk("[ZEPHYR] OTA_CHECKIN result=0x%08X\n", (unsigned)ota_st);
        } else if (strcmp(cmd, "REBOOT") == 0) {
            printk("[ZEPHYR] REBOOTING\n");
            sys_reboot(SYS_REBOOT_WARM);
        } else {
            printk("[ZEPHYR] UNKNOWN_CMD %s\n", cmd);
        }
        app_zeroize(cmd, sizeof(cmd));
    }
#endif
}
