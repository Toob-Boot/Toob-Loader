/**
 * @file main.c
 * @brief ESP-IDF v6.1 FreeRTOS Guest Application for Toob-Loader QEMU E2E.
 *
 * Exercises under unmodified Toob Stage 0 -> Stage 1 Direct-XIP handoff:
 *   1. TOOB_OS_INIT_OR_PANIC() .noinit CRC-32 validation at 0x50000000.
 *   2. Multi-task FreeRTOS scheduling, esp_timer, PSA Crypto SHA-256, and
 *      concurrent static-mutex contention (toob_os_lock / toob_os_unlock).
 *   3. Boot diagnostics (toob_get_boot_diag + toob_get_boot_diag_wire).
 *   4. Real ESP-IDF nvs_flash ("toob_sys" namespace) credential enrollment,
 *      sequence bumping, and server-initiated token rotation across OTAs.
 *   5. Boot confirmation (toob_confirm_boot) + 0x50001FC0 RTC nonce verification.
 *   6. Full signed TBM1 OTA driven end-to-end via sdk/os_client
 *      (toob_network_trigger_ota -> rtos_http_request -> toob_ota_* -> esp_restart).
 *   7. Unconfirmed firmware hang (APP_SIMULATE_HANG=1) verifying hardware
 *      TIMG0 MWDT reset and automatic Stage 1 A/B rollback.
 */

#include "libtoob.h"
#include "toob_espidf.h"
#include "toob_device_cred.h"
#include "toob_network_client.h"

#include "driver/uart.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef APP_FW_VER_STR
#  define APP_FW_VER_STR "1.0.0"
#endif

#ifndef APP_SIMULATE_HANG
#  define APP_SIMULATE_HANG 0
#endif

#define ESP32C3_CONFIRM_RTC_ADDR  ((uintptr_t)0x50001FC0U)
#define UART_RX_BUF_BYTES         4096
#define LINE_BUF_MAX              768U
#define TUNNEL_BODY_CHUNK_BYTES   128U
#define WDT_TASK_STACK_WORDS      2048U
#define WORKER_TASK_STACK_WORDS   4096U

typedef struct {
    char     fw_ver[16];
    uint32_t simulate_hang;
} app_variant_cfg_t;

__attribute__((section(".rodata.app_variant_cfg"), used))
static const volatile app_variant_cfg_t s_app_cfg = {
    .fw_ver = APP_FW_VER_STR,
    .simulate_hang = (uint32_t)APP_SIMULATE_HANG,
};

static volatile bool      s_suspend_wdt_feed = false;
static volatile bool      s_worker_selfcheck_ok = false;

static StaticTask_t       s_wdt_tcb;
static StackType_t        s_wdt_stack[WDT_TASK_STACK_WORDS];

static StaticTask_t       s_worker_tcb;
static StackType_t        s_worker_stack[WORKER_TASK_STACK_WORDS];

static StaticSemaphore_t  s_worker_sem_buf;
static SemaphoreHandle_t  s_worker_done_sem = NULL;

/* ==============================================================================
 * UART0 Raw Framing Helpers
 * ============================================================================== */

static void _uart_send_str(const char *str)
{
    if (str == NULL) {
        return;
    }
    size_t len = strlen(str);
    if (len > 0U) {
        (void)uart_write_bytes(UART_NUM_0, str, len);
    }
}

static uint8_t s_rx_stash[256];
static size_t  s_rx_head = 0U;
static size_t  s_rx_len  = 0U;

static bool _uart_read_line(char *out, size_t cap, uint32_t timeout_ms)
{
    if ((out == NULL) || (cap < 2U)) {
        return false;
    }

    size_t pos = 0U;
    int64_t deadline_us = esp_timer_get_time() + ((int64_t)timeout_ms * 1000LL);

    for (;;) {
        while (s_rx_head < s_rx_len) {
            uint8_t ch = s_rx_stash[s_rx_head++];
            if (ch == (uint8_t)'\r') {
                continue;
            }
            if (ch == (uint8_t)'\n') {
                out[pos] = '\0';
                return true;
            }
            if (pos < (cap - 1U)) {
                out[pos++] = (char)ch;
            }
        }

        s_rx_head = 0U;
        s_rx_len = 0U;

        if (!s_suspend_wdt_feed) {
            toob_espidf_feed_boot_wdt();
        }
        if (esp_timer_get_time() >= deadline_us) {
            break;
        }

        int got = uart_read_bytes(UART_NUM_0, s_rx_stash, sizeof(s_rx_stash), pdMS_TO_TICKS(10));
        if (got > 0) {
            s_rx_len = (size_t)got;
        }
    }

    out[0] = '\0';
    return false;
}

static void _hex_encode_bytes(const uint8_t *src, size_t len, char *dst)
{
    static const char k_hex[] = "0123456789abcdef";
    for (size_t i = 0U; i < len; i++) {
        dst[2U * i] = k_hex[(src[i] >> 4U) & 0x0FU];
        dst[(2U * i) + 1U] = k_hex[src[i] & 0x0FU];
    }
    dst[2U * len] = '\0';
}

static int _hex_nibble(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return (int)(c - '0');
    }
    if ((c >= 'a') && (c <= 'f')) {
        return 10 + (int)(c - 'a');
    }
    if ((c >= 'A') && (c <= 'F')) {
        return 10 + (int)(c - 'A');
    }
    return -1;
}

static bool _hex_decode_bytes(const char *hex, uint8_t *out, size_t max_out, size_t *out_len)
{
    if ((hex == NULL) || (out == NULL) || (out_len == NULL)) {
        return false;
    }
    size_t hlen = strlen(hex);
    if (((hlen % 2U) != 0U) || ((hlen / 2U) > max_out)) {
        return false;
    }
    size_t bytes = hlen / 2U;
    for (size_t i = 0U; i < bytes; i++) {
        int hi = _hex_nibble(hex[2U * i]);
        int lo = _hex_nibble(hex[(2U * i) + 1U]);
        if ((hi < 0) || (lo < 0)) {
            return false;
        }
        out[i] = (uint8_t)(((uint32_t)hi << 4U) | (uint32_t)lo);
    }
    *out_len = bytes;
    return true;
}

/* ==============================================================================
 * Deterministic UART0 HTTP Tunnel Overrides for sdk/os_client in Headless QEMU
 * ============================================================================== */

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
    if ((url == NULL) || (callback == NULL) || (out_status == NULL) || (out_retry_after_s == NULL)) {
        return TOOB_ERR_INVALID_ARG;
    }

    *out_status = 0U;
    *out_retry_after_s = 0U;

    char line[LINE_BUF_MAX];
    int n = snprintf(line, sizeof(line), "@@HTREQ %s %s %u %u %u\r\n",
                     (method == TOOB_HTTP_POST) ? "POST" : "GET",
                     url,
                     (unsigned)range_offset,
                     (unsigned)header_count,
                     (unsigned)body_len);
    if ((n <= 0) || ((size_t)n >= sizeof(line))) {
        return TOOB_ERR_INVALID_ARG;
    }
    _uart_send_str(line);

    if (headers != NULL) {
        for (uint32_t i = 0U; i < header_count; i++) {
            if (headers[i] == NULL) {
                continue;
            }
            char hdr_copy[256];
            size_t hlen = strlen(headers[i]);
            if (hlen >= sizeof(hdr_copy)) {
                hlen = sizeof(hdr_copy) - 1U;
            }
            memcpy(hdr_copy, headers[i], hlen);
            hdr_copy[hlen] = '\0';
            while ((hlen > 0U) &&
                   ((hdr_copy[hlen - 1U] == '\r') || (hdr_copy[hlen - 1U] == '\n'))) {
                hlen--;
                hdr_copy[hlen] = '\0';
            }
            n = snprintf(line, sizeof(line), "@@HTHDR %s\r\n", hdr_copy);
            memset(hdr_copy, 0, sizeof(hdr_copy));
            if ((n > 0) && ((size_t)n < sizeof(line))) {
                _uart_send_str(line);
            }
        }
    }

    if ((body != NULL) && (body_len > 0U)) {
        uint32_t off = 0U;
        char hex_chunk[(2U * TUNNEL_BODY_CHUNK_BYTES) + 1U];
        while (off < body_len) {
            uint32_t rem = body_len - off;
            uint32_t take = (rem > TUNNEL_BODY_CHUNK_BYTES) ? TUNNEL_BODY_CHUNK_BYTES : rem;
            _hex_encode_bytes(&body[off], take, hex_chunk);
            n = snprintf(line, sizeof(line), "@@HTBODY %s\r\n", hex_chunk);
            if ((n <= 0) || ((size_t)n >= sizeof(line))) {
                return TOOB_ERR_INVALID_ARG;
            }
            _uart_send_str(line);
            off += take;
        }
        memset(hex_chunk, 0, sizeof(hex_chunk));
    }

    _uart_send_str("@@HTEND\r\n");

    /* Wait for @@HTRESP <status> <retry_after> */
    bool got_resp = false;
    while (_uart_read_line(line, sizeof(line), 15000U)) {
        if (strncmp(line, "@@HTRESP ", 9U) == 0) {
            unsigned st_code = 0U;
            unsigned retry_s = 0U;
            if (sscanf(line + 9U, "%u %u", &st_code, &retry_s) >= 1) {
                *out_status = (uint16_t)st_code;
                *out_retry_after_s = (uint32_t)retry_s;
                got_resp = true;
                break;
            }
        }
    }
    if (!got_resp) {
        return TOOB_ERR_TIMEOUT;
    }

    uint8_t chunk_buf[300];
    toob_status_t cb_stat = TOOB_OK;

    for (;;) {
        _uart_send_str("@@HTNEXT\r\n");
        if (!_uart_read_line(line, sizeof(line), 15000U)) {
            return TOOB_ERR_TIMEOUT;
        }
        if (strcmp(line, "@@HTDONE") == 0) {
            break;
        }
        if (strncmp(line, "@@HTDATA ", 9U) == 0) {
            size_t decoded_len = 0U;
            if (!_hex_decode_bytes(line + 9U, chunk_buf, sizeof(chunk_buf), &decoded_len)) {
                return TOOB_ERR_VERIFY;
            }
            if (!s_suspend_wdt_feed) {
                toob_espidf_feed_boot_wdt();
            }
            if (decoded_len > 0U) {
                cb_stat = callback(chunk_buf, (uint32_t)decoded_len, ctx);
                if (cb_stat != TOOB_OK) {
                    _uart_send_str("@@HTABORT\r\n");
                    memset(chunk_buf, 0, sizeof(chunk_buf));
                    return cb_stat;
                }
            }
        }
    }

    memset(chunk_buf, 0, sizeof(chunk_buf));
    (void)uart_wait_tx_done(UART_NUM_0, pdMS_TO_TICKS(100));
    return TOOB_OK;
}

/* ==============================================================================
 * FreeRTOS Background Tasks (WDT Health Feeder & Concurrent Self-Check Worker)
 * ============================================================================== */

static void _wdt_monitor_task(void *arg)
{
    (void)arg;
    for (;;) {
        if (!s_suspend_wdt_feed) {
            toob_espidf_feed_boot_wdt();
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

static void _worker_selfcheck_task(void *arg)
{
    (void)arg;
    static const uint8_t k_abc[3] = { 'a', 'b', 'c' };
    static const uint8_t k_abc_sha256[32] = {
        0xbaU, 0x78U, 0x16U, 0xbfU, 0x8fU, 0x01U, 0xcfU, 0xeaU,
        0x41U, 0x41U, 0x40U, 0xdeU, 0x5dU, 0xaeU, 0x22U, 0x23U,
        0xb0U, 0x03U, 0x61U, 0xa3U, 0x96U, 0x17U, 0x7aU, 0x9cU,
        0xb4U, 0x10U, 0xffU, 0x61U, 0xf2U, 0x00U, 0x15U, 0xadU
    };

    bool all_ok = true;
    for (uint32_t iter = 0U; iter < 4U; iter++) {
        toob_boot_diag_t d;
        if (toob_get_boot_diag(&d) != TOOB_OK) {
            all_ok = false;
            break;
        }

        toob_os_sha256_ctx_t sha_ctx;
        uint8_t digest[32];
        if ((toob_os_sha256_init(&sha_ctx) != TOOB_OK) ||
            (toob_os_sha256_update(&sha_ctx, k_abc, sizeof(k_abc)) != TOOB_OK) ||
            (toob_os_sha256_finalize(&sha_ctx, digest) != TOOB_OK) ||
            (memcmp(digest, k_abc_sha256, sizeof(digest)) != 0)) {
            all_ok = false;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    s_worker_selfcheck_ok = all_ok && (esp_timer_get_time() > 0);
    if (s_worker_done_sem != NULL) {
        (void)xSemaphoreGive(s_worker_done_sem);
    }
    vTaskDelete(NULL);
}

/* ==============================================================================
 * ESP-IDF FreeRTOS Application Entry Point
 * ============================================================================== */

void app_main(void)
{
    /* Mandatory first statement: validate Stage 1's CRC-sealed .noinit handoff. */
    TOOB_OS_INIT_OR_PANIC();
    toob_espidf_feed_boot_wdt();

    s_worker_done_sem = xSemaphoreCreateBinaryStatic(&s_worker_sem_buf);

    (void)xTaskCreateStatic(
        _wdt_monitor_task,
        "toob_wdt",
        WDT_TASK_STACK_WORDS,
        NULL,
        configMAX_PRIORITIES - 2,
        s_wdt_stack,
        &s_wdt_tcb);

    (void)xTaskCreateStatic(
        _worker_selfcheck_task,
        "toob_wrk",
        WORKER_TASK_STACK_WORDS,
        NULL,
        tskIDLE_PRIORITY + 2,
        s_worker_stack,
        &s_worker_tcb);

    /* Concurrently query handoff & diagnostics from main_task while worker runs. */
    toob_handoff_t handoff;
    toob_boot_diag_t diag;
    toob_status_t h_st = toob_get_handoff(&handoff);
    toob_status_t d_st = toob_get_boot_diag(&diag);

    bool worker_done = (s_worker_done_sem != NULL) &&
                       (xSemaphoreTake(s_worker_done_sem, pdMS_TO_TICKS(2000)) == pdTRUE);
    bool tasks_ok = worker_done && s_worker_selfcheck_ok && (h_st == TOOB_OK) && (d_st == TOOB_OK);

    (void)uart_driver_install(UART_NUM_0, UART_RX_BUF_BYTES, 0, 0, NULL, 0);

    char ver_str[sizeof(s_app_cfg.fw_ver)];
    for (size_t i = 0U; i < sizeof(ver_str); i++) {
        ver_str[i] = s_app_cfg.fw_ver[i];
    }
    ver_str[sizeof(ver_str) - 1U] = '\0';

    int64_t now_us = esp_timer_get_time();
    char out[320];
    (void)snprintf(
        out,
        sizeof(out),
        "[ESPIDF-APP] BOOT ver=%s slot=%u part=0x%X fail_cnt=%u svn=%u outcome=%u timer_us=%lld tasks_ok=%u\r\n",
        ver_str,
        (unsigned)handoff.active_slot,
        (unsigned)handoff.booted_partition,
        (unsigned)handoff.boot_failure_count,
        (unsigned)diag.current_svn,
        (unsigned)diag.last_update_outcome,
        (long long)now_us,
        tasks_ok ? 1U : 0U);
    _uart_send_str(out);

    if (s_app_cfg.simulate_hang != 0U) {
        _uart_send_str("[ESPIDF-APP] SIMULATING_WDT_HANG (skipping toob_confirm_boot, halting WDT feed)\r\n");
        (void)uart_wait_tx_done(UART_NUM_0, pdMS_TO_TICKS(200));
        s_suspend_wdt_feed = true;
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    char cmd[256];
    for (;;) {
        if (!_uart_read_line(cmd, sizeof(cmd), 60000U)) {
            continue;
        }
        if (cmd[0] == '\0') {
            continue;
        }

        if (strcmp(cmd, "DIAG") == 0) {
            toob_boot_diag_t cur_diag;
            uint8_t wire_buf[TOOB_TDR1_MAX_SIZE];
            size_t wire_len = 0U;
            toob_status_t st1 = toob_get_boot_diag(&cur_diag);
            toob_status_t st2 = toob_get_boot_diag_wire(wire_buf, sizeof(wire_buf), &wire_len);
            if ((st1 == TOOB_OK) && (st2 == TOOB_OK) && (wire_len >= TOOB_TDR1_MIN_FRAME_SIZE)) {
                (void)snprintf(
                    out,
                    sizeof(out),
                    "[ESPIDF-APP] DIAG status=OK svn=%u outcome=%u edge=%u key=%u wire_len=%u\r\n",
                    (unsigned)cur_diag.current_svn,
                    (unsigned)cur_diag.last_update_outcome,
                    (unsigned)cur_diag.edge_recovery_events,
                    (unsigned)cur_diag.active_key_index,
                    (unsigned)wire_len);
            } else {
                (void)snprintf(out, sizeof(out), "[ESPIDF-APP] DIAG status=ERR s1=0x%08X s2=0x%08X\r\n",
                               (unsigned)st1, (unsigned)st2);
            }
            _uart_send_str(out);
        } else if (strncmp(cmd, "ENROLL ", 7U) == 0) {
            uint8_t raw_tok[TOOB_DEVICE_TOKEN_LEN];
            memset(raw_tok, 0, sizeof(raw_tok));
            size_t tok_len = 0U;
            if (!_hex_decode_bytes(cmd + 7U, raw_tok, sizeof(raw_tok), &tok_len) ||
                (tok_len != TOOB_DEVICE_TOKEN_LEN)) {
                _uart_send_str("[ESPIDF-APP] ENROLL status=INVALID_HEX\r\n");
                continue;
            }
            toob_status_t wst = toob_cred_enroll(raw_tok);
            toob_device_cred_t rb;
            memset(&rb, 0, sizeof(rb));
            toob_status_t rst = toob_cred_load(&rb);
            bool ok = (wst == TOOB_OK) && (rst == TOOB_OK) &&
                      (rb.checkin_seq == 0ULL) &&
                      (memcmp(raw_tok, rb.device_token, sizeof(raw_tok)) == 0);
            if (ok) {
                (void)snprintf(
                    out,
                    sizeof(out),
                    "[ESPIDF-APP] ENROLL status=OK seq=%llu token_prefix=%02x%02x%02x%02x\r\n",
                    (unsigned long long)rb.checkin_seq,
                    (unsigned)rb.device_token[0],
                    (unsigned)rb.device_token[1],
                    (unsigned)rb.device_token[2],
                    (unsigned)rb.device_token[3]);
            } else {
                (void)snprintf(out, sizeof(out), "[ESPIDF-APP] ENROLL status=ERR w=0x%08X r=0x%08X\r\n",
                               (unsigned)wst, (unsigned)rst);
            }
            memset(raw_tok, 0, sizeof(raw_tok));
            memset(&rb, 0, sizeof(rb));
            _uart_send_str(out);
        } else if (strcmp(cmd, "CRED") == 0) {
            toob_device_cred_t rb;
            toob_status_t rst = toob_cred_load(&rb);
            if (rst == TOOB_OK) {
                (void)snprintf(
                    out,
                    sizeof(out),
                    "[ESPIDF-APP] CRED status=OK seq=%llu token_prefix=%02x%02x%02x%02x\r\n",
                    (unsigned long long)rb.checkin_seq,
                    (unsigned)rb.device_token[0],
                    (unsigned)rb.device_token[1],
                    (unsigned)rb.device_token[2],
                    (unsigned)rb.device_token[3]);
            } else {
                (void)snprintf(out, sizeof(out), "[ESPIDF-APP] CRED status=0x%08X\r\n", (unsigned)rst);
            }
            memset(&rb, 0, sizeof(rb));
            _uart_send_str(out);
        } else if (strcmp(cmd, "CONFIRM") == 0) {
            toob_status_t cst = toob_confirm_boot();
            uint64_t rtc_val = *(const volatile uint64_t *)ESP32C3_CONFIRM_RTC_ADDR;
            bool rtc_match = (handoff.boot_nonce != 0ULL) && (rtc_val == handoff.boot_nonce);
            if (cst == TOOB_OK) {
                (void)snprintf(out, sizeof(out), "[ESPIDF-APP] CONFIRM status=OK rtc_match=%u\r\n",
                               rtc_match ? 1U : 0U);
            } else {
                (void)snprintf(out, sizeof(out), "[ESPIDF-APP] CONFIRM status=0x%08X rtc_match=%u\r\n",
                               (unsigned)cst, rtc_match ? 1U : 0U);
            }
            _uart_send_str(out);
        } else if (strncmp(cmd, "OTA ", 4U) == 0) {
            (void)snprintf(out, sizeof(out), "[ESPIDF-APP] OTA_START url=%s\r\n", cmd + 4U);
            _uart_send_str(out);
            toob_status_t ost = toob_network_trigger_ota(cmd + 4U);
            (void)snprintf(out, sizeof(out), "[ESPIDF-APP] OTA_RESULT status=0x%08X\r\n", (unsigned)ost);
            _uart_send_str(out);
        } else if (strcmp(cmd, "REBOOT") == 0) {
            _uart_send_str("[ESPIDF-APP] REBOOTING\r\n");
            (void)uart_wait_tx_done(UART_NUM_0, pdMS_TO_TICKS(200));
            esp_restart();
        }
    }
}
