#if !defined(_POSIX_C_SOURCE) && !defined(__ZEPHYR__) && !defined(ESP_PLATFORM)
#define _POSIX_C_SOURCE 200809L
#endif

#include "toob_network_client.h"
#include "toob_cloud_cmd_wire.h"
#include "toob_device_cred.h"
#include "libtoob.h"
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* GAP-08: Zephyr requires LOG_MODULE_REGISTER for logging to work */
#if defined(__ZEPHYR__)
    #include <zephyr/kernel.h>
    #include <zephyr/sys/reboot.h>
    LOG_MODULE_REGISTER(toob_client, LOG_LEVEL_INF);
#elif defined(ESP_PLATFORM)
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "esp_system.h"
#elif defined(_WIN32)
    __declspec(dllimport) void __stdcall Sleep(unsigned long dwMilliseconds);
#else
    #include <unistd.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define TOOB_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
    #define TOOB_NOINLINE __declspec(noinline)
#else
    #define TOOB_NOINLINE
#endif

#ifndef CONFIG_TOOB_SERVER_URL
#define CONFIG_TOOB_SERVER_URL "https://api.toob.io"
#endif

#ifndef CONFIG_TOOB_POLL_INTERVAL_SEC
#define CONFIG_TOOB_POLL_INTERVAL_SEC 86400U
#endif

#define TAG "toob_client"

/* Backoff & re-entrancy state */
static uint32_t s_consecutive_failures = 0U;
static uint32_t s_poll_epoch           = 0U;
static bool     s_ota_busy             = false;
static toob_ota_ctx_t s_ota_ctx;

#define TOOB_BACKOFF_BASE_SEC 30U
#define TOOB_BACKOFF_MAX_SEC  1800U /* 30 minutes cap */

/* ============================================================================
 * Constant-Time & Cryptographic Primitives (Zero Heap, Bounded Stack)
 * ============================================================================ */

static void _client_zeroize(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0U) {
        *p++ = 0U;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : : "g"(ptr) : "memory");
#endif
}

static bool _is_all_byte(const uint8_t *buf, size_t len, uint8_t val) {
    uint8_t diff = 0U;
    for (size_t i = 0U; i < len; i++) {
        diff |= (uint8_t)(buf[i] ^ val);
    }
    return (diff == 0U);
}

static bool _ct_memeq_glitch_safe(const uint8_t *a, const uint8_t *b, size_t len) {
    if (len == 0U) {
        return false;
    }
    volatile uint32_t acc_fwd = 0U;
    volatile uint32_t acc_rev = 0U;
    for (size_t i = 0U; i < len; i++) {
        acc_fwd |= (uint32_t)(a[i] ^ b[i]);
        acc_rev |= (uint32_t)(a[(len - 1U) - i] ^ b[(len - 1U) - i]);
    }
    volatile uint32_t s1 = 0U;
    volatile uint32_t s2 = 0U;
    if (acc_fwd == 0U) {
        s1 = TOOB_OK;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" ::: "memory");
#endif
    if (s1 == TOOB_OK && acc_rev == 0U) {
        s2 = TOOB_OK;
    }
    return (s1 == TOOB_OK) && (s2 == TOOB_OK) && (s1 == s2);
}

/* Streaming RFC 2104 HMAC-SHA256 atop toob_os_sha256_* (32-byte key). */
static toob_status_t _hmac_sha256_3part(
    const uint8_t key[32],
    const uint8_t *p1, uint32_t p1_len,
    const uint8_t *p2, uint32_t p2_len,
    const uint8_t *p3, uint32_t p3_len,
    uint8_t out_mac[32]) {
    toob_os_sha256_ctx_t sha_ctx;
    uint8_t pad[64];
    uint8_t inner_hash[32];

    _client_zeroize(&sha_ctx, sizeof(sha_ctx));
    _client_zeroize(pad, sizeof(pad));
    _client_zeroize(inner_hash, sizeof(inner_hash));

    for (size_t i = 0U; i < 32U; i++) {
        pad[i] = (uint8_t)(key[i] ^ 0x36U);
    }
    for (size_t i = 32U; i < 64U; i++) {
        pad[i] = 0x36U;
    }

    toob_status_t st = toob_os_sha256_init(&sha_ctx);
    if (st == TOOB_OK) {
        st = toob_os_sha256_update(&sha_ctx, pad, 64U);
    }
    if (st == TOOB_OK && p1 != NULL && p1_len > 0U) {
        st = toob_os_sha256_update(&sha_ctx, p1, p1_len);
    }
    if (st == TOOB_OK && p2 != NULL && p2_len > 0U) {
        st = toob_os_sha256_update(&sha_ctx, p2, p2_len);
    }
    if (st == TOOB_OK && p3 != NULL && p3_len > 0U) {
        st = toob_os_sha256_update(&sha_ctx, p3, p3_len);
    }
    if (st == TOOB_OK) {
        st = toob_os_sha256_finalize(&sha_ctx, inner_hash);
    }

    if (st == TOOB_OK) {
        for (size_t i = 0U; i < 32U; i++) {
            pad[i] = (uint8_t)(key[i] ^ 0x5CU);
        }
        for (size_t i = 32U; i < 64U; i++) {
            pad[i] = 0x5CU;
        }
        st = toob_os_sha256_init(&sha_ctx);
    }
    if (st == TOOB_OK) {
        st = toob_os_sha256_update(&sha_ctx, pad, 64U);
    }
    if (st == TOOB_OK) {
        st = toob_os_sha256_update(&sha_ctx, inner_hash, 32U);
    }
    if (st == TOOB_OK) {
        st = toob_os_sha256_finalize(&sha_ctx, out_mac);
    }

    _client_zeroize(&sha_ctx, sizeof(sha_ctx));
    _client_zeroize(pad, sizeof(pad));
    _client_zeroize(inner_hash, sizeof(inner_hash));
    return st;
}

/* ============================================================================
 * Closed O(n) RFC-3986 Relative-Path DFA (Zero <string.h>, TCI1-07 / FV-03)
 * ============================================================================ */

static bool _is_unreserved_ascii(uint8_t c) {
    return ((c >= (uint8_t)'A' && c <= (uint8_t)'Z') ||
            (c >= (uint8_t)'a' && c <= (uint8_t)'z') ||
            (c >= (uint8_t)'0' && c <= (uint8_t)'9') ||
            c == (uint8_t)'-' || c == (uint8_t)'.' ||
            c == (uint8_t)'_' || c == (uint8_t)'~');
}

static bool _validate_blob_path_dfa(const uint8_t *p, size_t n) {
    if (!p || n < 2U || n > TOOB_TCI1_MAX_BLOB_PATH_LEN || p[0] != (uint8_t)'/') {
        return false;
    }

    bool in_query = false;
    uint32_t seg_len = 0U;
    uint8_t dot_count = 0U; /* 0..2 while segment is all '.', 255 otherwise */
    uint32_t q_len = 0U;

    for (size_t i = 1U; i < n; i++) {
        uint8_t c = p[i];
        if (!in_query) {
            if (c == (uint8_t)'?') {
                if (seg_len == 0U || dot_count == 1U || dot_count == 2U) {
                    return false;
                }
                in_query = true;
                continue;
            }
            if (c == (uint8_t)'/') {
                if (seg_len == 0U || dot_count == 1U || dot_count == 2U) {
                    return false;
                }
                seg_len = 0U;
                dot_count = 0U;
                continue;
            }
            if (!_is_unreserved_ascii(c)) {
                return false;
            }
            seg_len++;
            if (c == (uint8_t)'.' && dot_count < 3U) {
                dot_count++;
            } else {
                dot_count = 255U;
            }
        } else {
            if (!_is_unreserved_ascii(c) && c != (uint8_t)'&' && c != (uint8_t)'=') {
                return false;
            }
            q_len++;
        }
    }

    if (!in_query) {
        if (seg_len == 0U || dot_count == 1U || dot_count == 2U) {
            return false;
        }
    } else if (q_len == 0U) {
        return false;
    }
    return true;
}

static bool _validate_cloud_cmd_precheck(const uint8_t *cmd, size_t n) {
    if (!cmd ||
        n < TOOB_TCI1_MIN_CLOUD_CMD_LEN ||
        n > TOOB_TCI1_MAX_CLOUD_CMD_LEN ||
        (n % TOOB_CLOUD_CMD_ALIGN) != 0U) {
        return false;
    }
    if (toob_wire_get_le32(&cmd[0]) != TOOB_CLOUD_CMD_MAGIC ||
        cmd[4] != TOOB_CLOUD_CMD_VERSION) {
        return false;
    }
    if (toob_wire_get_le32(&cmd[20]) != (uint32_t)n) {
        return false;
    }
    return true;
}

/* ============================================================================
 * Phase 1: Const-Pure Authenticated TCI1 Parser (TCI1-06 / TCI1-07)
 * ============================================================================ */

toob_status_t toob_tci1_parse(
    const uint8_t *data,
    size_t len,
    const uint8_t token_key[32],
    const uint8_t device_id[32],
    uint64_t expected_seq,
    toob_update_info_t *out,
    const uint8_t **out_cloud_cmd,
    uint16_t *out_cloud_cmd_len) {
    if (out_cloud_cmd != NULL) {
        *out_cloud_cmd = NULL;
    }
    if (out_cloud_cmd_len != NULL) {
        *out_cloud_cmd_len = 0U;
    }
    if (!data || !token_key || !device_id || !out) {
        return TOOB_ERR_INVALID_ARG;
    }
    _client_zeroize(out, sizeof(*out));

    if (_is_all_byte(token_key, 32U, 0x00U) ||
        _is_all_byte(token_key, 32U, 0xFFU) ||
        expected_seq == 0ULL ||
        len < TOOB_TCI1_MIN_FRAME_SIZE ||
        len > TOOB_TCI1_MAX_FRAME_SIZE) {
        return TOOB_ERR_VERIFY;
    }

    /* Encrypt-then-MAC (EtM): Verify 128-bit HMAC-SHA256 BEFORE reading header offsets
     * or unmasking rotated_token (TCI1-06). */
    size_t body_len = len - TOOB_TCI1_AUTH_TAG_LEN;
    uint8_t calc_mac[32];
    _client_zeroize(calc_mac, sizeof(calc_mac));
    toob_status_t mac_st = _hmac_sha256_3part(
        token_key,
        (const uint8_t *)TOOB_TCI1_AUTH_DOMAIN, TOOB_TCI1_AUTH_DOMAIN_LEN,
        device_id, 32U,
        data, (uint32_t)body_len,
        calc_mac);
    bool auth_ok = (mac_st == TOOB_OK) &&
                   _ct_memeq_glitch_safe(calc_mac, &data[body_len], TOOB_TCI1_AUTH_TAG_LEN);
    _client_zeroize(calc_mac, sizeof(calc_mac));
    if (!auth_ok) {
        return TOOB_ERR_VERIFY;
    }

    uint32_t magic = toob_wire_get_le32(&data[0]);
    uint8_t  version = data[4];
    uint8_t  target_slot = data[5];
    uint16_t flags = toob_wire_get_le16(&data[6]);
    uint16_t hdr_size = toob_wire_get_le16(&data[8]);
    uint16_t blob_path_len = toob_wire_get_le16(&data[10]);
    uint16_t cloud_cmd_len = toob_wire_get_le16(&data[12]);
    uint16_t reserved0 = toob_wire_get_le16(&data[14]);

    if (magic != TOOB_TCI1_MAGIC ||
        version != TOOB_TCI1_VERSION ||
        (flags & (uint16_t)~TOOB_TCI1_KNOWN_FLAGS_MASK) != 0U ||
        hdr_size < TOOB_TCI1_HDR_SIZE ||
        (hdr_size % 8U) != 0U ||
        (size_t)hdr_size > body_len ||
        reserved0 != 0U) {
        return TOOB_ERR_VERIFY;
    }

    bool has_rot = ((flags & TOOB_TCI1_FLAG_HAS_ROTATED_TOKEN) != 0U);
    bool has_cmd = ((flags & TOOB_TCI1_FLAG_HAS_CLOUD_CMD) != 0U);
    if (!has_cmd && cloud_cmd_len != 0U) {
        return TOOB_ERR_VERIFY;
    }

    size_t rot_len = has_rot ? TOOB_TCI1_ROTATED_TOKEN_LEN : 0U;
    size_t expected_body = (size_t)hdr_size + (size_t)blob_path_len + rot_len + (size_t)cloud_cmd_len;
    if (expected_body != body_len) {
        return TOOB_ERR_VERIFY;
    }

    uint32_t remote_svn = toob_wire_get_le32(&data[16]);
    uint32_t total_size = toob_wire_get_le32(&data[20]);
    uint64_t seq_echo = toob_wire_get_le64(&data[72]);
    uint32_t remote_build = toob_wire_get_le32(&data[80]);
    uint32_t retry_after_sec = toob_wire_get_le32(&data[84]);

    if (seq_echo != expected_seq || retry_after_sec > TOOB_TCI1_MAX_RETRY_AFTER_SEC) {
        return TOOB_ERR_VERIFY;
    }

    size_t cursor = (size_t)hdr_size;

    if (total_size > 0U) {
        bool slot_valid = (target_slot == TOOB_TCI1_SLOT_APP ||
                           target_slot == TOOB_TCI1_SLOT_NETCORE ||
                           target_slot == TOOB_TCI1_SLOT_STAGE1);
        if (total_size < TOOB_TCI1_MIN_TBM1_TOTAL_SIZE ||
            !slot_valid ||
            _is_all_byte(&data[24], 32U, 0x00U) ||
            _is_all_byte(&data[24], 32U, 0xFFU) ||
            _is_all_byte(&data[56], 16U, 0x00U) ||
            !_validate_blob_path_dfa(&data[cursor], (size_t)blob_path_len)) {
            return TOOB_ERR_VERIFY;
        }

        for (size_t i = 0U; i < (size_t)blob_path_len; i++) {
            out->blob_path[i] = (char)data[cursor + i];
        }
        out->blob_path[blob_path_len] = '\0';
        for (size_t i = 0U; i < 32U; i++) {
            out->sha256[i] = data[24U + i];
        }
        for (size_t i = 0U; i < 16U; i++) {
            out->assignment_id[i] = data[56U + i];
        }
        out->total_size = total_size;
        out->target_slot = target_slot;
        out->remote_svn = remote_svn;
        out->remote_build = remote_build;
        out->update_available = true;
    } else {
        if ((!has_rot && !has_cmd) ||
            target_slot != 0U ||
            remote_svn != 0U ||
            remote_build != 0U ||
            blob_path_len != 0U ||
            !_is_all_byte(&data[24], 32U, 0x00U) ||
            !_is_all_byte(&data[56], 16U, 0x00U)) {
            return TOOB_ERR_VERIFY;
        }
        out->update_available = false;
    }
    out->retry_after_sec = retry_after_sec;
    cursor += (size_t)blob_path_len;

    if (has_rot) {
        uint8_t seq_le[8];
        uint8_t mask[32];
        toob_wire_put_le64(seq_le, seq_echo);
        _client_zeroize(mask, sizeof(mask));

        toob_status_t rot_st = _hmac_sha256_3part(
            token_key,
            (const uint8_t *)TOOB_TCI1_ROT_DOMAIN, TOOB_TCI1_ROT_DOMAIN_LEN,
            device_id, 32U,
            seq_le, 8U,
            mask);
        _client_zeroize(seq_le, sizeof(seq_le));
        if (rot_st != TOOB_OK) {
            _client_zeroize(mask, sizeof(mask));
            _client_zeroize(out, sizeof(*out));
            return TOOB_ERR_VERIFY;
        }

        for (size_t i = 0U; i < TOOB_TCI1_ROTATED_TOKEN_LEN; i++) {
            out->rotated_token[i] = (uint8_t)(data[cursor + i] ^ mask[i]);
        }
        _client_zeroize(mask, sizeof(mask));
        cursor += TOOB_TCI1_ROTATED_TOKEN_LEN;

        if (_is_all_byte(out->rotated_token, 32U, 0x00U) ||
            _is_all_byte(out->rotated_token, 32U, 0xFFU)) {
            _client_zeroize(out, sizeof(*out));
            return TOOB_ERR_VERIFY;
        }
        out->has_rotated_token = true;
    }

    if (has_cmd) {
        if (!_validate_cloud_cmd_precheck(&data[cursor], (size_t)cloud_cmd_len)) {
            _client_zeroize(out, sizeof(*out));
            return TOOB_ERR_VERIFY;
        }
        if (out_cloud_cmd != NULL) {
            *out_cloud_cmd = &data[cursor];
        }
        if (out_cloud_cmd_len != NULL) {
            *out_cloud_cmd_len = cloud_cmd_len;
        }
    }

    return TOOB_OK;
}

/* ============================================================================
 * HTTP Streaming Callbacks with Pre-Write Status Gating (TCI1-04)
 * ============================================================================ */

typedef struct {
    uint8_t         buf[TOOB_TCI1_MAX_FRAME_SIZE];
    size_t          len;
    const uint16_t *http_status;
    bool            rejected_by_status;
} tci1_manifest_rx_t;

static toob_status_t _manifest_chunk_cb(const uint8_t *chunk, uint32_t len, void *ctx) {
    tci1_manifest_rx_t *rx = (tci1_manifest_rx_t *)ctx;
    if (!chunk || !rx || !rx->http_status) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (*rx->http_status != 200U) {
        rx->rejected_by_status = true;
        return TOOB_ERR_STATE;
    }
    if (len > sizeof(rx->buf) || rx->len > (sizeof(rx->buf) - (size_t)len)) {
        return TOOB_ERR_INVALID_ARG;
    }
    memcpy(&rx->buf[rx->len], chunk, len);
    rx->len += (size_t)len;
    return TOOB_OK;
}

typedef struct {
    toob_ota_ctx_t *ota;
    const uint16_t *http_status;
    uint16_t        expected_status;
    bool            rejected_by_status;
} ota_payload_rx_t;

static toob_status_t _payload_chunk_cb(const uint8_t *chunk, uint32_t len, void *user_ctx) {
    ota_payload_rx_t *rx = (ota_payload_rx_t *)user_ctx;
    if (!chunk || !rx || !rx->ota || !rx->http_status) {
        return TOOB_ERR_INVALID_ARG;
    }
    /* TCI1-04: Reject non-expected HTTP status BEFORE touching staging flash! */
    if (*rx->http_status != rx->expected_status) {
        rx->rejected_by_status = true;
        return TOOB_ERR_STATE;
    }
    toob_status_t stat = toob_ota_process_chunk(rx->ota, chunk, len);
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Failed to process OTA chunk: 0x%08X", (unsigned)stat);
    }
    return stat;
}

/* ============================================================================
 * Backoff & Deterministic Device-ID Jitter (TCI1-03)
 * ============================================================================ */

static uint32_t _calculate_backoff_sec(void) {
    if (s_consecutive_failures == 0U) {
        return CONFIG_TOOB_POLL_INTERVAL_SEC;
    }
    uint32_t backoff = TOOB_BACKOFF_BASE_SEC;
    for (uint32_t i = 1U; i < s_consecutive_failures && i < 10U; i++) {
        backoff *= 2U;
        if (backoff >= TOOB_BACKOFF_MAX_SEC) {
            backoff = TOOB_BACKOFF_MAX_SEC;
            break;
        }
    }
    return backoff;
}

static uint32_t _apply_device_jitter(uint32_t base_sec) {
    if (base_sec < 8U) {
        return base_sec;
    }
    uint8_t dev_id[32];
    uint32_t seed = s_poll_epoch++;
    if (toob_get_device_id(dev_id, sizeof(dev_id)) == TOOB_OK) {
        uint8_t mix[36];
        memcpy(mix, dev_id, 32U);
        toob_wire_put_le32(&mix[32], seed);
        seed = toob_lib_crc32(mix, sizeof(mix));
        _client_zeroize(mix, sizeof(mix));
    }
    _client_zeroize(dev_id, sizeof(dev_id));

    uint32_t span = base_sec / 8U; /* +/- 12.5% */
    uint32_t window = (2U * span) + 1U;
    uint32_t offset = seed % window;
    return (base_sec - span) + offset;
}

static void _hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0U; i < len; i++) {
        out[2U * i] = digits[(size_t)(in[i] >> 4U)];
        out[(2U * i) + 1U] = digits[(size_t)(in[i] & 0x0FU)];
    }
    out[2U * len] = '\0';
}

/* ============================================================================
 * Stack-Segregated Phase 1 (Check-In) & Phase 3 (Download) Helpers (TCI1-07)
 * ============================================================================ */

static TOOB_NOINLINE toob_status_t _checkin_phase(
    const char *server_url,
    toob_update_info_t *out_info,
    uint32_t *out_app_svn,
    uint32_t *out_stage1_svn,
    uint32_t *out_app_build,
    uint32_t *out_retry_after_s,
    bool *out_healthy_noop,
    bool *out_cmd_staged) {
    _client_zeroize(out_info, sizeof(*out_info));
    *out_app_svn = 0U;
    *out_stage1_svn = 0U;
    *out_app_build = 0U;
    *out_retry_after_s = 0U;
    *out_healthy_noop = false;
    *out_cmd_staged = false;

    toob_device_cred_t cred;
    toob_status_t cred_stat = toob_cred_load(&cred);
    if (cred_stat != TOOB_OK) {
        TOOB_LOGE(TAG, "No valid device credentials in OS-NVS (0x%08X), skipping checkin", (unsigned)cred_stat);
        _client_zeroize(&cred, sizeof(cred));
        return cred_stat;
    }

    toob_boot_diag_t diag;
    if (toob_get_boot_diag(&diag) == TOOB_OK) {
        *out_app_svn = (diag.installed_app_svn > diag.current_svn)
                           ? diag.installed_app_svn
                           : diag.current_svn;
        *out_stage1_svn = diag.installed_stage1_svn;
        *out_app_build = diag.build_number;
    }
    _client_zeroize(&diag, sizeof(diag));

    uint8_t dev_id[32];
    toob_status_t id_stat = toob_get_device_id(dev_id, sizeof(dev_id));
    if (id_stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Failed to obtain device ID");
        _client_zeroize(&cred, sizeof(cred));
        return id_stat;
    }

    char dev_id_hex[(2U * sizeof(dev_id)) + 1U];
    _hex_encode(dev_id, sizeof(dev_id), dev_id_hex);

    char check_url[256];
    int written = snprintf(check_url, sizeof(check_url), "%s/v1/devices/%s/checkin", server_url, dev_id_hex);
    if (written < 0 || (size_t)written >= sizeof(check_url)) {
        TOOB_LOGE(TAG, "Check URL truncated");
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return TOOB_ERR_INVALID_ARG;
    }

    /* Persist monotonic sequence BEFORE serializing TDR1 so checkin_seq == X-Toob-Seq (TDR1-04). */
    uint64_t seq = 0ULL;
    toob_status_t seq_stat = toob_cred_bump_seq(&seq);
    if (seq_stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Failed to persist check-in sequence (0x%08X)", (unsigned)seq_stat);
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return seq_stat;
    }

    uint8_t diag_buf[TOOB_TDR1_MAX_SIZE];
    size_t diag_len = 0U;
    toob_status_t wire_stat = toob_get_boot_diag_wire_seq(diag_buf, sizeof(diag_buf), seq, &diag_len);
    if (wire_stat != TOOB_OK || diag_len > UINT32_MAX) {
        TOOB_LOGE(TAG, "Failed to serialize TDR1 boot diagnostics");
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return (wire_stat != TOOB_OK) ? wire_stat : TOOB_ERR_FLASH;
    }

    char token_hex[(2U * TOOB_DEVICE_TOKEN_LEN) + 1U];
    _hex_encode(cred.device_token, TOOB_DEVICE_TOKEN_LEN, token_hex);

    char auth_hdr[sizeof("Authorization: Bearer \r\n") + (2U * TOOB_DEVICE_TOKEN_LEN)];
    written = snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s\r\n", token_hex);
    _client_zeroize(token_hex, sizeof(token_hex));
    if (written < 0 || (size_t)written >= sizeof(auth_hdr)) {
        _client_zeroize(auth_hdr, sizeof(auth_hdr));
        _client_zeroize(diag_buf, sizeof(diag_buf));
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return TOOB_ERR_INVALID_ARG;
    }

    char seq_hdr[64];
    written = snprintf(seq_hdr, sizeof(seq_hdr), "X-Toob-Seq: %llu\r\n", (unsigned long long)seq);
    if (written < 0 || (size_t)written >= sizeof(seq_hdr)) {
        _client_zeroize(auth_hdr, sizeof(auth_hdr));
        _client_zeroize(diag_buf, sizeof(diag_buf));
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return TOOB_ERR_INVALID_ARG;
    }

    const char *const headers[3] = {
        auth_hdr,
        "Content-Type: application/octet-stream\r\n",
        seq_hdr
    };

    uint16_t http_status = 0U;
    uint32_t retry_after = 0U;
    tci1_manifest_rx_t mrx;
    _client_zeroize(&mrx, sizeof(mrx));
    mrx.http_status = &http_status;

    toob_status_t stat = rtos_http_request(TOOB_HTTP_POST, check_url,
                                           headers, 3U,
                                           diag_buf, (uint32_t)diag_len, 0U,
                                           _manifest_chunk_cb, &mrx,
                                           &http_status, &retry_after);
    _client_zeroize(auth_hdr, sizeof(auth_hdr));
    _client_zeroize(diag_buf, sizeof(diag_buf));

    if (retry_after > 0U && retry_after <= TOOB_TCI1_MAX_RETRY_AFTER_SEC) {
        *out_retry_after_s = retry_after;
    }

    if (stat != TOOB_OK && !mrx.rejected_by_status) {
        _client_zeroize(&mrx, sizeof(mrx));
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        TOOB_LOGE(TAG, "Checkin POST failed (transport error 0x%08X)", (unsigned)stat);
        return stat;
    }

    /* TCI1-03: Distinguish healthy 204 No Content from empty 200 OK truncation! */
    if (http_status == 204U) {
        TOOB_LOGI(TAG, "No update available (204 No Content, App SVN: %u)", (unsigned)*out_app_svn);
        *out_healthy_noop = true;
        _client_zeroize(&mrx, sizeof(mrx));
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return TOOB_ERR_NOT_FOUND;
    }
    if (http_status != 200U) {
        TOOB_LOGW(TAG, "Checkin HTTP status: %u (Retry-After: %u s)", (unsigned)http_status, (unsigned)retry_after);
        _client_zeroize(&mrx, sizeof(mrx));
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return TOOB_ERR_NOT_FOUND;
    }
    if (mrx.len < TOOB_TCI1_MIN_FRAME_SIZE) {
        TOOB_LOGE(TAG, "Truncated 200 OK TCI1 response (%u bytes)", (unsigned)mrx.len);
        _client_zeroize(&mrx, sizeof(mrx));
        _client_zeroize(dev_id, sizeof(dev_id));
        _client_zeroize(&cred, sizeof(cred));
        return TOOB_ERR_VERIFY;
    }

    const uint8_t *cloud_cmd_ptr = NULL;
    uint16_t cloud_cmd_len = 0U;
    toob_status_t parse_st = toob_tci1_parse(
        mrx.buf, mrx.len, cred.device_token, dev_id, seq,
        out_info, &cloud_cmd_ptr, &cloud_cmd_len);
    _client_zeroize(dev_id, sizeof(dev_id));
    _client_zeroize(&cred, sizeof(cred));

    if (parse_st == TOOB_OK && cloud_cmd_ptr != NULL && cloud_cmd_len > 0U) {
        toob_status_t cmd_st = toob_submit_cloud_command(cloud_cmd_ptr, (uint32_t)cloud_cmd_len);
        if (cmd_st == TOOB_OK) {
            *out_cmd_staged = true;
        } else {
            TOOB_LOGW(TAG, "Cloud command submission failed: 0x%08X", (unsigned)cmd_st);
        }
    }
    _client_zeroize(&mrx, sizeof(mrx));

    if (parse_st != TOOB_OK) {
        _client_zeroize(out_info, sizeof(*out_info));
        TOOB_LOGE(TAG, "Failed to authenticate/parse TCI1 manifest");
        return parse_st;
    }

    if (out_info->retry_after_sec > 0U) {
        *out_retry_after_s = out_info->retry_after_sec;
    }

    if (out_info->has_rotated_token) {
        TOOB_LOGI(TAG, "Persisting authenticated rotated token to NVS...");
        toob_status_t rot_stat = toob_cred_rotate_token(out_info->rotated_token);
        if (rot_stat != TOOB_OK) {
            TOOB_LOGE(TAG, "Failed to persist rotated token: 0x%08X", (unsigned)rot_stat);
        }
        _client_zeroize(out_info->rotated_token, sizeof(out_info->rotated_token));
    }

    return TOOB_OK;
}

static TOOB_NOINLINE toob_status_t _download_and_finalize_phase(
    const char *server_url,
    const toob_update_info_t *info,
    uint32_t *inout_retry_after_s) {
    uint32_t resume_offset = 0U;
    toob_status_t stat = toob_ota_resume_assigned(
        &s_ota_ctx, info->total_size, info->sha256, info->assignment_id, &resume_offset);
    if (stat == TOOB_OK) {
        TOOB_LOGI(TAG, "Resuming verified download from offset %u", (unsigned)resume_offset);
    } else {
        stat = toob_ota_begin_assigned(
            &s_ota_ctx, info->total_size, info->sha256, info->assignment_id);
        if (stat != TOOB_OK) {
            TOOB_LOGE(TAG, "OTA begin failed: 0x%08X", (unsigned)stat);
            return stat;
        }
        resume_offset = 0U;
    }

    char download_url[256];
    int written = snprintf(download_url, sizeof(download_url), "%s%s", server_url, info->blob_path);
    if (written < 0 || (size_t)written >= sizeof(download_url)) {
        TOOB_LOGE(TAG, "Download URL truncated");
        toob_status_t pause_rc = toob_ota_pause(&s_ota_ctx);
        (void)pause_rc;
        return TOOB_ERR_INVALID_ARG;
    }

    uint16_t http_status = 0U;
    uint32_t retry_after = 0U;
    uint16_t expected_http = (resume_offset > 0U) ? 206U : 200U;
    ota_payload_rx_t prx = {
        .ota = &s_ota_ctx,
        .http_status = &http_status,
        .expected_status = expected_http,
        .rejected_by_status = false,
    };

    stat = rtos_http_request(TOOB_HTTP_GET, download_url,
                             NULL, 0U, NULL, 0U, resume_offset,
                             _payload_chunk_cb, &prx,
                             &http_status, &retry_after);
    if (retry_after > 0U && retry_after <= TOOB_TCI1_MAX_RETRY_AFTER_SEC) {
        *inout_retry_after_s = retry_after;
    }

    if (stat != TOOB_OK && !prx.rejected_by_status) {
        TOOB_LOGE(TAG, "Download interrupted: 0x%08X (preserving checkpoint)", (unsigned)stat);
        toob_status_t pause_rc = toob_ota_pause(&s_ota_ctx);
        (void)pause_rc;
        return stat;
    }

    if (http_status == 416U || (resume_offset > 0U && http_status == 200U)) {
        TOOB_LOGW(TAG, "Range resume rejected (HTTP %u), resetting checkpoint", (unsigned)http_status);
        toob_status_t abort_rc = toob_ota_abort(&s_ota_ctx);
        (void)abort_rc;
        return TOOB_ERR_NOT_FOUND;
    }
    if (http_status != expected_http || prx.rejected_by_status) {
        TOOB_LOGE(TAG, "Download rejected with HTTP %u (preserving checkpoint)", (unsigned)http_status);
        toob_status_t pause_rc = toob_ota_pause(&s_ota_ctx);
        (void)pause_rc;
        return TOOB_ERR_NOT_FOUND;
    }

    stat = toob_ota_finalize(&s_ota_ctx);
    if (stat == TOOB_ERR_WAL_LOCKED) {
        TOOB_LOGW(TAG, "WAL locked: previous update pending, reboot to consume");
    } else if (stat == TOOB_ERR_VERIFY) {
        TOOB_LOGE(TAG, "Finalize failed: SHA-256 mismatch (aborting checkpoint)");
        toob_status_t abort_rc = toob_ota_abort(&s_ota_ctx);
        (void)abort_rc;
    } else if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Finalize failed: 0x%08X", (unsigned)stat);
    }
    return stat;
}

/* ============================================================================
 * Main OTA Cycle & Daemon Loop (UPD-004, UPD-005, TCI1-01..08)
 * ============================================================================ */

static toob_status_t _run_ota_cycle(
    const char *server_url,
    uint32_t *out_retry_after_s,
    bool *out_healthy_noop) {
    if (!server_url) {
        server_url = CONFIG_TOOB_SERVER_URL;
    }
    if (out_retry_after_s != NULL) {
        *out_retry_after_s = 0U;
    }
    if (out_healthy_noop != NULL) {
        *out_healthy_noop = false;
    }

    /* Non-blocking re-entrancy guard protected by OS mutex (TCI1-07). */
    toob_os_lock();
    if (s_ota_busy) {
        toob_os_unlock();
        return TOOB_ERR_STATE;
    }
    s_ota_busy = true;
    toob_os_unlock();

    toob_status_t final_stat = TOOB_OK;
    static bool s_net_init = false;
    if (!s_net_init) {
        final_stat = toob_network_init();
        if (final_stat == TOOB_OK) {
            final_stat = toob_ota_ctx_init(&s_ota_ctx);
        }
        if (final_stat != TOOB_OK) {
            TOOB_LOGE(TAG, "L1 Smoke Test failed");
            toob_os_lock();
            s_ota_busy = false;
            toob_os_unlock();
            return final_stat;
        }
        TOOB_LOGI(TAG, "L1 Smoke Test passed");
        s_net_init = true;
    }

    toob_update_info_t info;
    uint32_t app_svn = 0U;
    uint32_t stage1_svn = 0U;
    uint32_t app_build = 0U;
    uint32_t retry_s = 0U;
    bool healthy_noop = false;
    bool cmd_staged = false;

    final_stat = _checkin_phase(
        server_url, &info, &app_svn, &stage1_svn, &app_build,
        &retry_s, &healthy_noop, &cmd_staged);

    if (final_stat == TOOB_OK) {
        if (!info.update_available) {
            if (cmd_staged) {
                final_stat = TOOB_ERR_REQUIRES_RESET;
                TOOB_LOGI(TAG, "Cloud command staged in control-only check-in. Rebooting...");
#if defined(__ZEPHYR__)
                sys_reboot(SYS_REBOOT_WARM);
#elif defined(ESP_PLATFORM)
                esp_restart();
#endif
            } else {
                healthy_noop = true;
                final_stat = TOOB_ERR_NOT_FOUND;
            }
        } else {
            /* TCI1-01: Target-slot-specific SVN & build_number admissibility check. */
            uint32_t slot_svn = (info.target_slot == TOOB_TCI1_SLOT_STAGE1)
                                    ? stage1_svn
                                    : app_svn;
            if (info.remote_svn < slot_svn) {
                TOOB_LOGW(TAG, "Rejected downgrade: remote SVN %u < slot %u floor %u",
                          (unsigned)info.remote_svn, (unsigned)info.target_slot, (unsigned)slot_svn);
                final_stat = TOOB_ERR_VERIFY;
            } else if (info.remote_svn == slot_svn &&
                       (info.target_slot != TOOB_TCI1_SLOT_APP || info.remote_build <= app_build)) {
                TOOB_LOGI(TAG, "Slot %u already at SVN %u (build %u)",
                          (unsigned)info.target_slot, (unsigned)slot_svn, (unsigned)app_build);
                healthy_noop = true;
                final_stat = TOOB_ERR_NOT_FOUND;
            } else {
                TOOB_LOGI(TAG, "Update available: slot=%u, size=%u, svn=%u, build=%u, path=%s",
                          (unsigned)info.target_slot, (unsigned)info.total_size,
                          (unsigned)info.remote_svn, (unsigned)info.remote_build, info.blob_path);
                final_stat = _download_and_finalize_phase(server_url, &info, &retry_s);
            }
        }
    }

    _client_zeroize(&info, sizeof(info));

    if (out_retry_after_s != NULL) {
        *out_retry_after_s = retry_s;
    }
    if (out_healthy_noop != NULL) {
        *out_healthy_noop = healthy_noop;
    }

    toob_os_lock();
    s_ota_busy = false;
    toob_os_unlock();

    if (final_stat == TOOB_OK) {
        TOOB_LOGI(TAG, "OTA update staged successfully. Rebooting...");
#if defined(__ZEPHYR__)
        sys_reboot(SYS_REBOOT_WARM);
#elif defined(ESP_PLATFORM)
        esp_restart();
#endif
    }

    return final_stat;
}

toob_status_t toob_network_trigger_ota(const char *server_url) {
    return _run_ota_cycle(server_url, NULL, NULL);
}

_Noreturn void toob_network_daemon_loop(void) {
    while (1) {
        uint32_t server_retry_s = 0U;
        bool healthy_noop = false;
        toob_status_t result = _run_ota_cycle(NULL, &server_retry_s, &healthy_noop);

        uint32_t sleep_sec;
        if (result == TOOB_OK || healthy_noop) {
            s_consecutive_failures = 0U;
            sleep_sec = (server_retry_s > 0U)
                            ? _apply_device_jitter(server_retry_s)
                            : _apply_device_jitter(CONFIG_TOOB_POLL_INTERVAL_SEC);
        } else {
            if (s_consecutive_failures < UINT32_MAX) {
                s_consecutive_failures++;
            }
            sleep_sec = (server_retry_s > 0U)
                            ? _apply_device_jitter(server_retry_s)
                            : _apply_device_jitter(_calculate_backoff_sec());
            TOOB_LOGW(TAG, "Retry in %u seconds (failures: %u)",
                      (unsigned)sleep_sec, (unsigned)s_consecutive_failures);
        }

#if defined(__ZEPHYR__)
        k_sleep(K_SECONDS(sleep_sec));
#elif defined(ESP_PLATFORM)
        uint32_t remaining = sleep_sec;
        while (remaining > 0U) {
            uint32_t chunk = (remaining > 60U) ? 60U : remaining;
            vTaskDelay(pdMS_TO_TICKS(chunk * 1000U));
            remaining -= chunk;
        }
#elif defined(_WIN32)
        uint32_t rem_s = sleep_sec;
        while (rem_s > 0U) {
            uint32_t chunk_s = (rem_s > 3600U) ? 3600U : rem_s;
            Sleep((unsigned long)(chunk_s * 1000U));
            rem_s -= chunk_s;
        }
#else
        sleep(sleep_sec);
#endif
    }
}
