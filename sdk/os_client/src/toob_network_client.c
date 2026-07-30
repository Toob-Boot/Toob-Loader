#include "toob_network_client.h"
#include "toob_device_cred.h"
#include "libtoob.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* ZCBOR API for SUIT/Meta Parsing */
#include <zcbor_decode.h>

/* GAP-08: Zephyr requires LOG_MODULE_REGISTER for logging to work */
#if defined(__ZEPHYR__)
    #include <zephyr/kernel.h>
    #include <zephyr/sys/reboot.h>
    LOG_MODULE_REGISTER(toob_client, LOG_LEVEL_INF);
#elif defined(ESP_PLATFORM)
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "esp_system.h"
#else
    #include <unistd.h>
#endif

#ifndef CONFIG_TOOB_SERVER_URL
#define CONFIG_TOOB_SERVER_URL "https://api.toob.io"
#endif

#ifndef CONFIG_TOOB_POLL_INTERVAL_SEC
#define CONFIG_TOOB_POLL_INTERVAL_SEC 86400
#endif

static const char *TAG = "toob_client";

/* Backoff state for exponential retry */
static uint32_t s_consecutive_failures = 0;
#define TOOB_BACKOFF_BASE_SEC     30
#define TOOB_BACKOFF_MAX_SEC      1800  /* 30 minutes cap */

static uint32_t _calculate_backoff_sec(void) {
    if (s_consecutive_failures == 0) {
        return CONFIG_TOOB_POLL_INTERVAL_SEC;
    }
    uint32_t backoff = TOOB_BACKOFF_BASE_SEC;
    for (uint32_t i = 1; i < s_consecutive_failures && i < 10; i++) {
        backoff *= 2;
        if (backoff >= TOOB_BACKOFF_MAX_SEC) {
            backoff = TOOB_BACKOFF_MAX_SEC;
            break;
        }
    }
    return backoff;
}

/* ============================================================================
 * Phase 1: CBOR Manifest Fetching & Parsing (UPD-004, UPD-005)
 * ============================================================================ */

typedef struct {
    uint8_t buf[512]; /* UPD-005: Resized from 256 to 512 bytes */
    size_t  len;
} cbor_manifest_buf_t;

static toob_status_t _manifest_chunk_cb(const uint8_t* chunk, uint32_t len, void* ctx) {
    cbor_manifest_buf_t* mbuf = (cbor_manifest_buf_t*)ctx;
    /* GAP-N16: Integer overflow protection */
    if (len > sizeof(mbuf->buf) || mbuf->len > sizeof(mbuf->buf) - len) {
        return TOOB_ERR_INVALID_ARG; /* Manifest exceeds 512 bytes */
    }
    memcpy(&mbuf->buf[mbuf->len], chunk, len);
    mbuf->len += len;
    return TOOB_OK;
}

/* Parsed ein Meta-CBOR Map (Keys 1=svn, 2=size, 3=sha256, 4=image_type, 5=blob_path) */
static bool _parse_cbor_manifest(const uint8_t* data, size_t len, toob_update_info_t* out) {
    if (!data || len == 0 || !out) {
        return false;
    }

    zcbor_state_t state[2];
    /* GAP-N01: Korrekte zcbor_new_decode_state Signatur (7 Parameter).
     * State array size 2 limits nesting depth to 1 level (DoS protection). */
    zcbor_new_decode_state(state, 2, data, len, 1, NULL, 0);
    
    if (!zcbor_map_start_decode(state)) return false;
    
    bool ok = true;
    bool has_size = false;
    bool has_sha256 = false;
    bool has_svn = false;
    bool has_blob_path = false;

    bool parsed_svn = false;
    bool parsed_size = false;
    bool parsed_sha256 = false;
    bool parsed_image_type = false;
    bool parsed_blob_path = false;

    /* GAP-N02: zcbor_array_at_end existiert, list_or_map_end nicht */
    while (ok && !zcbor_array_at_end(state)) {
        uint32_t key;
        if (!zcbor_uint32_decode(state, &key)) { ok = false; break; }
        
        switch (key) {
            case 1: /* SVN */
                if (parsed_svn) { ok = false; break; }
                ok = zcbor_uint32_decode(state, &out->remote_svn);
                has_svn = ok;
                parsed_svn = ok;
                break;
            case 2: /* Size */
                if (parsed_size) { ok = false; break; }
                ok = zcbor_uint32_decode(state, &out->total_size);
                has_size = ok && (out->total_size > 0);
                parsed_size = ok;
                break;
            case 3: /* SHA256 */
            {
                if (parsed_sha256) { ok = false; break; }
                struct zcbor_string str;
                ok = zcbor_bstr_decode(state, &str);
                if (ok && str.len == 32) {
                    memcpy(out->sha256, str.value, 32);
                    has_sha256 = true;
                    parsed_sha256 = true;
                } else {
                    ok = false; /* Strikt: Muss exakt 32 Byte sein */
                }
                break;
            }
            case 4: /* Image Type */
            {
                if (parsed_image_type) { ok = false; break; }
                uint32_t itype;
                ok = zcbor_uint32_decode(state, &itype);
                if (ok && itype <= 255) {
                    out->image_type = (uint8_t)itype;
                    parsed_image_type = true;
                } else {
                    ok = false;
                }
                break;
            }
            case 5: /* blob_path (UPD-005) */
            {
                if (parsed_blob_path) { ok = false; break; }
                struct zcbor_string str;
                ok = zcbor_tstr_decode(state, &str);
                if (ok && str.len > 0 && str.len <= 128) {
                    memcpy(out->blob_path, str.value, str.len);
                    out->blob_path[str.len] = '\0';
                    has_blob_path = true;
                    parsed_blob_path = true;
                } else {
                    ok = false; /* Over 128 bytes or 0 bytes -> FAIL */
                }
                break;
            }
            case 7: /* rotated_token (UPD-032) */
            {
                static bool parsed_rotated_token = false;
                if (parsed_rotated_token) { ok = false; break; }
                struct zcbor_string str;
                ok = zcbor_bstr_decode(state, &str);
                if (ok && str.len == 32) {
                    memcpy(out->rotated_token, str.value, 32);
                    out->has_rotated_token = true;
                    parsed_rotated_token = true;
                } else {
                    ok = false;
                }
                break;
            }
            default:
                /* zcbor_any_skip fails if nesting > 1, preventing DoS stack exhaustion */
                ok = zcbor_any_skip(state, NULL);
                break;
        }
    }
    
    ok = ok && zcbor_map_end_decode(state);
    
    /* Verify that the entire buffer was consumed (detect trailing garbage bytes) */
    if (ok) {
        size_t consumed = (size_t)(state[0].payload - data);
        if (consumed != len) {
            ok = false;
        }
    }

    /* UPD-005 Host-Bound Security Check (MISRA/CERT C):
     * Key 5 MUST contain path + query ONLY. Reject if it contains '://' or '//' */
    if (ok && has_blob_path) {
        if (strstr(out->blob_path, "://") != NULL || strstr(out->blob_path, "//") != NULL) {
            TOOB_LOGE(TAG, "blob_path contains illegal schema/host specifier: %s", out->blob_path);
            ok = false;
        }
    }
    
    /* Mathematische Perfektion: Pflichtfelder MÜSSEN vorhanden und valide sein */
    return ok && has_size && has_sha256 && has_svn && has_blob_path;
}

/* ============================================================================
 * Phase 2: Payload Streaming
 * ============================================================================ */

static toob_status_t _payload_chunk_cb(const uint8_t* chunk, uint32_t len, void* user_ctx) {
    toob_ota_ctx_t *ota = (toob_ota_ctx_t *)user_ctx;
    toob_status_t stat = toob_ota_process_chunk(ota, chunk, len);
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Failed to process OTA chunk: 0x%08X", (unsigned)stat);
    }
    return stat;
}

/* ============================================================================
 * Main OTA Flow (UPD-004, UPD-005)
 * ============================================================================ */

/* OTA session context (static: survives across resume cycles) */
static toob_ota_ctx_t s_ota_ctx;

toob_status_t toob_network_trigger_ota(const char* server_url) {
    if (!server_url) server_url = CONFIG_TOOB_SERVER_URL;
    
    /* 1. L1 Smoke Test (GAP-N11: Init nur einmalig) */
    static bool s_net_init = false;
    if (!s_net_init) {
        toob_status_t stat = toob_network_init();
        if (stat != TOOB_OK) {
            TOOB_LOGE(TAG, "L1 Smoke Test failed");
            return stat;
        }
        TOOB_LOGI(TAG, "L1 Smoke Test passed");
        s_net_init = true;
        toob_ota_ctx_init(&s_ota_ctx);
    }

    /* UPD-004 Step 0: Load device credentials from OS-NVS */
    toob_device_cred_t cred;
    toob_status_t cred_stat = toob_cred_load(&cred);
    if (cred_stat != TOOB_OK) {
        TOOB_LOGE(TAG, "No device credentials in OS-NVS (0x%08X), skipping checkin", (unsigned)cred_stat);
        return cred_stat; /* Fail fast! No anonymous requests! */
    }
    
    toob_status_t stat = TOOB_OK;

    /* Extract current SVN */
    uint32_t current_svn = 0;
    toob_boot_diag_t diag;
    if (toob_get_boot_diag(&diag) == TOOB_OK) {
        current_svn = diag.current_svn;
    }

    /* UPD-004 Step 1: Obtain Device ID & hex encode (64 chars) */
    uint8_t dev_id[32];
    if (toob_get_device_id(dev_id) != TOOB_OK) {
        TOOB_LOGE(TAG, "Failed to compute device ID");
        return TOOB_ERR_HARDWARE;
    }

    char dev_id_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(&dev_id_hex[i * 2], 3, "%02x", dev_id[i]);
    }
    dev_id_hex[64] = '\0';

    /* UPD-004 Step 2: Format POST Checkin URL: %s/v1/devices/%s/checkin */
    char check_url[256];
    int written = snprintf(check_url, sizeof(check_url), "%s/v1/devices/%s/checkin", server_url, dev_id_hex);
    if (written < 0 || (size_t)written >= sizeof(check_url)) {
        TOOB_LOGE(TAG, "Check URL truncated");
        return TOOB_ERR_INVALID_ARG;
    }

    /* UPD-004 Step 3: Get telemetry CBOR body (toob_get_boot_diag_cbor) */
    uint8_t diag_buf[512];
    uint32_t diag_len = 0;
    if (toob_get_boot_diag_cbor(diag_buf, sizeof(diag_buf), &diag_len) != TOOB_OK) {
        TOOB_LOGE(TAG, "Failed to generate boot diag CBOR");
        return TOOB_ERR_HARDWARE;
    }

    /* UPD-004 Step 4: Sequence counter & Headers assembly */
    uint64_t seq = 0;
    (void)toob_cred_bump_seq(&seq);

    char auth_hdr[96];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s\r\n", (const char*)cred.device_token);

    char seq_hdr[64];
    snprintf(seq_hdr, sizeof(seq_hdr), "X-Toob-Seq: %llu\r\n", (unsigned long long)seq);

    const char *const headers[3] = {
        auth_hdr,
        "Content-Type: application/cbor\r\n",
        seq_hdr
    };

    /* UPD-004 Step 5: Execute HTTP POST Check-in request */
    cbor_manifest_buf_t mbuf = { .len = 0 };
    uint16_t http_status = 0;
    uint32_t retry_after = 0;
    stat = rtos_http_request(TOOB_HTTP_POST, check_url,
                             headers, 3,
                             diag_buf, diag_len, 0,
                             _manifest_chunk_cb, &mbuf,
                             &http_status, &retry_after);
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Checkin POST request failed (transport error 0x%08X)", (unsigned)stat);
        return stat;
    }

    /* UPD-004 Step 6: Evaluate HTTP Status & 204 No Content */
    if (http_status == 204 || mbuf.len == 0) {
        TOOB_LOGI(TAG, "No update available (204 No Content, SVN: %u)", current_svn);
        memset(&mbuf, 0, sizeof(mbuf)); /* Zeroise buffer immediately */
        return TOOB_ERR_NOT_FOUND;
    }
    if (http_status != 200) {
        TOOB_LOGW(TAG, "Checkin HTTP status: %u (Retry-After: %u s)", http_status, retry_after);
        memset(&mbuf, 0, sizeof(mbuf)); /* Zeroise buffer immediately */
        return TOOB_ERR_NOT_FOUND;
    }

    /* UPD-004 / UPD-005 Step 7: Parse Manifest & Zeroise Buffer */
    toob_update_info_t info;
    memset(&info, 0, sizeof(info));
    bool parse_ok = _parse_cbor_manifest(mbuf.buf, mbuf.len, &info);
    memset(&mbuf, 0, sizeof(mbuf)); /* UPD-005: Immediate zeroisation per security spec */
    if (!parse_ok) {
        TOOB_LOGE(TAG, "Failed to parse CBOR manifest");
        return TOOB_ERR_VERIFY;
    }

    /* UPD-032: Handle Server-Initiated Token Rotation (Key 7) */
    if (info.has_rotated_token) {
        TOOB_LOGI(TAG, "Server requested token rotation (Key 7), persisting new token to NVS...");
        toob_status_t rot_stat = toob_cred_rotate_token(info.rotated_token);
        if (rot_stat != TOOB_OK) {
            TOOB_LOGE(TAG, "Failed to persist rotated token: 0x%08X", (unsigned)rot_stat);
        }
    }

    /* Defense-in-Depth: Anti-Rollback Prüfung auf OS-Ebene (vor dem Bootloader) */
    if (info.remote_svn <= current_svn) {
        TOOB_LOGI(TAG, "Update skipped: remote SVN (%u) is not strictly newer than current (%u)", 
                  info.remote_svn, current_svn);
        return TOOB_ERR_NOT_FOUND;
    }

    info.update_available = true;
    TOOB_LOGI(TAG, "Update available: size=%u, svn=%u, blob_path=%s", info.total_size, info.remote_svn, info.blob_path);

    /* Phase 2: Resume / Begin */
    uint32_t resume_offset = 0;
    stat = toob_ota_resume(&s_ota_ctx, info.total_size, info.sha256, &resume_offset);
    if (stat == TOOB_OK && resume_offset > 0) {
        TOOB_LOGI(TAG, "Resuming verified download from offset %u", resume_offset);
    } else {
        stat = toob_ota_begin(&s_ota_ctx, info.total_size, info.sha256);
        if (stat != TOOB_OK) {
            TOOB_LOGE(TAG, "OTA begin failed: 0x%08X", (unsigned)stat);
            return stat;
        }
        resume_offset = 0;
    }

    /* UPD-005 Phase 3: Download Payload via Host-Bound URL (%s%s) */
    char download_url[256];
    written = snprintf(download_url, sizeof(download_url), "%s%s", server_url, info.blob_path);
    if (written < 0 || (size_t)written >= sizeof(download_url)) {
        TOOB_LOGE(TAG, "Download URL truncated");
        toob_ota_abort(&s_ota_ctx);
        return TOOB_ERR_INVALID_ARG;
    }
    
    stat = rtos_http_request(TOOB_HTTP_GET, download_url,
                             NULL, 0, NULL, 0, resume_offset,
                             _payload_chunk_cb, &s_ota_ctx,
                             &http_status, &retry_after);
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Download failed: 0x%08X", (unsigned)stat);
        toob_ota_abort(&s_ota_ctx);
        return stat;
    }
    if (http_status != 200 && http_status != 206) {
        TOOB_LOGE(TAG, "Download rejected with HTTP %u", http_status);
        toob_ota_abort(&s_ota_ctx);
        return TOOB_ERR_NOT_FOUND;
    }

    /* Phase 4: Finalize */
    stat = toob_ota_finalize(&s_ota_ctx);
    if (stat == TOOB_ERR_WAL_LOCKED) {
        TOOB_LOGW(TAG, "WAL locked: previous update pending, reboot to consume");
    } else if (stat == TOOB_ERR_VERIFY) {
        TOOB_LOGE(TAG, "Finalize failed: SHA-256 mismatch (stream corrupted)");
    } else if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Finalize failed: 0x%08X", (unsigned)stat);
    }
    if (stat != TOOB_OK) return stat;

    TOOB_LOGI(TAG, "OTA update staged successfully. Rebooting...");
    
    /* GAP-N12: Tatsächlicher Reboot nach OTA Erfolg */
#if defined(__ZEPHYR__)
    sys_reboot(SYS_REBOOT_COLD);
#elif defined(ESP_PLATFORM)
    esp_restart();
#endif

    return TOOB_OK;
}

_Noreturn void toob_network_daemon_loop(void) {
    while (1) {
        toob_status_t result = toob_network_trigger_ota(NULL);

        uint32_t sleep_sec;
        if (result == TOOB_OK) {
            s_consecutive_failures = 0;
            sleep_sec = CONFIG_TOOB_POLL_INTERVAL_SEC;
        } else {
            if (s_consecutive_failures < UINT32_MAX) s_consecutive_failures++;
            sleep_sec = _calculate_backoff_sec();
            TOOB_LOGW(TAG, "Retry in %u seconds (failures: %u)", sleep_sec, s_consecutive_failures);
        }

#if defined(__ZEPHYR__)
        k_sleep(K_SECONDS(sleep_sec));
#elif defined(ESP_PLATFORM)
        uint32_t remaining = sleep_sec;
        while (remaining > 0) {
            uint32_t chunk = (remaining > 60) ? 60 : remaining;
            vTaskDelay(pdMS_TO_TICKS(chunk * 1000));
            remaining -= chunk;
        }
#else
        sleep(sleep_sec);
#endif
    }
}
