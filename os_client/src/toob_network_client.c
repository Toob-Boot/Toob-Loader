#include "toob_network_client.h"
#include "libtoob.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* Assume zcbor is available as requested */
#include <zcbor_decode.h>

/* GAP-08: Zephyr requires LOG_MODULE_REGISTER for logging to work */
#if defined(__ZEPHYR__)
    #include <zephyr/kernel.h>
    LOG_MODULE_REGISTER(toob_client, LOG_LEVEL_INF);
#elif defined(ESP_PLATFORM)
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
#else
    #include <unistd.h>
#endif

#ifndef CONFIG_TOOB_SERVER_URL
#define CONFIG_TOOB_SERVER_URL "https://api.toob.io/v1/update"
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
 * Phase 1: CBOR Manifest Fetching & Parsing
 * ============================================================================ */

typedef struct {
    uint8_t buf[256];
    size_t  len;
} cbor_manifest_buf_t;

static toob_status_t _manifest_chunk_cb(const uint8_t* chunk, uint32_t len, void* ctx) {
    cbor_manifest_buf_t* mbuf = (cbor_manifest_buf_t*)ctx;
    if (mbuf->len + len > sizeof(mbuf->buf)) {
        return TOOB_ERR_INVALID_ARG; /* Manifest zu groß */
    }
    memcpy(&mbuf->buf[mbuf->len], chunk, len);
    mbuf->len += len;
    return TOOB_OK;
}

/* Parsed ein Meta-CBOR Map mit den Keys 1=svn, 2=size, 3=sha256, 4=image_type */
static bool _parse_cbor_manifest(const uint8_t* data, size_t len, toob_update_info_t* out) {
    zcbor_state_t state[2];
    zcbor_new_decode_state(state, 2, data, len, 1);
    
    if (!zcbor_map_start_decode(state)) return false;
    
    bool ok = true;
    bool has_size = false;
    bool has_sha256 = false;
    bool has_svn = false;

    while (ok && !zcbor_list_or_map_end(state)) {
        uint32_t key;
        if (!zcbor_uint32_decode(state, &key)) { ok = false; break; }
        
        switch (key) {
            case 1: /* SVN */
                ok = zcbor_uint32_decode(state, &out->remote_svn);
                has_svn = ok;
                break;
            case 2: /* Size */
                ok = zcbor_uint32_decode(state, &out->total_size);
                has_size = ok && (out->total_size > 0);
                break;
            case 3: /* SHA256 */
            {
                struct zcbor_string str;
                ok = zcbor_bstr_decode(state, &str);
                if (ok && str.len == 32) {
                    memcpy(out->sha256, str.value, 32);
                    has_sha256 = true;
                } else {
                    ok = false; /* Strikt: Muss exakt 32 Byte sein */
                }
                break;
            }
            case 4: /* Image Type */
            {
                uint32_t itype;
                ok = zcbor_uint32_decode(state, &itype);
                out->image_type = (uint8_t)itype;
                break;
            }
            default:
                ok = zcbor_any_skip(state, NULL);
                break;
        }
    }
    
    ok = ok && zcbor_map_end_decode(state);
    
    /* Mathematische Perfektion: Pflichtfelder MÜSSEN vorhanden und valide sein */
    return ok && has_size && has_sha256 && has_svn;
}

/* ============================================================================
 * Phase 2: Payload Streaming
 * ============================================================================ */

static toob_status_t _payload_chunk_cb(const uint8_t* chunk, uint32_t len, void* ctx) {
    (void)ctx;
    toob_status_t stat = toob_ota_process_chunk(chunk, len);
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Failed to process OTA chunk: 0x%08X", stat);
    }
    return stat;
}

/* ============================================================================
 * Main OTA Flow
 * ============================================================================ */

toob_status_t toob_network_trigger_ota(const char* server_url) {
    if (!server_url) server_url = CONFIG_TOOB_SERVER_URL;
    
    /* 1. L1 Smoke Test */
    toob_status_t stat = toob_network_init();
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "L1 Smoke Test failed");
        return stat;
    }
    TOOB_LOGI(TAG, "L1 Smoke Test passed");

    /* Extract current SVN */
    uint32_t current_svn = 0;
    toob_boot_diag_t diag;
    if (toob_get_boot_diag(&diag) == TOOB_OK) {
        current_svn = diag.current_svn;
    }

    /* Phase 1: Fetch CBOR Manifest */
    char check_url[256];
    snprintf(check_url, sizeof(check_url), "%s/check?svn=%u", server_url, current_svn);
    
    cbor_manifest_buf_t mbuf = { .len = 0 };
    stat = rtos_http_get(check_url, 0, _manifest_chunk_cb, &mbuf);
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Check request failed (HTTP error/Timeout)");
        return stat;
    }

    /* HTTP 204 No Content liefert mbuf.len == 0 */
    if (mbuf.len == 0) {
        TOOB_LOGI(TAG, "No update available (SVN: %u)", current_svn);
        return TOOB_ERR_NOT_FOUND;
    }

    toob_update_info_t info;
    memset(&info, 0, sizeof(info));
    if (!_parse_cbor_manifest(mbuf.buf, mbuf.len, &info)) {
        TOOB_LOGE(TAG, "Failed to parse CBOR manifest");
        return TOOB_ERR_VERIFY;
    }
    /* Defense-in-Depth: Anti-Rollback Prüfung auf OS-Ebene (vor dem Bootloader) */
    if (info.remote_svn <= current_svn) {
        TOOB_LOGI(TAG, "Update skipped: remote SVN (%u) is not strictly newer than current (%u)", 
                  info.remote_svn, current_svn);
        return TOOB_ERR_NOT_FOUND;
    }

    info.update_available = true;
    TOOB_LOGI(TAG, "Update available: size=%u, svn=%u", info.total_size, info.remote_svn);

    /* Phase 2: Resume / Begin */
    uint32_t resume_offset = 0;
    if (toob_ota_resume(&resume_offset) == TOOB_OK && resume_offset > 0) {
        TOOB_LOGI(TAG, "Resuming download from offset %u", resume_offset);
    } else {
        stat = toob_ota_begin_verified(info.total_size, info.image_type, info.sha256);
        if (stat != TOOB_OK) {
            TOOB_LOGE(TAG, "OTA begin failed: 0x%08X", stat);
            return stat;
        }
        resume_offset = 0;
    }

    /* Phase 3: Download Payload */
    char download_url[256];
    snprintf(download_url, sizeof(download_url), "%s/download", server_url);
    
    stat = rtos_http_get(download_url, resume_offset, _payload_chunk_cb, NULL);
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Download failed: 0x%08X", stat);
        toob_ota_abort();
        return stat;
    }

    /* Phase 4: Finalize */
    stat = toob_ota_finalize();
    if (stat != TOOB_OK) {
        TOOB_LOGE(TAG, "Finalize failed (hash mismatch?): 0x%08X", stat);
        return stat;
    }

    TOOB_LOGI(TAG, "OTA update staged successfully. Rebooting...");
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
        vTaskDelay(pdMS_TO_TICKS((uint64_t)sleep_sec * 1000));
#else
        sleep(sleep_sec);
#endif
    }
}
