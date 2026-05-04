#include "toob_network_client.h"

#if defined(ESP_PLATFORM)
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include <string.h>

static const char *TAG = "toob_http";

/**
 * @brief ESP-IDF spezifische HTTP Implementierung.
 * Kümmert sich ausschließlich um den TLS Aufbau, Redirects, Header
 * und das synchrone Lesen der Chunks in den Callback.
 */
toob_status_t rtos_http_get(const char* url, uint32_t resume_offset, 
                            toob_http_chunk_cb_t callback, void* ctx) {
    if (!url || !callback) return TOOB_ERR_INVALID_ARG;

    esp_http_client_config_t config = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .max_redirection_count = 3,
        .buffer_size = 2048,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        TOOB_LOGE(TAG, "HTTP client init failed");
        return TOOB_ERR_STATE;
    }

    if (resume_offset > 0) {
        char range_hdr[48];
        snprintf(range_hdr, sizeof(range_hdr), "bytes=%u-", resume_offset);
        esp_http_client_set_header(client, "Range", range_hdr);
        TOOB_LOGI(TAG, "HTTP GET %s (Range: %s)", url, range_hdr);
    } else {
        TOOB_LOGI(TAG, "HTTP GET %s", url);
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        TOOB_LOGE(TAG, "HTTP open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return TOOB_ERR_TIMEOUT;
    }

    int content_length = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);

    /* 204 No Content ist ein valider Status (z.B. wenn kein Update verfügbar ist) */
    if (status == 204) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return TOOB_OK;
    }

    /* Validierung des HTTP Status Codes */
    if (status != 200 && status != 206) {
        TOOB_LOGW(TAG, "Unexpected HTTP status: %d", status);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return TOOB_ERR_NOT_FOUND;
    }

    if (content_length > 0) {
        TOOB_LOGI(TAG, "Streaming %d bytes...", content_length);
    }

    uint8_t buf[1024];
    int bytes_read;
    toob_status_t stat = TOOB_OK;

    /* Synchrones Streamen direkt in den Callback */
    while ((bytes_read = esp_http_client_read(client, (char *)buf, sizeof(buf))) > 0) {
        stat = callback(buf, (uint32_t)bytes_read, ctx);
        if (stat != TOOB_OK) {
            TOOB_LOGE(TAG, "Callback rejected chunk: 0x%08X", stat);
            break;
        }
    }

    if (bytes_read < 0) {
        TOOB_LOGE(TAG, "HTTP read error");
        stat = TOOB_ERR_TIMEOUT;
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return stat;
}

#endif /* ESP_PLATFORM */
