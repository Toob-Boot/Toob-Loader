#include "toob_network_client.h"

#if defined(ESP_PLATFORM)
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "libtoob.h"
#include <string.h>

static const char *TAG = "toob_http";

static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (evt->data_len > 0) {
                toob_status_t stat = toob_ota_process_chunk(evt->data, evt->data_len);
                if (stat != TOOB_OK) {
                    TOOB_LOGE(TAG, "OTA chunk processing failed: %d", stat);
                    return ESP_FAIL;
                }
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            if (toob_ota_finalize() != TOOB_OK) {
                TOOB_LOGE(TAG, "OTA finalize failed (Signature or Hash mismatch)");
                return ESP_FAIL;
            }
            break;
        case HTTP_EVENT_DISCONNECTED:
            /* Safe to call, libtoob handles repeated aborts harmlessly */
            toob_ota_abort();
            break;
        default:
            break;
    }
    return ESP_OK;
}

toob_status_t rtos_http_download(const char* url) {
    /* 
     * In a production deployment, the initial SUIT manifest is fetched, 
     * parsed, and toob_ota_begin() is called with the actual size.
     * For this native scaffold, we initialize the OTA daemon directly.
     */
    toob_status_t stat = toob_ota_begin(0xFFFFFFFF, 0); 
    if (stat != TOOB_OK) {
        return stat;
    }

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        /* 
         * P10 Security: We use the native ESP-IDF Certificate Bundle. 
         * This natively verifies the remote API via Trusted Root CAs, 
         * without duplicating mbedTLS configurations.
         */
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .buffer_size = 2048, /* Match our chunk size if possible */
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        TOOB_LOGE(TAG, "Failed to initialize ESP HTTP client");
        toob_ota_abort();
        return TOOB_ERR_STATE;
    }

    TOOB_LOGI(TAG, "Starting native TLS download from %s", url);
    esp_err_t err = esp_http_client_perform(client);
    
    if (err == ESP_OK) {
        int status_code = esp_http_client_get_status_code(client);
        TOOB_LOGI(TAG, "Download complete. HTTP Status: %d", status_code);
        esp_http_client_cleanup(client);
        return (status_code == 200) ? TOOB_OK : TOOB_ERR_NOT_FOUND;
    } else {
        TOOB_LOGE(TAG, "Native TLS download failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return TOOB_ERR_TIMEOUT;
    }
}
#endif /* ESP_PLATFORM */
