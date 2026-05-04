#ifndef TOOB_NETWORK_CLIENT_H
#define TOOB_NETWORK_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "libtoob_types.h" /* provided by libtoob */

/* --- UNIFIED LOGGING MACROS --- */
#if defined(ESP_PLATFORM)
    #include "esp_log.h"
    #define TOOB_LOGI(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)
    #define TOOB_LOGE(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
    #define TOOB_LOGW(tag, fmt, ...) ESP_LOGW(tag, fmt, ##__VA_ARGS__)
#elif defined(__ZEPHYR__)
    #include <zephyr/logging/log.h>
    #define TOOB_LOGI(tag, fmt, ...) LOG_INF(fmt, ##__VA_ARGS__)
    #define TOOB_LOGE(tag, fmt, ...) LOG_ERR(fmt, ##__VA_ARGS__)
    #define TOOB_LOGW(tag, fmt, ...) LOG_WRN(fmt, ##__VA_ARGS__)
#else
    #include <stdio.h>
    #define TOOB_LOGI(tag, fmt, ...) printf("[INFO] " tag ": " fmt "\n", ##__VA_ARGS__)
    #define TOOB_LOGE(tag, fmt, ...) printf("[ERR]  " tag ": " fmt "\n", ##__VA_ARGS__)
    #define TOOB_LOGW(tag, fmt, ...) printf("[WARN] " tag ": " fmt "\n", ##__VA_ARGS__)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the RTOS specific network stack and DNS (L1 Smoke Test).
 *        This function is implemented in rtos_glue_*.c.
 * @return TOOB_OK on success, or a specific error code.
 */
toob_status_t toob_network_init(void);

/**
 * @brief Manually trigger an OTA update check.
 * @param server_url The URL of the OTA server. If NULL, uses Kconfig default.
 * @return TOOB_OK if update started, TOOB_ERR_NOT_FOUND if no update, etc.
 */
toob_status_t toob_network_trigger_ota(const char* server_url);

/**
 * @brief RTOS specific Native HTTP/TLS Download.
 *        Implemented in rtos_http_*.c to utilize zero-bloat native network stacks.
 * @param url The URL to download
 * @return TOOB_OK on success, or specific error code
 */
toob_status_t rtos_http_download(const char* url);

/**
 * @brief Start the daemon polling loop. Usually run in a separate RTOS thread.
 */
_Noreturn void toob_network_daemon_loop(void);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_NETWORK_CLIENT_H */
