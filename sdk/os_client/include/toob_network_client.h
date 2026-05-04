#ifndef TOOB_NETWORK_CLIENT_H
#define TOOB_NETWORK_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "libtoob_types.h"

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
 * @brief Unified Callback für HTTP-Daten (Manifest oder Payload).
 * @param chunk Der empfangene Byte-Chunk
 * @param len Länge des Chunks
 * @param ctx User-definierter Kontext
 * @return TOOB_OK bei Erfolg, sonst bricht der HTTP-Client ab
 */
typedef toob_status_t (*toob_http_chunk_cb_t)(const uint8_t* chunk, uint32_t len, void* ctx);

/**
 * @brief SUIT-CBOR basierte Update Metadaten (Phase 1 Meta-Check)
 * 
 * CDDL Definition für den /check Endpoint:
 * toob_meta_check = {
 *     1: uint .size 4,              ; remote_svn (Security Version Number)
 *     2: uint .size 4,              ; total_size (Blob Size in Bytes)
 *     3: bstr .size 32,             ; sha256 (Full Blob SHA-256 für den OS-Stream)
 *     ? 4: uint .size 1             ; image_type (0=OS, 3=Bootloader)
 * }
 */
typedef struct __attribute__((aligned(4))) {
    uint32_t total_size;       /**< Payload size in bytes */
    uint8_t  sha256[32];       /**< Expected SHA-256 digest of the payload */
    uint8_t  image_type;       /**< 0 = OS Update, 3 = Bootloader */
    uint8_t  _padding[3];      /**< GAP-N15: Explicit padding for ABI safety */
    uint32_t remote_svn;       /**< Server-side Security Version Number */
    bool     update_available; /**< True if the server has a newer version */
    uint8_t  _padding2[3];     /**< GAP-N15: Explicit padding for ABI safety */
} toob_update_info_t;

_Static_assert(sizeof(toob_update_info_t) == 48, "toob_update_info_t ABI size drift");

/**
 * @brief Initialize the RTOS specific network stack (L1 Smoke Test).
 *        Implemented in rtos_glue_*.c.
 */
toob_status_t toob_network_init(void);

/**
 * @brief Führt einen HTTP GET Request aus und streamt die Antwort asynchron.
 *        Dies ist die EINZIGE Funktion, die das RTOS in rtos_http_*.c implementieren muss!
 * 
 * @param url           Komplette URL (z.B. check oder download Endpunkt)
 * @param resume_offset Range-Header Offset (0 für neuen Download)
 * @param callback      Wird für jeden empfangenen Chunk aufgerufen
 * @param ctx           User-Context Pointer (wird an callback gereicht)
 * @return TOOB_OK bei erfolgreichem HTTP 200/206 und vollständig verarbeitetem Stream
 */
toob_status_t rtos_http_get(const char* url, uint32_t resume_offset, 
                            toob_http_chunk_cb_t callback, void* ctx);

/**
 * @brief Manually trigger an OTA update check and download if available.
 */
toob_status_t toob_network_trigger_ota(const char* server_url);

/**
 * @brief Start the daemon polling loop. Usually run in a separate RTOS thread.
 */
_Noreturn void toob_network_daemon_loop(void);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_NETWORK_CLIENT_H */
