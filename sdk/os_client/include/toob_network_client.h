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
    bool     has_rotated_token;/**< UPD-032: True if Key 7 token rotation present */
    uint8_t  _padding2[2];     /**< GAP-N15: Explicit padding for ABI safety */
    char     blob_path[129];   /**< UPD-005: Relative path+query (max 128 bytes) */
    uint8_t  rotated_token[32];/**< UPD-032: New 32-byte rotated token */
    uint8_t  _padding3[3];     /**< Explicit padding to 4-byte boundary (216 bytes total) */
} toob_update_info_t;

_Static_assert(sizeof(toob_update_info_t) == 216, "toob_update_info_t ABI size drift");

/**
 * @brief Initialize the RTOS specific network stack (L1 Smoke Test).
 *        Implemented in rtos_glue_*.c.
 */
toob_status_t toob_network_init(void);

/**
 * @brief HTTP method selector for rtos_http_request().
 */
typedef enum { TOOB_HTTP_GET = 0, TOOB_HTTP_POST = 1 } toob_http_method_t;

/**
 * @brief Unified HTTP hook — the ONLY function each RTOS port must implement.
 *
 * Replaces the former rtos_http_get(). Supports GET and POST, custom headers,
 * request body, and extracts HTTP status code + Retry-After from the response.
 *
 * Contract:
 * - out_status and out_retry_after_s are set BEFORE the first callback invocation.
 * - The return value indicates transport-level success only. The caller evaluates
 *   out_status for HTTP semantics (200, 204, 401, etc.).
 * - headers is a NULL-terminated array of "Name: Value\r\n" strings. Caller owns
 *   the memory. NULL if no custom headers are needed.
 * - range_offset is only applied for GET. Ignored for POST.
 *
 * @param method            HTTP method (GET or POST).
 * @param url               Complete URL (null-terminated).
 * @param headers           NULL-terminated array of header strings (caller-owned), or NULL.
 * @param header_count      Number of entries in headers (excluding NULL terminator).
 * @param body              Request body bytes (NULL for GET or empty POST).
 * @param body_len          Length of body in bytes (0 if body is NULL).
 * @param range_offset      Range header byte offset (0 = no range). Ignored for POST.
 * @param callback          Chunk callback for response body streaming.
 * @param ctx               User context passed through to callback.
 * @param out_status        [out] HTTP status code. Must not be NULL.
 * @param out_retry_after_s [out] Parsed Retry-After value in seconds (0 if absent). Must not be NULL.
 * @return TOOB_OK on successful HTTP exchange (caller evaluates out_status).
 *         TOOB_ERR_TIMEOUT on connect/read timeout.
 *         TOOB_ERR_INVALID_ARG on NULL url/callback/out_status/out_retry_after_s.
 */
TOOB_MUST_CHECK toob_status_t rtos_http_request(
    toob_http_method_t method,
    const char *url,
    const char *const *headers, uint32_t header_count,
    const uint8_t *body, uint32_t body_len,
    uint32_t range_offset,
    toob_http_chunk_cb_t callback, void *ctx,
    uint16_t *out_status,
    uint32_t *out_retry_after_s);

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
