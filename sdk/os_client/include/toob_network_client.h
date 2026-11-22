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
 * @brief TCI1-based Check-In Update Metadata (Phase 1 Meta-Check).
 *
 * Parsed and HMAC-SHA256-128 authenticated from `TCI1` (`toob_checkin_wire.h`).
 */
typedef struct __attribute__((aligned(4))) {
    uint32_t total_size;        /**< Payload size in bytes (>= 576 for updates) */
    uint8_t  sha256[32];        /**< Expected SHA-256 digest of the payload */
    uint8_t  assignment_id[16]; /**< TCI1-05: 16B UUID assignment identifier */
    uint8_t  target_slot;       /**< TCI1-01: 0 = App, 1 = Netcore, 3 = Stage1 */
    bool     update_available;  /**< True if the server assigned a firmware update */
    bool     has_rotated_token; /**< UPD-032: True if TCI1 rotated_token present */
    uint8_t  _padding1;         /**< Explicit padding to 4-byte boundary */
    uint32_t remote_svn;        /**< Server-side target-slot SVN */
    uint32_t remote_build;      /**< TCI1-01: Server-side TBM1 build_number */
    uint32_t retry_after_sec;   /**< TCI1-03: Authenticated server poll/backoff hint */
    char     blob_path[124];    /**< UPD-005: RFC-3986 relative path (max 120 + NUL) */
    uint8_t  rotated_token[32]; /**< UPD-032: Unmasked 32-byte rotated token */
} toob_update_info_t;

_Static_assert(sizeof(toob_update_info_t) == 224U, "toob_update_info_t ABI size drift");

/**
 * @brief Authenticate and parse a const-pure TCI1 check-in response frame (TCI1-06 / TCI1-07).
 *
 * Verifies Trunc_128(HMAC-SHA256(token_key, "TCI1-AUTH-V1" || device_id || body))
 * in constant time before parsing offsets, enforces seq_echo == expected_seq,
 * validates blob_path via a closed O(n) RFC-3986 DFA without <string.h>, and
 * XOR-unmasks rotated_token when present.
 */
TOOB_MUST_CHECK toob_status_t toob_tci1_parse(
    const uint8_t *data,
    size_t len,
    const uint8_t token_key[32],
    const uint8_t device_id[32],
    uint64_t expected_seq,
    toob_update_info_t *out,
    const uint8_t **out_cloud_cmd,
    uint16_t *out_cloud_cmd_len);

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
