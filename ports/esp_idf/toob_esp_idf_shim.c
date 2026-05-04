#include "libtoob.h"
#include "esp_flash.h"
#include "esp_err.h"
#include "mbedtls/sha256.h"
#include <string.h>

/**
 * @brief Zero-Bloat Hook: ESP-IDF Flash Read Implementation
 */
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    esp_err_t err = esp_flash_read(NULL, buf, addr, len);
    return (err == ESP_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

/**
 * @brief Zero-Bloat Hook: ESP-IDF Flash Write Implementation
 */
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    esp_err_t err = esp_flash_write(NULL, buf, addr, len);
    return (err == ESP_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

/**
 * @brief Zero-Bloat Hook: ESP-IDF Flash Erase Implementation (GAP-10)
 */
toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    esp_err_t err = esp_flash_erase_region(NULL, addr, len);
    return (err == ESP_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

/**
 * @brief Zero-Bloat Hook: SHA-256 Init via mbedTLS (GAP-11)
 */
toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) {
    if (!ctx) return TOOB_ERR_INVALID_ARG;
    _Static_assert(sizeof(mbedtls_sha256_context) <= sizeof(ctx->opaque),
                   "mbedtls_sha256_context exceeds opaque buffer");
    mbedtls_sha256_context *mbctx = (mbedtls_sha256_context *)ctx->opaque;
    mbedtls_sha256_init(mbctx);
    int ret = mbedtls_sha256_starts(mbctx, 0); /* 0 = SHA-256 (not SHA-224) */
    return (ret == 0) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

/**
 * @brief Zero-Bloat Hook: SHA-256 Update via mbedTLS (GAP-11)
 */
toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) {
    if (!ctx || !data) return TOOB_ERR_INVALID_ARG;
    mbedtls_sha256_context *mbctx = (mbedtls_sha256_context *)ctx->opaque;
    int ret = mbedtls_sha256_update(mbctx, data, len);
    return (ret == 0) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

/**
 * @brief Zero-Bloat Hook: SHA-256 Finalize via mbedTLS (GAP-11)
 */
toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) {
    if (!ctx || !out_hash) return TOOB_ERR_INVALID_ARG;
    mbedtls_sha256_context *mbctx = (mbedtls_sha256_context *)ctx->opaque;
    int ret = mbedtls_sha256_finish(mbctx, out_hash);
    mbedtls_sha256_free(mbctx);
    return (ret == 0) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}
