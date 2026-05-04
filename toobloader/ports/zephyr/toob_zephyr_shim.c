#include "libtoob.h"
#include <zephyr/drivers/flash.h>
#include <zephyr/device.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <string.h>

/**
 * @brief Zero-Bloat Hook: Zephyr Flash Read Implementation
 */
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    if (!device_is_ready(flash_dev)) return TOOB_ERR_FLASH;
    int rc = flash_read(flash_dev, (off_t)addr, buf, len);
    return (rc == 0) ? TOOB_OK : TOOB_ERR_FLASH;
}

/**
 * @brief Zero-Bloat Hook: Zephyr Flash Write Implementation
 */
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    if (!device_is_ready(flash_dev)) return TOOB_ERR_FLASH;
    int rc = flash_write(flash_dev, (off_t)addr, buf, len);
    return (rc == 0) ? TOOB_OK : TOOB_ERR_FLASH;
}

/**
 * @brief Zero-Bloat Hook: Zephyr Flash Erase Implementation (GAP-10)
 */
toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    if (!device_is_ready(flash_dev)) return TOOB_ERR_FLASH;
    int rc = flash_erase(flash_dev, (off_t)addr, len);
    return (rc == 0) ? TOOB_OK : TOOB_ERR_FLASH;
}

/**
 * @brief Zero-Bloat Hook: SHA-256 Init via TinyCrypt (GAP-11)
 */
toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) {
    if (!ctx) return TOOB_ERR_INVALID_ARG;
    _Static_assert(sizeof(struct tc_sha256_state_struct) <= sizeof(ctx->opaque),
                   "tc_sha256 context exceeds opaque buffer");
    struct tc_sha256_state_struct *tcctx = (struct tc_sha256_state_struct *)ctx->opaque;
    int ret = tc_sha256_init(tcctx);
    return (ret == TC_CRYPTO_SUCCESS) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

/**
 * @brief Zero-Bloat Hook: SHA-256 Update via TinyCrypt (GAP-11)
 */
toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) {
    if (!ctx || !data) return TOOB_ERR_INVALID_ARG;
    struct tc_sha256_state_struct *tcctx = (struct tc_sha256_state_struct *)ctx->opaque;
    int ret = tc_sha256_update(tcctx, data, len);
    return (ret == TC_CRYPTO_SUCCESS) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

/**
 * @brief Zero-Bloat Hook: SHA-256 Finalize via TinyCrypt (GAP-11)
 */
toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) {
    if (!ctx || !out_hash) return TOOB_ERR_INVALID_ARG;
    struct tc_sha256_state_struct *tcctx = (struct tc_sha256_state_struct *)ctx->opaque;
    int ret = tc_sha256_final(out_hash, tcctx);
    return (ret == TC_CRYPTO_SUCCESS) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}
