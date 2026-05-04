#include "libtoob.h"

/* FreeRTOS does not have a universal Flash/Crypto HAL.
 * It relies on vendor-specific HALs (e.g., STM32 HAL, NXP SDK).
 * You MUST include your specific vendor's headers and implement the hooks below.
 */

/* TODO: Include vendor-specific Flash header (e.g., "stm32_hal_flash.h") */
/* TODO: Include vendor-specific SHA-256 header (e.g., "stm32_hal_hash.h") */

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    /* TODO: Implement vendor-specific flash read */
    (void)addr; (void)buf; (void)len;
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    /* TODO: Implement vendor-specific flash write */
    (void)addr; (void)buf; (void)len;
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    /* TODO: Implement vendor-specific flash erase (GAP-10) */
    (void)addr; (void)len;
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) {
    /* TODO: Implement vendor-specific SHA-256 init (GAP-11) */
    (void)ctx;
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) {
    /* TODO: Implement vendor-specific SHA-256 update (GAP-11) */
    (void)ctx; (void)data; (void)len;
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) {
    /* TODO: Implement vendor-specific SHA-256 finalize (GAP-11) */
    (void)ctx; (void)out_hash;
    return TOOB_ERR_NOT_SUPPORTED;
}
