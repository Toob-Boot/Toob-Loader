#include "libtoob.h"
#include "esp_flash.h"
#include "esp_err.h"

/**
 * @brief Zero-Bloat Hook: ESP-IDF Flash Read Implementation
 */
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    // NULL targets the primary/default SPI flash chip in ESP-IDF
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
