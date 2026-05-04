#include "libtoob.h"
#include <zephyr/drivers/flash.h>
#include <zephyr/device.h>

/**
 * @brief Zero-Bloat Hook: Zephyr Flash Read Implementation
 */
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    
    if (!device_is_ready(flash_dev)) {
        return TOOB_ERR_FLASH;
    }
    
    int rc = flash_read(flash_dev, (off_t)addr, buf, len);
    return (rc == 0) ? TOOB_OK : TOOB_ERR_FLASH;
}

/**
 * @brief Zero-Bloat Hook: Zephyr Flash Write Implementation
 */
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    
    if (!device_is_ready(flash_dev)) {
        return TOOB_ERR_FLASH;
    }
    
    int rc = flash_write(flash_dev, (off_t)addr, buf, len);
    return (rc == 0) ? TOOB_OK : TOOB_ERR_FLASH;
}
