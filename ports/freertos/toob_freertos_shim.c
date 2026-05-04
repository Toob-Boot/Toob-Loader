#include "libtoob.h"

// FreeRTOS does not have a universal Flash HAL (unlike Zephyr or ESP-IDF).
// It relies on vendor-specific HALs (e.g., STM32 HAL, NXP SDK).
// You must include your specific vendor's Flash header here.
// #include "stm32_hal_flash.h" 

/**
 * @brief Zero-Bloat Hook: FreeRTOS Flash Read Implementation
 */
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    // TODO: Implement vendor-specific flash read.
    // Example for hypothetical STM32 HAL:
    // HAL_FLASH_Read(addr, buf, len);
    
    return TOOB_ERR_FLASH; // Replace with TOOB_OK on success
}

/**
 * @brief Zero-Bloat Hook: FreeRTOS Flash Write Implementation
 */
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    // TODO: Implement vendor-specific flash write.
    // Ensure that you handle page alignment and unlocking if required by your HAL.
    // Example for hypothetical STM32 HAL:
    // HAL_FLASH_Unlock();
    // HAL_FLASH_Program(TYPEPROGRAM_FAST, addr, (uint64_t)buf);
    // HAL_FLASH_Lock();
    
    return TOOB_ERR_FLASH; // Replace with TOOB_OK on success
}
