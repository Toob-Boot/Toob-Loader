#ifndef BOOT_DELAY_H
#define BOOT_DELAY_H

#include "boot_hal.h"

/**
 * @brief Führt eine blockierende Verzögerung aus und füttert den Watchdog.
 * 
 * @param platform Pointer auf die Boot Platform
 * @return BOOT_OK bei Erfolg, BOOT_ERR_TIMEOUT wenn die MCU/Clock festhängt
 */
boot_status_t boot_delay_with_wdt(const boot_platform_t *platform, uint32_t ms);

#endif /* BOOT_DELAY_H */
