#ifndef BOOT_DELAY_H
#define BOOT_DELAY_H

#include "boot_hal.h"

/**
 * @brief Führt eine blockierende Verzögerung aus und füttert den Watchdog.
 * 
 * @param platform Pointer auf die Boot Platform
 * @param ms       Wartezeit in Millisekunden
 */
void boot_delay_with_wdt(const boot_platform_t *platform, uint32_t ms);

#endif /* BOOT_DELAY_H */
