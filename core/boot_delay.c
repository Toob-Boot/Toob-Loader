/*
 * Toob-Boot Core File: boot_delay.c
 * Relevant Spec-Dateien:
 * - docs/hals.md (Watchdog timeout during delay)
 * - docs/testing_requirements.md
 */

#include "boot_delay.h"

void boot_delay_with_wdt(const boot_platform_t *platform, uint32_t ms) {
    if (!platform || !platform->clock) {
        return; // P10-compliant: Fallback wenn Clock HAL fehlt
    }

    uint32_t start_time = platform->clock->get_tick_ms();
    
    // Bounded-Loop: Basiert auf Hardware-Tick für WDT-Sicherheit
    while ((platform->clock->get_tick_ms() - start_time) < ms) {
        if (platform->wdt) {
            platform->wdt->kick();
        }
        platform->clock->delay_ms(1);
    }
}
