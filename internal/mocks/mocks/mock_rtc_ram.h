/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: RTC RAM Mock Header
 * ==============================================================================
 */

#ifndef MOCK_RTC_RAM_H
#define MOCK_RTC_RAM_H

#include <stdint.h>
#include <stdbool.h>
#include "boot_hal.h"

extern const confirm_hal_t sandbox_confirm_hal;

/* Entfernt die rtc_sim.bin Datei physisch mit remove(). Zwingend nötig für saubere Unit-Test Teardowns! */
void mock_rtc_ram_reset_to_factory(void);

/* Simuliert einen libtoob_api Aufruf aus dem komplett hochgefahrenen Feature-OS. */
void mock_rtc_ram_set_nonce(uint64_t nonce);

/* Simuliert physische Korruption des RTC RAMs (z.B. Bit-Rot / Batterie leer) */
void mock_rtc_ram_force_corruption(void);

#endif /* MOCK_RTC_RAM_H */
