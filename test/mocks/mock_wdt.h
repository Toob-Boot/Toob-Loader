/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Watchdog Mock Header
 * ==============================================================================
 */

#ifndef MOCK_WDT_H
#define MOCK_WDT_H

#include <stdint.h>
#include <stdbool.h>
#include "boot_hal.h"

/**
 * @brief Die instanziierte Watchdog HAL für die M-SANDBOX.
 */
extern const wdt_hal_t sandbox_wdt_hal;

/**
 * @brief Gibt die Anzahl der bisherigen WDT-Kicks zurück.
 *        Nützlich für Unit-Tests, um zu prüfen, ob der P10-Code "zu oft" kickt.
 */
uint32_t mock_wdt_get_kick_count(void);

/**
 * @brief Setzt die Watchdog-Statistiken und Timer für den nächsten Test zurück.
 */
void mock_wdt_reset_state(void);

#endif /* MOCK_WDT_H */
