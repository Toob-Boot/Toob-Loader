/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Clock Mock Header
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * 1. docs/hals.md -> clock_hal_t
 * 2. docs/testing_requirements.md -> Deterministic Execution
 */

#ifndef MOCK_CLOCK_H
#define MOCK_CLOCK_H

#include "boot_hal.h"
#include <stdint.h>
#include <stdbool.h>

extern const clock_hal_t sandbox_clock_hal;

/* --- Test-Runner Injection Utilities --- */

/**
 * @brief Überschreibt die Systemzeit hart für Time-Travel Tests.
 */
void mock_clock_set_tick(uint32_t exact_ms);

/**
 * @brief Erzwingt einen anderen Reset-Grund zur Laufzeit.
 */
void mock_clock_set_reset_reason(reset_reason_t reason);

/**
 * @brief Setzt die laufende Zeit auf 0 und den Grund auf POWER_ON für Unit-Tests.
 */
void mock_clock_reset_to_factory(void);

#endif /* MOCK_CLOCK_H */
