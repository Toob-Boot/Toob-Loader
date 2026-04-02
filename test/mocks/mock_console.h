/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Console UART Mock Header
 * ==============================================================================
 */

#ifndef MOCK_CONSOLE_H
#define MOCK_CONSOLE_H

#include "boot_hal.h"

extern const console_hal_t sandbox_console_hal;

/**
 * @brief Testrunner Hilfsfunktion (Leak Prevention). 
 *        Schließt den simulierten UART-Stream zuverlässig ab.
 */
void mock_console_reset_state(void);

#endif /* MOCK_CONSOLE_H */
