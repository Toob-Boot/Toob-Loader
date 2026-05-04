/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Mapped Flash Header
 * ==============================================================================
 * 
 * Dies ist der Header für das Host-Native Flash-Backend (stdio.h).
 * 
 * REFERENCED SPECIFICATIONS:
 * 1. docs/hals.md -> flash_hal_t
 * 2. docs/sandbox_setup.md -> File-basierte Mock-Simulation
 */

#ifndef MOCK_FLASH_H
#define MOCK_FLASH_H

#include <stdint.h>
#include <stdbool.h>
#include "boot_hal.h"

/**
 * @brief Die instanziierte Flash HAL für die M-SANDBOX.
 * Wird in chip_platform.c der Sandbox der platform->flash zugewiesen.
 */
extern const flash_hal_t sandbox_flash_hal;

/**
 * @brief Löscht die Host-SIM-Datei physikalisch für saubere Unit Tests.
 */
void mock_flash_reset_to_factory(void);

/**
 * @brief Manuelles Interface für C-Runner, um die ENV-Variable zu überschreiben.
 * 
 * @param write_count_limit Anzahl an wdt/flash writes, nach denen ein 
 *                          Brownout Reset simuliert wird. 0 = deaktiviert.
 */
void mock_flash_set_fail_limit(uint32_t write_count_limit);

/**
 * @brief Manuelles Interface für statische Bit-Rot Injektion in mock_flash_read.
 * 
 * @param addr Hexadezimale Adresse, an der der Bit-Fehler emuliert werden soll.
 * @param value Der injizierte 8-Bit Wert (z.B. 0x00 oder 0xFF).
 */
void mock_flash_set_bitrot(uint32_t addr, uint8_t value);

#endif /* MOCK_FLASH_H */
