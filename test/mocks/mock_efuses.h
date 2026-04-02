/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Mapped eFuses & OTP Header
 * ==============================================================================
 */

#ifndef MOCK_EFUSES_H
#define MOCK_EFUSES_H

#include "boot_hal.h"
#include <stdint.h>
#include <stddef.h>

boot_status_t mock_efuse_read_pubkey(uint8_t key[32], uint8_t key_index);
boot_status_t mock_efuse_read_dslc(uint8_t *buffer, size_t *len);
boot_status_t mock_efuse_read_monotonic_counter(uint32_t *ctr);
boot_status_t mock_efuse_advance_monotonic_counter(void);

/**
 * @brief Testrunner Methode: Resettet den simulierten eFuse Fortschritt 
 * zurück auf 0, um State-Pollution zwischen Tests zu vermeiden.
 */
void mock_efuse_reset_state(void);

#endif /* MOCK_EFUSES_H */
