#ifndef LOGGER_H
#define LOGGER_H

#include "fz_profiles.h"
#include <stdbool.h>
#include <stdint.h>


// Initializes the logger with the active hardware profile
void fz_logger_init(fz_profile_t *active_profile);

// Profile-aware logging function (mutes output if profile forbids it)
void fz_log(const char *str);

// Profile-aware hexadecimal logging
void fz_log_hex(uint32_t val);

// Profile-aware UART read (returns true if byte received)
bool fz_uart_rx_byte(uint8_t *c);

#endif // LOGGER_H
