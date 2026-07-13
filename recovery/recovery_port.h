/**
 * @file recovery_port.h
 * @brief Platform Porting Hooks for Recovery OS.
 */

#ifndef RECOVERY_PORT_H
#define RECOVERY_PORT_H

#include "libtoob_types.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Initialize the serial port console at standard baudrate.
 */
toob_status_t recovery_serial_init(void);

/**
 * @brief Read a single byte from UART with a timeout.
 * @param out Pointer to store the received byte.
 * @param timeout_ms Max time to wait in milliseconds.
 * @return TOOB_OK if a byte was read, or TOOB_ERR_TIMEOUT.
 */
toob_status_t recovery_serial_getchar(uint8_t *out, uint32_t timeout_ms);

/**
 * @brief Write a single byte to UART.
 */
void recovery_serial_putchar(char c);

/**
 * @brief Write a null-terminated string to UART.
 */
void recovery_serial_print(const char *str);

/**
 * @brief Reboot the system.
 */
_Noreturn void recovery_system_reboot(void);

#endif /* RECOVERY_PORT_H */
