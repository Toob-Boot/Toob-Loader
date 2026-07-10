/**
 * @file boot_crc32.h
 * @brief Zero-Allocation CRC-32 Utility for Toob-Boot
 *
 * Implements standard IEEE 802.3 CRC-32 (Polynomial 0xEDB88320).
 * Used globally by the Bootloader for WAL Verification and Handoff Sealing.
 */

#ifndef TOOB_BOOT_CRC32_H
#define TOOB_BOOT_CRC32_H

#include <stdint.h>
#include <stddef.h>
#include "boot_types.h"
#include "boot_hal.h"

/**
 * @brief Computes standard CRC-32 over a byte buffer
 * @param data Pointer to the buffer
 * @param len Length of the buffer in bytes
 * @return 32-bit CRC value
 */
uint32_t compute_boot_crc32(const uint8_t *data, size_t len);

/**
 * @brief O(1) Streaming CRC-32 Berechnung direkt aus dem Flash.
 *
 * Liest in arena-großen Chunks und berechnet CRC-32 inkrementell.
 * Arena wird nach Abschluss zeroized (P10 Leakage Prevention).
 */
boot_status_t boot_crc32_flash_stream(const boot_platform_t *platform,
                                      uint32_t addr, size_t len,
                                      uint32_t *out_crc,
                                      uint8_t *arena, size_t arena_len);

#endif /* TOOB_BOOT_CRC32_H */
