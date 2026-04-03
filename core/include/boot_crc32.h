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

/**
 * @brief Computes standard CRC-32 over a byte buffer
 * @param data Pointer to the buffer
 * @param len Length of the buffer in bytes
 * @return 32-bit CRC value
 */
uint32_t compute_boot_crc32(const uint8_t *data, size_t len);

#endif /* TOOB_BOOT_CRC32_H */
