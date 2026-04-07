#ifndef TOOB_INTERNAL_H
#define TOOB_INTERNAL_H

#include "libtoob_types.h"
#include <stdint.h>
#include <stddef.h>

/**
 * @brief Computes standard IEEE 802.3 CRC-32 (matching Bootloader's algorithm)
 * @param data Byte pointer to the buffer
 * @param length Length of the buffer
 * @return Computed CRC-32 value
 */
uint32_t toob_lib_crc32(const uint8_t *data, size_t length);

/**
 * @brief Führt einen naiven O(1) WAL Append aus, ohne Code-Duplikation.
 *        Strikte Regel: Findet die Funktion keinen Platz mehr, wird
 *        abgewiesen (TOOB_ERR_WAL_FULL) und KEIN Erase vom OS ausgeführt.
 * 
 *        Arch-Note: "Naive" means it intentionally avoids complex WAL lifecycle
 *        tasks like sector rotation or TMR healing. Those are strictly reserved
 *        for the Bootloader (S1) upon reset to prevent OS-induced Wear-Suicide.
 * 
 * @param intent Pointer auf assemblierten Transaktions-Payload
 * @return TOOB_OK, TOOB_ERR_FLASH, TOOB_ERR_WAL_FULL, TOOB_ERR_NOT_FOUND, TOOB_ERR_WAL_LOCKED, oder TOOB_ERR_REQUIRES_RESET.
 */
toob_status_t toob_wal_naive_append(const toob_wal_entry_payload_t *intent);

#endif /* TOOB_INTERNAL_H */
