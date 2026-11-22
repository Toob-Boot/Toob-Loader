/**
 * @file boot_decomp.h
 * @brief Streaming Decompressor for Compressed Firmware Images (Heatshrink LZSS)
 *
 * Implements a zero-heap, O(1)-RAM streaming decompressor that expands compressed
 * staging payloads into a target slot, resumable via WAL checkpoints.
 */

#ifndef TOOB_BOOT_DECOMP_H
#define TOOB_BOOT_DECOMP_H

#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_types.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Streams compressed Heatshrink data from flash, decompresses it with
 * the caller's arena, and writes the uncompressed firmware to dest_addr.
 *
 * @param platform Platform HAL pointer
 * @param src_addr Physical flash address of compressed payload
 * @param src_size Compressed payload length in bytes
 * @param dest_addr Physical flash address of destination
 * @param dest_max_size Maximum capacity of destination
 * @param expected_installed_size Exact uncompressed size
 * @param open_txn WAL transaction for checkpointing
 * @param arena Caller-provided memory buffer
 * @param arena_len Arena length (>= 1024 bytes)
 * @return BOOT_OK on success, error code otherwise.
 */
boot_status_t boot_decomp_apply(const boot_platform_t *platform, uint32_t src_addr, size_t src_size,
                                uint32_t dest_addr, size_t dest_max_size,
                                uint32_t expected_installed_size, wal_entry_payload_t *open_txn,
                                uint8_t *arena, size_t arena_len);

#endif /* TOOB_BOOT_DECOMP_H */
