#ifndef BOOT_COBS_H
#define BOOT_COBS_H

/**
 * @file boot_cobs.h
 * @brief Consistent Overhead Byte Stuffing (COBS) Framing Layer
 *
 * Shared transport primitive for all UART-based protocols in Toob-Boot:
 * - Stage 1.5 Serial Rescue (boot_panic.c)
 * - Factory Provisioning (boot_provisioning.c)
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/stage_1_5_spec.md (COBS Frame Format, Sync Markers)
 * - S. Cheshire, M. Baker: "Consistent Overhead Byte Stuffing" (IEEE/ACM 1999)
 *
 * SECURITY CONTRACT:
 * - Zero-Allocation: Decode operates in-place (no heap, no secondary buffer).
 * - Glitch-Shielded bounds checks on every COBS block (Anti-RCE).
 * - Trailing garbage is zeroized after decode (Anti-Leakage).
 */

#include "boot_hal.h"
#include <stddef.h>
#include <stdint.h>

/* Frame Sync Markers (COBS uses 0x00 as delimiter) */
#define COBS_MARKER_START 0x00
#define COBS_MARKER_END   0x00

/**
 * @brief Streams a buffer to UART using Naked COBS encoding with O(1) memory.
 *
 * Emits [START_MARKER] [COBS-Encoded Payload] [END_MARKER] with native
 * WDT feeding during transmission to prevent watchdog resets on large payloads.
 *
 * @param platform  Initialized platform (console HAL required).
 * @param data      Raw payload to encode and transmit.
 * @param len       Payload length in bytes (must be > 0).
 */
void boot_cobs_send_frame(const boot_platform_t *platform,
                          const uint8_t *data, size_t len);

/**
 * @brief O(1) in-place Naked COBS Decoder.
 *
 * Decodes a COBS-encoded payload by shifting bytes forward within the
 * same buffer. Uses __restrict to enable register-level optimization
 * since read and write pointers never collide.
 *
 * SECURITY:
 * - Glitch-shielded bounds check per COBS block (prevents RCE via overflow).
 * - Trailing bytes beyond decoded length are zeroized (Anti-Leakage).
 *
 * @param data     COBS-encoded buffer (modified in-place).
 * @param len      Length of the encoded data.
 * @param out_len  Receives the decoded payload length.
 * @return BOOT_OK on success, BOOT_ERR_INVALID_ARG on malformed input.
 */
boot_status_t boot_cobs_decode_in_place(uint8_t *__restrict data, size_t len,
                                        size_t *__restrict out_len);

/**
 * @brief Receives a single COBS-framed message from UART.
 *
 * Blocks until a complete frame [data...] [END_MARKER] is received.
 * Feeds the WDT during the wait to prevent watchdog resets.
 *
 * @param platform    Initialized platform (console + WDT HAL required).
 * @param buf         Receive buffer (raw COBS-encoded bytes, no markers).
 * @param buf_max     Maximum buffer capacity.
 * @param out_len     Receives the number of raw bytes placed in buf.
 * @return BOOT_OK when a complete frame has been received. On buffer overflow,
 *         the receive buffer is silently zeroized and the function retries
 *         (consistent with boot_panic.c overflow defense).
 */
boot_status_t boot_cobs_recv_frame(const boot_platform_t *platform,
                                   uint8_t *buf, size_t buf_max,
                                   size_t *out_len);

#endif /* BOOT_COBS_H */
