/**
 * @file toob_crc32_contract.h
 * @brief CRC-32 algorithm contract — shared constants between Core and OS.
 *
 * Both sides implement CRC-32 with intentionally different strategies:
 *   Core  (boot_crc32.c)  — table-less, byte-at-a-time (minimal BSS).
 *   OS    (toob_crc32.c)  — 1KB lookup table (maximal throughput).
 *
 * This header guarantees both use the same polynomial, initial value, and
 * final XOR, producing bit-identical results. Implementors include this
 * header and static-assert against the contract constants.
 */

#ifndef TOOB_CRC32_CONTRACT_H
#define TOOB_CRC32_CONTRACT_H

#include <stdint.h>

#define TOOB_CRC32_POLY      0xEDB88320u  /* IEEE 802.3 reflected polynomial */
#define TOOB_CRC32_INIT      0xFFFFFFFFu
#define TOOB_CRC32_FINAL_XOR 0xFFFFFFFFu  /* result = ~accumulator */

#endif /* TOOB_CRC32_CONTRACT_H */
