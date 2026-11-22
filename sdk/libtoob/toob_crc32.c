#include "toob_internal.h"
#include "toob_crc32_contract.h"

/* IEEE 802.3 CRC-32 — 16-entry (64-byte) nibble lookup table for OS-side footprint & speed.
 * Core (boot_crc32.c) uses a table-less byte-at-a-time variant for minimal Stage 0/1 footprint.
 * Both produce identical results per toob_crc32_contract.h. */

static const uint32_t toob_crc32_nibble_table[16] = {
    0x00000000U, 0x1DB71064U, 0x3B6E20C8U, 0x26D930ACU,
    0x76DC4190U, 0x6B6B51F4U, 0x4DB26158U, 0x5005713CU,
    0xEDB88320U, 0xF00F9344U, 0xD6D6A3E8U, 0xCB61B38CU,
    0x9B64C2B0U, 0x86D3D2D4U, 0xA00AE278U, 0xBDBDF21CU
};

/* nibble_table[8] == TOOB_CRC32_POLY (0xEDB88320U) per contract polynomial */
_Static_assert(sizeof(toob_crc32_nibble_table) / sizeof(toob_crc32_nibble_table[0]) == 16U,
               "CRC-32 nibble table must contain exactly 16 entries");

uint32_t toob_lib_crc32(const uint8_t *data, size_t length) {
    /* No NULL-guard: a page fault on NULL is the correct failure mode.
     * Returning 0 would mimic a valid empty-buffer CRC and mask caller bugs. */
    uint32_t crc = TOOB_CRC32_INIT;
    for (size_t i = 0U; i < length; i++) {
        uint8_t b = data[i];
        crc = (crc >> 4U) ^ toob_crc32_nibble_table[(crc ^ b) & 0x0FU];
        crc = (crc >> 4U) ^ toob_crc32_nibble_table[(crc ^ (b >> 4U)) & 0x0FU];
    }
    return crc ^ TOOB_CRC32_FINAL_XOR;
}

