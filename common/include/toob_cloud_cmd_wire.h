/**
 * @file toob_cloud_cmd_wire.h
 * @brief Fixed-layout binary wire format for signed Cloud Commands ("TCC1").
 *
 * Replaces legacy zcbor/CDDL cloud command envelopes with a deterministic,
 * 16-byte-aligned fixed binary envelope (analogous to TBM1), enabling:
 *   1. True Pre-Auth Ed25519 signature verification BEFORE parsing command
 *      fields or variable parameters (zero pre-auth parser attack surface).
 *   2. Native 16-byte block alignment for XTS-AES (ESP32-C6) and 8/16/32-byte
 *      ECC flash controllers without trailing-0xFF signature offset ambiguity.
 *   3. Zero build-time parser codegen and zero dynamic schema runtime.
 *
 * Wire layout (little-endian, total_len is always a multiple of 16 bytes):
 *   [0 .. 64)                  : toob_cloud_cmd_hdr_t (64 bytes)
 *   [64 .. 64 + aligned_plen)  : optional params (zero-padded to 16B boundary)
 *   [total_len - 64 .. total_len): Ed25519 signature over [0 .. total_len - 64)
 */

#ifndef TOOB_CLOUD_CMD_WIRE_H
#define TOOB_CLOUD_CMD_WIRE_H

#include <stddef.h>
#include <stdint.h>

/* "TCC1" in little-endian */
#define TOOB_CLOUD_CMD_MAGIC       0x31434354U
#define TOOB_CLOUD_CMD_VERSION     1U
#define TOOB_CLOUD_CMD_HDR_SIZE    64U
#define TOOB_CLOUD_CMD_SIG_SIZE    64U
#define TOOB_CLOUD_CMD_MIN_SIZE    128U
/* Bounded to BOOT_CRYPTO_ARENA_SIZE (2048) - 256B crypto work zone */
#define TOOB_CLOUD_CMD_MAX_SIZE    1792U
#define TOOB_CLOUD_CMD_ALIGN       16U
#define TOOB_CLOUD_CMD_MAX_PARAMS  (TOOB_CLOUD_CMD_MAX_SIZE - TOOB_CLOUD_CMD_MIN_SIZE)

#if defined(__GNUC__) || defined(__clang__) || defined(__ICCARM__)
#  define TOOB_TCC1_ALIGN8 __attribute__((aligned(8)))
#elif defined(_MSC_VER)
#  define TOOB_TCC1_ALIGN8 __declspec(align(8))
#else
#  define TOOB_TCC1_ALIGN8
#endif

/**
 * @brief Fixed 64-byte Cloud Command header.
 * `crc32` covers [0 .. offsetof(toob_cloud_cmd_hdr_t, crc32)) = 56 bytes.
 */
typedef struct TOOB_TCC1_ALIGN8 {
    uint32_t magic;         /*  0: TOOB_CLOUD_CMD_MAGIC (0x31434354U) */
    uint8_t  version;       /*  4: TOOB_CLOUD_CMD_VERSION (1U) */
    uint8_t  command;       /*  5: toob_cloud_cmd_t enum value */
    uint16_t flags;         /*  6: Reserved flags (must be 0) */
    uint32_t counter_min;   /*  8: Anti-replay monotonic counter floor */
    uint32_t issued_at;     /* 12: Unix timestamp (seconds) */
    uint32_t params_len;    /* 16: Exact unpadded parameter byte length */
    uint32_t total_len;     /* 20: Total envelope length (multiple of 16, 128..1792) */
    uint8_t  device_id[32]; /* 24: Target DICE device_id (SHA-256) */
    uint32_t crc32;         /* 56: CRC-32 over [0 .. 56) */
    uint32_t _reserved;     /* 60: Must be 0 */
} toob_cloud_cmd_hdr_t;

_Static_assert(sizeof(toob_cloud_cmd_hdr_t) == 64U,
               "toob_cloud_cmd_hdr_t must be exactly 64 bytes");
_Static_assert(offsetof(toob_cloud_cmd_hdr_t, device_id) == 24U,
               "toob_cloud_cmd_hdr_t.device_id offset drift");
_Static_assert(offsetof(toob_cloud_cmd_hdr_t, crc32) == 56U,
               "toob_cloud_cmd_hdr_t.crc32 offset drift");

#define TOOB_CLOUD_CMD_HDR_CRC_LEN offsetof(toob_cloud_cmd_hdr_t, crc32)

/** Aligns `n` up to a multiple of TOOB_CLOUD_CMD_ALIGN (16 bytes). */
#define TOOB_CLOUD_CMD_ALIGN_UP(n) \
    (((uint32_t)(n) + (TOOB_CLOUD_CMD_ALIGN - 1U)) & ~(TOOB_CLOUD_CMD_ALIGN - 1U))

#endif /* TOOB_CLOUD_CMD_WIRE_H */

