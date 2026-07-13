/**
 * @file toob_port.h
 * @brief Platform Porting Hooks for libtoob.
 *
 * This header defines the structural contracts and interface hooks that the
 * guest OS (e.g. Zephyr, FreeRTOS, baremetal) must physically implement to
 * bridge libtoob with the vendor-specific hardware.
 */

#ifndef TOOB_PORT_H
#define TOOB_PORT_H

#include "libtoob_types.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==============================================================================
 * 1. Flash Porting Hooks
 * ============================================================================== */

/**
 * @brief Hook: Physical Flash Read.
 * @param addr Absolute byte address in SPI flash.
 * @param buf Data buffer in local OS SRAM.
 * @param len Length of the data to read in bytes.
 * @return TOOB_OK on success, or TOOB_ERR_FLASH / TOOB_ERR_FLASH_HW on hardware failure.
 */
TOOB_MUST_CHECK toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len);

/**
 * @brief Hook: Physical Flash Write.
 * @param addr Absolute byte address in SPI flash (must be page-aligned).
 * @param buf Constant data buffer containing payload to be written.
 * @param len Length of the data to write in bytes.
 * @return TOOB_OK on success, or TOOB_ERR_FLASH / TOOB_ERR_FLASH_HW on hardware failure.
 */
TOOB_MUST_CHECK toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len);

/**
 * @brief Hook: Physical Flash Sector Erase.
 * @param addr Absolute byte address in SPI flash (must be sector-aligned).
 * @param len Length of data to erase (must be sector-aligned).
 * @return TOOB_OK on success, or TOOB_ERR_FLASH / TOOB_ERR_FLASH_HW on hardware failure.
 */
TOOB_MUST_CHECK toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len);

/* ==============================================================================
 * 2. Cryptography Porting Hooks (SHA-256 Stream acceleration OS-side)
 * ============================================================================== */

typedef struct {
    uint8_t opaque[128]; /* Context buffer for the OS hardware crypto driver */
} toob_os_sha256_ctx_t;

/**
 * @brief Hook: Initialize streaming SHA-256 context.
 * @param ctx Context structure to initialize.
 * @return TOOB_OK on success, or TOOB_ERR_NOT_SUPPORTED / TOOB_ERR_VERIFY.
 */
TOOB_MUST_CHECK toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx);

/**
 * @brief Hook: Feed data into the streaming SHA-256 engine.
 * @param ctx Active context structure.
 * @param data Chunk data pointer.
 * @param len Length of the chunk in bytes.
 * @return TOOB_OK on success, or TOOB_ERR_NOT_SUPPORTED / TOOB_ERR_VERIFY.
 */
TOOB_MUST_CHECK toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len);

/**
 * @brief Hook: Finalize streaming SHA-256 calculation and output hash.
 * @param ctx Active context structure.
 * @param out_hash Output buffer of exactly 32 bytes.
 * @return TOOB_OK on success, or TOOB_ERR_NOT_SUPPORTED / TOOB_ERR_VERIFY.
 */
TOOB_MUST_CHECK toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_PORT_H */
