#ifndef TOOB_BOOT_IDENTITY_H
#define TOOB_BOOT_IDENTITY_H

#include "boot_types.h"
#include "boot_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Derives the cryptographic Device-ID from hardware secrets.
 *
 * Mathematically binds the hardware UID, the burned Root Public Key,
 * and a domain separator string into a 32-byte SHA-256 digest.
 * Operates entirely zero-allocation via iterative hashing.
 *
 * @param platform Hardware abstraction layer pointers.
 * @param out_id   32-byte output buffer for the Device-ID.
 * @return         BOOT_OK on success, otherwise error.
 */
boot_status_t boot_derive_device_id(const boot_platform_t *platform, uint8_t out_id[32]);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_BOOT_IDENTITY_H */
