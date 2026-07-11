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

/**
 * @brief Derives a 16-byte device-bound journal key via KDF.
 *
 * Uses H(chip_uid ‖ root_pubkey ‖ "toob-journal-key-v1"), truncated
 * to 16 bytes. The key is used by the WAL chain mechanism (K4) to
 * compute device-bound chain tags over security-bearing journal entries.
 *
 * On chips without fuse secrets the binding degrades to
 * chip_uid + root_pubkey only (documented in security_model.md).
 *
 * @param platform Hardware abstraction layer pointers.
 * @param out_key  16-byte output buffer for the journal key.
 * @return         BOOT_OK on success, otherwise error.
 */
boot_status_t boot_derive_journal_key(const boot_platform_t *platform,
                                      uint8_t out_key[16]);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_BOOT_IDENTITY_H */
