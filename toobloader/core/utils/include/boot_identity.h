#ifndef TOOB_BOOT_IDENTITY_H
#define TOOB_BOOT_IDENTITY_H

#include "boot_hal.h"
#include "boot_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Resolves the highest contiguous non-revoked OTP Root Public Key slot.
 *
 * Double-reads every OTP slot in [0, TOOB_MAX_OTP_SLOTS) and verifies both
 * populated slot integrity (non-zero/non-0xFF and read-back agreement) and a
 * contiguous blank tail (no holes after the first BOOT_ERR_NOT_FOUND).
 *
 * @param platform Hardware abstraction layer pointers.
 * @param out_idx  Output pointer receiving the active OTP key slot index.
 * @return         BOOT_OK on valid contiguous table, BOOT_ERR_VERIFY on fault/hole.
 */
boot_status_t boot_otp_get_active_key_index(const boot_platform_t *platform, uint8_t *out_idx);

/**
 * @brief Derives the cryptographic Device-ID from hardware secrets.
 *
 * Mathematically binds the hardware UID, the burned Root Public Key (slot 0),
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
 * When keystore->read_device_secret is present, derives
 * H(device_secret || chip_uid || active_pubkey || "toob-journal-key-v2")[0:16].
 * Chips without a hardware device secret require explicit
 * TOOB_ALLOW_PUBLIC_JOURNAL_KEY_DEGRADATION (v1 fallback) and otherwise fail
 * closed with BOOT_ERR_NOT_SUPPORTED.
 *
 * @param platform Hardware abstraction layer pointers.
 * @param out_key  16-byte output buffer for the journal key.
 * @return         BOOT_OK on success, otherwise error.
 */
boot_status_t boot_derive_journal_key(const boot_platform_t *platform, uint8_t out_key[16]);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_BOOT_IDENTITY_H */
