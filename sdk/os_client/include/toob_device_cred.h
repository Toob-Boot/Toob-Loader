/**
 * @file toob_device_cred.h
 * @brief Device Credential Store (UPD-003)
 *
 * Manages a persistent bearer token and monotonic check-in sequence counter
 * in OS-managed NVS. The credential is written during device enrollment
 * (provisioning) and read on every check-in.
 *
 * This module intentionally does NOT live inside the bootloader core — the
 * credential is an OS-side concern, persisted in the OS NVS partition, not
 * in the bootloader-sealed .noinit or WAL regions.
 */

#ifndef TOOB_DEVICE_CRED_H
#define TOOB_DEVICE_CRED_H

#include "libtoob_types.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sent as 64 lower-case hex characters (Authorization: Bearer <hex>); the server HMACs that string. */
#define TOOB_DEVICE_TOKEN_LEN   32
/* Persistent NVS envelope size: 4B magic + 4B CRC-32 + 8B checkin_seq + 32B token (TCI1-07). */
#define TOOB_CRED_NVS_BLOB_SIZE 48U

/**
 * @brief Decoded device credential state.
 *
 * Persisted atomically under the NVS key "toob_sys/cred" inside a 48-byte
 * Magic + IEEE 802.3 CRC-32 envelope protected by toob_os_lock().
 */
typedef struct {
    uint8_t  device_token[TOOB_DEVICE_TOKEN_LEN];
    uint64_t checkin_seq;
} toob_device_cred_t;

_Static_assert(sizeof(toob_device_cred_t) == 40,
               "toob_device_cred_t ABI size drift");

/**
 * @brief Enroll initial 32-byte device token into OS NVS with checkin_seq = 0 (TCI1-07).
 *
 * Rejects NULL, all-0x00, and all-0xFF tokens. Writes a CRC-32-sealed 48-byte
 * NVS envelope under toob_os_lock().
 *
 * @param token 32-byte provisioned bearer token.
 * @return TOOB_OK on success, TOOB_ERR_INVALID_ARG on NULL/degenerate token,
 *         or TOOB_ERR_FLASH on NVS write failure.
 */
TOOB_MUST_CHECK toob_status_t toob_cred_enroll(const uint8_t token[TOOB_DEVICE_TOKEN_LEN]);

/**
 * @brief Load device credentials from OS NVS.
 *
 * On any error the output struct is defensively zeroed.
 *
 * @param out  Destination struct.
 * @return TOOB_OK on success.
 *         TOOB_ERR_NOT_FOUND if no credential is stored (device not enrolled).
 *         TOOB_ERR_VERIFY if stored data has wrong size (corruption).
 *         TOOB_ERR_INVALID_ARG if out is NULL.
 */
TOOB_MUST_CHECK toob_status_t toob_cred_load(toob_device_cred_t *out);

/**
 * @brief Atomically increment checkin_seq, persist, and return new value.
 *
 * Read-modify-write of the credential blob. The incremented sequence is
 * written to NVS before returning, guaranteeing strict monotonicity across
 * reboots. At typical check-in intervals (hours), flash wear is negligible.
 *
 * @param out_seq  [out] The new sequence number after increment.
 * @return TOOB_OK on success.
 *         TOOB_ERR_NOT_FOUND if credential doesn't exist.
 *         TOOB_ERR_FLASH if NVS write fails.
 *         TOOB_ERR_INVALID_ARG if out_seq is NULL.
 */
TOOB_MUST_CHECK toob_status_t toob_cred_bump_seq(uint64_t *out_seq);

/**
 * @brief Rotate stored device token (UPD-032).
 *
 * Atomically updates the 32-byte bearer token in the OS NVS credential blob while
 * preserving checkin_seq.
 *
 * @param new_token 32-byte new token buffer.
 * @return TOOB_OK on success.
 *         TOOB_ERR_NOT_FOUND if credential doesn't exist.
 *         TOOB_ERR_FLASH if NVS write fails.
 *         TOOB_ERR_INVALID_ARG if new_token is NULL.
 */
TOOB_MUST_CHECK toob_status_t toob_cred_rotate_token(const uint8_t new_token[TOOB_DEVICE_TOKEN_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_DEVICE_CRED_H */
