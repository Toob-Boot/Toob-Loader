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

#define TOOB_DEVICE_TOKEN_LEN 32

/**
 * @brief Persistent device credential blob.
 *
 * Stored as a single atomic blob under the NVS key "toob_sys/cred".
 * The struct is serialized byte-for-byte — no versioning header, because
 * the ABI is locked by _Static_assert and the key is namespaced.
 */
typedef struct {
    uint8_t  device_token[TOOB_DEVICE_TOKEN_LEN];
    uint64_t checkin_seq;
} toob_device_cred_t;

_Static_assert(sizeof(toob_device_cred_t) == 40,
               "toob_device_cred_t ABI size drift");

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
