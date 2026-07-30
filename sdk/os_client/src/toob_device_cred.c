/**
 * @file toob_device_cred.c
 * @brief Device Credential Store implementation (UPD-003)
 *
 * Platform-independent read/write of the device credential blob.
 * All NVS access is routed through the toob_os_nvs_read/write porting hooks.
 */

#include "toob_device_cred.h"
#include "toob_port.h"
#include <string.h>

#define CRED_NVS_KEY "toob_sys/cred"

toob_status_t toob_cred_load(toob_device_cred_t *out) {
    if (!out) return TOOB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    size_t len = sizeof(toob_device_cred_t);
    toob_status_t st = toob_os_nvs_read(CRED_NVS_KEY, (uint8_t *)out, &len);
    if (st != TOOB_OK) {
        memset(out, 0, sizeof(*out));
        return st;
    }
    if (len != sizeof(toob_device_cred_t)) {
        memset(out, 0, sizeof(*out));
        return TOOB_ERR_VERIFY;
    }
    return TOOB_OK;
}

toob_status_t toob_cred_bump_seq(uint64_t *out_seq) {
    if (!out_seq) return TOOB_ERR_INVALID_ARG;

    toob_device_cred_t cred;
    toob_status_t st = toob_cred_load(&cred);
    if (st != TOOB_OK) return st;

    cred.checkin_seq++;

    st = toob_os_nvs_write(CRED_NVS_KEY, (const uint8_t *)&cred, sizeof(cred));
    if (st != TOOB_OK) return st;

    *out_seq = cred.checkin_seq;
    return TOOB_OK;
}

toob_status_t toob_cred_rotate_token(const uint8_t new_token[TOOB_DEVICE_TOKEN_LEN]) {
    if (!new_token) return TOOB_ERR_INVALID_ARG;

    toob_device_cred_t cred;
    toob_status_t st = toob_cred_load(&cred);
    if (st != TOOB_OK) return st;

    memcpy(cred.device_token, new_token, TOOB_DEVICE_TOKEN_LEN);

    return toob_os_nvs_write(CRED_NVS_KEY, (const uint8_t *)&cred, sizeof(cred));
}
