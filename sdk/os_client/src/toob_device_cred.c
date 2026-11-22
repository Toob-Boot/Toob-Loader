/**
 * @file toob_device_cred.c
 * @brief Device Credential Store implementation (UPD-003)
 *
 * Platform-independent read/write of the device credential blob.
 * All NVS access is routed through the toob_os_nvs_read/write porting hooks,
 * and all temporary stack copies of bearer tokens are securely zeroized
 * before every return (HIGH-25).
 */

#include "toob_device_cred.h"
#include "libtoob.h"
#include "toob_port.h"
#include <string.h>

#define CRED_NVS_KEY       "toob_sys/cred"
#define CRED_ENV_MAGIC     0x31524354U /* "TCR1" LE */
#define CRED_ENV_HDR_BYTES 8U          /* magic(4) + crc32(4) */

static void _cred_secure_zeroize(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0U) {
        *p++ = 0U;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : : "g"(ptr) : "memory");
#endif
}

static bool _cred_token_is_valid(const uint8_t tok[TOOB_DEVICE_TOKEN_LEN]) {
    uint8_t diff_zero = 0U;
    uint8_t diff_ones = 0U;
    for (size_t i = 0U; i < TOOB_DEVICE_TOKEN_LEN; i++) {
        diff_zero |= tok[i];
        diff_ones |= (uint8_t)(tok[i] ^ 0xFFU);
    }
    return (diff_zero != 0U) && (diff_ones != 0U);
}

static toob_status_t _cred_store_unlocked(const toob_device_cred_t *cred) {
    uint8_t raw[TOOB_CRED_NVS_BLOB_SIZE];
    _cred_secure_zeroize(raw, sizeof(raw));

    toob_wire_put_le32(&raw[0], CRED_ENV_MAGIC);
    toob_wire_put_le64(&raw[8], cred->checkin_seq);
    memcpy(&raw[16], cred->device_token, TOOB_DEVICE_TOKEN_LEN);

    uint32_t crc = toob_lib_crc32(&raw[CRED_ENV_HDR_BYTES],
                                  TOOB_CRED_NVS_BLOB_SIZE - CRED_ENV_HDR_BYTES);
    toob_wire_put_le32(&raw[4], crc);

    toob_status_t st = toob_os_nvs_write(CRED_NVS_KEY, raw, sizeof(raw));
    _cred_secure_zeroize(raw, sizeof(raw));
    return st;
}

static toob_status_t _cred_load_unlocked(toob_device_cred_t *out) {
    _cred_secure_zeroize(out, sizeof(*out));

    uint8_t raw[TOOB_CRED_NVS_BLOB_SIZE];
    _cred_secure_zeroize(raw, sizeof(raw));

    size_t len = sizeof(raw);
    toob_status_t st = toob_os_nvs_read(CRED_NVS_KEY, raw, &len);
    if (st != TOOB_OK) {
        _cred_secure_zeroize(raw, sizeof(raw));
        return st;
    }
    if (len != TOOB_CRED_NVS_BLOB_SIZE) {
        _cred_secure_zeroize(raw, sizeof(raw));
        return TOOB_ERR_VERIFY;
    }

    uint32_t magic = toob_wire_get_le32(&raw[0]);
    uint32_t stored_crc = toob_wire_get_le32(&raw[4]);
    uint32_t calc_crc = toob_lib_crc32(&raw[CRED_ENV_HDR_BYTES],
                                       TOOB_CRED_NVS_BLOB_SIZE - CRED_ENV_HDR_BYTES);
    if (magic != CRED_ENV_MAGIC || calc_crc != stored_crc || !_cred_token_is_valid(&raw[16])) {
        _cred_secure_zeroize(raw, sizeof(raw));
        return TOOB_ERR_VERIFY;
    }

    out->checkin_seq = toob_wire_get_le64(&raw[8]);
    memcpy(out->device_token, &raw[16], TOOB_DEVICE_TOKEN_LEN);
    _cred_secure_zeroize(raw, sizeof(raw));
    return TOOB_OK;
}

toob_status_t toob_cred_enroll(const uint8_t token[TOOB_DEVICE_TOKEN_LEN]) {
    if (!token || !_cred_token_is_valid(token)) {
        return TOOB_ERR_INVALID_ARG;
    }

    toob_device_cred_t cred;
    _cred_secure_zeroize(&cred, sizeof(cred));
    memcpy(cred.device_token, token, TOOB_DEVICE_TOKEN_LEN);
    cred.checkin_seq = 0ULL;

    toob_os_lock();
    toob_status_t st = _cred_store_unlocked(&cred);
    toob_os_unlock();

    _cred_secure_zeroize(&cred, sizeof(cred));
    return st;
}

toob_status_t toob_cred_load(toob_device_cred_t *out) {
    if (!out) {
        return TOOB_ERR_INVALID_ARG;
    }
    toob_os_lock();
    toob_status_t st = _cred_load_unlocked(out);
    toob_os_unlock();
    return st;
}

toob_status_t toob_cred_bump_seq(uint64_t *out_seq) {
    if (!out_seq) {
        return TOOB_ERR_INVALID_ARG;
    }
    *out_seq = 0ULL;

    toob_device_cred_t cred;
    _cred_secure_zeroize(&cred, sizeof(cred));

    toob_os_lock();
    toob_status_t st = _cred_load_unlocked(&cred);
    if (st == TOOB_OK) {
        if (cred.checkin_seq == UINT64_MAX) {
            st = TOOB_ERR_COUNTER_EXHAUSTED;
        } else {
            cred.checkin_seq++;
            st = _cred_store_unlocked(&cred);
            if (st == TOOB_OK) {
                *out_seq = cred.checkin_seq;
            }
        }
    }
    toob_os_unlock();

    _cred_secure_zeroize(&cred, sizeof(cred));
    return st;
}

toob_status_t toob_cred_rotate_token(const uint8_t new_token[TOOB_DEVICE_TOKEN_LEN]) {
    if (!new_token || !_cred_token_is_valid(new_token)) {
        return TOOB_ERR_INVALID_ARG;
    }

    toob_device_cred_t cred;
    _cred_secure_zeroize(&cred, sizeof(cred));

    toob_os_lock();
    toob_status_t st = _cred_load_unlocked(&cred);
    if (st == TOOB_OK) {
        memcpy(cred.device_token, new_token, TOOB_DEVICE_TOKEN_LEN);
        st = _cred_store_unlocked(&cred);
    }
    toob_os_unlock();

    _cred_secure_zeroize(&cred, sizeof(cred));
    return st;
}
