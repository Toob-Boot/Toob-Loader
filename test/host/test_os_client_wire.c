/**
 * @file test_os_client_wire.c
 * @brief Host-SIL End-to-End Conformance Test for TDR1 / TCI1 Check-In Wire
 *        Protocol across sdk/libtoob, sdk/os_client, and TCC1 Cloud Commands.
 *
 * Verifies:
 *   1. Unenrolled NVS fail-closed gate (zero HTTP traffic).
 *   2. TDR1 binary telemetry POST serialization + IEEE 802.3 CRC-32 + headers.
 *   3. Fail-closed TCI1 rejection on CRC bit-flip, unknown flags, trailing
 *      bytes, and SSRF blob_path injection (':', "//", missing leading '/').
 *   4. Control-only TCI1 frame (total_size == 0) executing token rotation +
 *      signed TCC1 cloud command submission without triggering a blob GET.
 *   5. Forward-compatible TCI1 frame (header_size == 88 > 80) + full SHA-256
 *      verified OTA stream + Mailbox UPDATE_PENDING seal.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libtoob_config_sandbox.h"
#include "libtoob.h"
#include "toob_checkin_wire.h"
#include "toob_cloud_cmd_wire.h"
#include "toob_device_cred.h"
#include "toob_internal.h"
#include "toob_mailbox_wire.h"
#include "toob_network_client.h"

extern void toob_mailbox_session_reset_for_test(void);

/* ============================================================================
 * Compact FIPS 180-4 SHA-256 Reference Implementation
 * ============================================================================ */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    uint32_t datalen;
} ref_sha256_ctx_t;

static const uint32_t k_sha256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

static void ref_sha256_transform(ref_sha256_ctx_t *c, const uint8_t data[64]) {
    uint32_t m[64];
    for (uint32_t i = 0U, j = 0U; i < 16U; i++, j += 4U) {
        m[i] = ((uint32_t)data[j] << 24U) | ((uint32_t)data[j + 1U] << 16U) |
               ((uint32_t)data[j + 2U] << 8U) | (uint32_t)data[j + 3U];
    }
    for (uint32_t i = 16U; i < 64U; i++) {
        uint32_t s0 = rotr32(m[i - 15U], 7U) ^ rotr32(m[i - 15U], 18U) ^ (m[i - 15U] >> 3U);
        uint32_t s1 = rotr32(m[i - 2U], 17U) ^ rotr32(m[i - 2U], 19U) ^ (m[i - 2U] >> 10U);
        m[i] = m[i - 16U] + s0 + m[i - 7U] + s1;
    }
    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];
    for (uint32_t i = 0U; i < 64U; i++) {
        uint32_t S1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + k_sha256[i] + m[i];
        uint32_t S0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g;  c->state[7] += h;
}

static void ref_sha256_init(ref_sha256_ctx_t *c) {
    c->datalen = 0U;
    c->bitlen = 0ULL;
    c->state[0] = 0x6a09e667U; c->state[1] = 0xbb67ae85U;
    c->state[2] = 0x3c6ef372U; c->state[3] = 0xa54ff53aU;
    c->state[4] = 0x510e527fU; c->state[5] = 0x9b05688cU;
    c->state[6] = 0x1f83d9abU; c->state[7] = 0x5be0cd19U;
}

static void ref_sha256_update(ref_sha256_ctx_t *c, const uint8_t *data, size_t len) {
    for (size_t i = 0U; i < len; i++) {
        c->data[c->datalen++] = data[i];
        if (c->datalen == 64U) {
            ref_sha256_transform(c, c->data);
            c->bitlen += 512ULL;
            c->datalen = 0U;
        }
    }
}

static void ref_sha256_final(ref_sha256_ctx_t *c, uint8_t hash[32]) {
    uint32_t i = c->datalen;
    if (c->datalen < 56U) {
        c->data[i++] = 0x80U;
        while (i < 56U) c->data[i++] = 0x00U;
    } else {
        c->data[i++] = 0x80U;
        while (i < 64U) c->data[i++] = 0x00U;
        ref_sha256_transform(c, c->data);
        memset(c->data, 0, 56U);
    }
    c->bitlen += (uint64_t)c->datalen * 8ULL;
    for (uint32_t b = 0U; b < 8U; b++) {
        c->data[63U - b] = (uint8_t)(c->bitlen >> (b * 8U));
    }
    ref_sha256_transform(c, c->data);
    for (i = 0U; i < 4U; i++) {
        for (uint32_t w = 0U; w < 8U; w++) {
            hash[i + w * 4U] = (uint8_t)((c->state[w] >> (24U - i * 8U)) & 0xFFU);
        }
    }
}

static void compute_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    ref_sha256_ctx_t c;
    ref_sha256_init(&c);
    ref_sha256_update(&c, data, len);
    ref_sha256_final(&c, out);
}

static void compute_hmac_sha256_3(const uint8_t key[32],
                                  const uint8_t *p1, size_t l1,
                                  const uint8_t *p2, size_t l2,
                                  const uint8_t *p3, size_t l3,
                                  uint8_t out[32]) {
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[32];
    memset(ipad, 0x36U, sizeof(ipad));
    memset(opad, 0x5CU, sizeof(opad));
    for (size_t i = 0U; i < 32U; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    ref_sha256_ctx_t c;
    ref_sha256_init(&c);
    ref_sha256_update(&c, ipad, sizeof(ipad));
    if (l1 > 0U) ref_sha256_update(&c, p1, l1);
    if (l2 > 0U) ref_sha256_update(&c, p2, l2);
    if (l3 > 0U) ref_sha256_update(&c, p3, l3);
    ref_sha256_final(&c, inner);

    ref_sha256_init(&c);
    ref_sha256_update(&c, opad, sizeof(opad));
    ref_sha256_update(&c, inner, sizeof(inner));
    ref_sha256_final(&c, out);
}

/* ============================================================================
 * Mock Flash, .noinit RAM, NVS & HTTP Transport
 * ============================================================================ */

#define MOCK_FLASH_SIZE 0x00100000U

#if !defined(_WIN32) && !defined(TOOB_HOST_FUZZING)
toob_handoff_t          toob_handoff_state;
toob_boot_diag_t        toob_diag_state;
toob_ota_resume_state_t g_toob_ota_resume_state;
#endif

static uint8_t  g_flash[MOCK_FLASH_SIZE];
static uint32_t g_flash_write_calls = 0U;
static uint32_t g_flash_erase_calls = 0U;
static bool     g_has_cred = false;
static uint8_t  g_cred_blob[TOOB_CRED_NVS_BLOB_SIZE];

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
    if (!buf || addr > MOCK_FLASH_SIZE || len > (MOCK_FLASH_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }
    memcpy(buf, &g_flash[addr], len);
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len) {
    if (!buf || len == 0U ||
        (addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
        (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
        addr > MOCK_FLASH_SIZE || len > (MOCK_FLASH_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }
    for (uint32_t i = 0U; i < len; i++) {
        g_flash[addr + i] &= buf[i];
    }
    g_flash_write_calls++;
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if ((addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U ||
        (len % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U ||
        addr > MOCK_FLASH_SIZE || len > (MOCK_FLASH_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }
    memset(&g_flash[addr], 0xFF, len);
    g_flash_erase_calls++;
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx) {
    ref_sha256_init((ref_sha256_ctx_t *)ctx->opaque);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len) {
    ref_sha256_update((ref_sha256_ctx_t *)ctx->opaque, data, len);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32]) {
    ref_sha256_final((ref_sha256_ctx_t *)ctx->opaque, out_hash);
    return TOOB_OK;
}

void toob_os_lock(void) {}
void toob_os_unlock(void) {}

toob_status_t toob_os_confirm_rtc_write(uint64_t boot_nonce) {
    (void)boot_nonce;
    return TOOB_OK;
}

toob_status_t toob_os_nvs_read(const char *key, uint8_t *out_buf, size_t *inout_len) {
    if (!key || !out_buf || !inout_len || strcmp(key, "toob_sys/cred") != 0) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (!g_has_cred) {
        return TOOB_ERR_NOT_FOUND;
    }
    if (*inout_len < sizeof(g_cred_blob)) {
        return TOOB_ERR_INVALID_ARG;
    }
    memcpy(out_buf, g_cred_blob, sizeof(g_cred_blob));
    *inout_len = sizeof(g_cred_blob);
    return TOOB_OK;
}

toob_status_t toob_os_nvs_write(const char *key, const uint8_t *buf, size_t len) {
    if (!key || !buf || strcmp(key, "toob_sys/cred") != 0 || len != sizeof(g_cred_blob)) {
        return TOOB_ERR_INVALID_ARG;
    }
    memcpy(g_cred_blob, buf, sizeof(g_cred_blob));
    g_has_cred = true;
    return TOOB_OK;
}

/* Mock HTTP Server State */
static uint32_t g_post_calls = 0U;
static uint32_t g_get_calls  = 0U;
static char     g_last_post_url[256];
static char     g_last_get_url[256];
static char     g_last_auth_hdr[192];
static char     g_last_ctype_hdr[128];
static char     g_last_seq_hdr[64];
static uint8_t  g_last_post_body[512];
static uint32_t g_last_post_body_len = 0U;

static uint16_t g_mock_post_status = 200U;
static uint8_t  g_mock_tci1_resp[600];
static size_t   g_mock_tci1_resp_len = 0U;

static uint16_t g_mock_get_status = 200U;
static uint8_t  g_mock_blob[2048];
static size_t   g_mock_blob_len = 0U;

static uint32_t g_last_get_range = 0U;

toob_status_t toob_network_init(void) {
    return TOOB_OK;
}

toob_status_t rtos_http_request(
    toob_http_method_t method,
    const char *url,
    const char *const *headers, uint32_t header_count,
    const uint8_t *body, uint32_t body_len,
    uint32_t range_offset,
    toob_http_chunk_cb_t callback, void *ctx,
    uint16_t *out_status,
    uint32_t *out_retry_after_s) {
    *out_retry_after_s = 300U;

    if (method == TOOB_HTTP_POST) {
        g_post_calls++;
        snprintf(g_last_post_url, sizeof(g_last_post_url), "%s", url);
        g_last_auth_hdr[0] = '\0';
        g_last_ctype_hdr[0] = '\0';
        g_last_seq_hdr[0] = '\0';
        for (uint32_t i = 0U; i < header_count; i++) {
            if (strncmp(headers[i], "Authorization:", 14U) == 0) {
                snprintf(g_last_auth_hdr, sizeof(g_last_auth_hdr), "%s", headers[i]);
            } else if (strncmp(headers[i], "Content-Type:", 13U) == 0) {
                snprintf(g_last_ctype_hdr, sizeof(g_last_ctype_hdr), "%s", headers[i]);
            } else if (strncmp(headers[i], "X-Toob-Seq:", 11U) == 0) {
                snprintf(g_last_seq_hdr, sizeof(g_last_seq_hdr), "%s", headers[i]);
            }
        }
        assert(body_len <= sizeof(g_last_post_body));
        if (body_len > 0U) {
            memcpy(g_last_post_body, body, body_len);
        }
        g_last_post_body_len = body_len;

        *out_status = g_mock_post_status;
        if (g_mock_post_status == 204U) {
            return TOOB_OK;
        }
        /* Stream TCI1 response in small 29-byte fragments to test _manifest_chunk_cb reassembly! */
        size_t pos = 0U;
        while (pos < g_mock_tci1_resp_len) {
            size_t take = g_mock_tci1_resp_len - pos;
            if (take > 29U) {
                take = 29U;
            }
            toob_status_t st = callback(&g_mock_tci1_resp[pos], (uint32_t)take, ctx);
            if (st != TOOB_OK) {
                return st;
            }
            pos += take;
        }
        return TOOB_OK;
    }

    g_get_calls++;
    g_last_get_range = range_offset;
    snprintf(g_last_get_url, sizeof(g_last_get_url), "%s", url);
    *out_status = g_mock_get_status;
    size_t pos = (g_mock_get_status == 206U && range_offset < g_mock_blob_len) ? (size_t)range_offset : 0U;
    while (pos < g_mock_blob_len) {
        size_t take = g_mock_blob_len - pos;
        if (take > 61U) {
            take = 61U;
        }
        toob_status_t st = callback(&g_mock_blob[pos], (uint32_t)take, ctx);
        if (st != TOOB_OK) {
            return st;
        }
        pos += take;
    }
    return TOOB_OK;
}

/* ============================================================================
 * Helpers to Initialize Handoff, Diag & TCI1 Wire Frames
 * ============================================================================ */

static void setup_valid_runtime_state(uint32_t current_svn) {
    memset(g_flash, 0xFF, sizeof(g_flash));
    g_flash_write_calls = 0U;
    g_flash_erase_calls = 0U;
    memset(&g_toob_ota_resume_state, 0, sizeof(g_toob_ota_resume_state));
    toob_mailbox_session_reset_for_test();

    memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
    toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
    toob_handoff_state.magic = TOOB_STATE_COMMITTED;
    toob_handoff_state.boot_nonce = 0xCAFEBABE11223344ULL;
    toob_handoff_state.active_slot = 0U;
    toob_handoff_state.booted_partition = TOOB_PARTITION_APP;
    memset(toob_handoff_state.device_id, 0x42, 32U);
    toob_handoff_state.crc32_trailer = toob_lib_crc32(
        (const uint8_t *)&toob_handoff_state,
        offsetof(toob_handoff_t, crc32_trailer));

    memset(&toob_diag_state, 0, sizeof(toob_diag_state));
    toob_diag_state.struct_version = TOOB_DIAG_STRUCT_VERSION;
    toob_diag_state.current_svn = current_svn;
    toob_diag_state.installed_app_svn = current_svn;
    toob_diag_state.installed_stage1_svn = 2U;
    toob_diag_state.build_number = 77U;
    toob_diag_state.reader_major = 2U;
    toob_diag_state.reader_minor = 1U;
    toob_diag_state.ext_health_present = 1U;
    toob_diag_state.ext_health.wal_erase_count = 3U;
    toob_diag_state.ext_health.swap_buffer_erase_count = 9U;
    toob_diag_state.crc32_trailer = toob_lib_crc32(
        (const uint8_t *)&toob_diag_state,
        offsetof(toob_boot_diag_t, crc32_trailer));
}

static size_t build_tci1_frame(uint8_t *dst,
                               const uint8_t token_key[32],
                               const uint8_t device_id[32],
                               uint64_t seq_echo,
                               uint16_t hdr_size,
                               uint8_t target_slot,
                               uint16_t extra_flags,
                               uint32_t remote_svn,
                               uint32_t remote_build,
                               uint32_t total_size,
                               const uint8_t sha256[32],
                               const uint8_t assignment_id[16],
                               const char *blob_path,
                               const uint8_t *rot_tok,
                               const uint8_t *cloud_cmd,
                               uint16_t cloud_cmd_len) {
    size_t blob_len = (blob_path != NULL) ? strlen(blob_path) : 0U;
    size_t rot_len = (rot_tok != NULL) ? 32U : 0U;
    size_t body_len = (size_t)hdr_size + blob_len + rot_len + (size_t)cloud_cmd_len;
    size_t total_len = body_len + TOOB_TCI1_AUTH_TAG_LEN;
    memset(dst, 0, total_len);

    uint16_t flags = extra_flags;
    if (rot_tok != NULL) {
        flags |= TOOB_TCI1_FLAG_HAS_ROTATED_TOKEN;
    }
    if (cloud_cmd != NULL && cloud_cmd_len > 0U) {
        flags |= TOOB_TCI1_FLAG_HAS_CLOUD_CMD;
    }

    toob_wire_put_le32(&dst[0], TOOB_TCI1_MAGIC);
    dst[4] = TOOB_TCI1_VERSION;
    dst[5] = target_slot;
    toob_wire_put_le16(&dst[6], flags);
    toob_wire_put_le16(&dst[8], hdr_size);
    toob_wire_put_le16(&dst[10], (uint16_t)blob_len);
    toob_wire_put_le16(&dst[12], cloud_cmd_len);
    toob_wire_put_le32(&dst[16], remote_svn);
    toob_wire_put_le32(&dst[20], total_size);
    if (sha256 != NULL) {
        memcpy(&dst[24], sha256, 32U);
    }
    if (assignment_id != NULL) {
        memcpy(&dst[56], assignment_id, 16U);
    }
    toob_wire_put_le64(&dst[72], seq_echo);
    toob_wire_put_le32(&dst[80], remote_build);
    toob_wire_put_le32(&dst[84], 3600U);

    size_t off = (size_t)hdr_size;
    if (blob_len > 0U) {
        memcpy(&dst[off], blob_path, blob_len);
        off += blob_len;
    }
    if (rot_len > 0U) {
        uint8_t seq_le[8];
        uint8_t mask[32];
        toob_wire_put_le64(seq_le, seq_echo);
        compute_hmac_sha256_3(token_key,
                              (const uint8_t *)TOOB_TCI1_ROT_DOMAIN, TOOB_TCI1_ROT_DOMAIN_LEN,
                              device_id, 32U,
                              seq_le, sizeof(seq_le),
                              mask);
        for (size_t i = 0U; i < 32U; i++) {
            dst[off + i] = rot_tok[i] ^ mask[i];
        }
        off += rot_len;
    }
    if (cloud_cmd_len > 0U) {
        memcpy(&dst[off], cloud_cmd, cloud_cmd_len);
    }

    uint8_t full_mac[32];
    compute_hmac_sha256_3(token_key,
                          (const uint8_t *)TOOB_TCI1_AUTH_DOMAIN, TOOB_TCI1_AUTH_DOMAIN_LEN,
                          device_id, 32U,
                          dst, body_len,
                          full_mac);
    memcpy(&dst[body_len], full_mac, TOOB_TCI1_AUTH_TAG_LEN);
    return total_len;
}

int main(void) {
    printf("=========================================================\n");
    printf("   os_client TDR1 / TCI1 Check-In Wire Conformance Suite\n");
    printf("=========================================================\n");

    setup_valid_runtime_state(5U);
    g_has_cred = false;

    uint8_t dev_id[32];
    memset(dev_id, 0x42, sizeof(dev_id));

    /* 1. Unenrolled NVS must fail closed with zero HTTP traffic */
    assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_ERR_NOT_FOUND);
    assert(g_post_calls == 0U && g_get_calls == 0U);

    /* 1b. toob_cred_enroll rejects degenerate all-0x00 and all-0xFF tokens + NVS CRC guard */
    uint8_t zero_tok[32];
    uint8_t ff_tok[32];
    uint8_t init_tok[32];
    memset(zero_tok, 0x00, sizeof(zero_tok));
    memset(ff_tok, 0xFF, sizeof(ff_tok));
    memset(init_tok, 0xAB, sizeof(init_tok));
    assert(toob_cred_enroll(zero_tok) == TOOB_ERR_INVALID_ARG);
    assert(toob_cred_enroll(ff_tok) == TOOB_ERR_INVALID_ARG);
    assert(toob_cred_enroll(init_tok) == TOOB_OK);

    /* Flip 1 bit in NVS TCR1 blob -> toob_cred_load rejects with TOOB_ERR_VERIFY */
    g_cred_blob[12] ^= 0x01U;
    toob_device_cred_t probe_cred;
    assert(toob_cred_load(&probe_cred) == TOOB_ERR_VERIFY);
    g_cred_blob[12] ^= 0x01U;
    assert(toob_cred_load(&probe_cred) == TOOB_OK);
    assert(probe_cred.checkin_seq == 0ULL);

    uint8_t dummy_sha[32];
    uint8_t dummy_asgn[16];
    memset(dummy_sha, 0x33, sizeof(dummy_sha));
    memset(dummy_asgn, 0x77, sizeof(dummy_asgn));

    /* 2a. HMAC-SHA256-128 tag bit-flip (seq = 1) */
    g_mock_post_status = 200U;
    g_mock_tci1_resp_len = build_tci1_frame(
        g_mock_tci1_resp, init_tok, dev_id, 1ULL, TOOB_TCI1_HDR_SIZE, TOOB_TCI1_SLOT_APP, 0U,
        6U, 100U, 640U, dummy_sha, dummy_asgn, "/v1/blobs/fw.tbm1", NULL, NULL, 0U);
    g_mock_tci1_resp[g_mock_tci1_resp_len - 1U] ^= 0x01U;
    assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_ERR_VERIFY);
    assert(g_post_calls == 1U && g_get_calls == 0U);

    /* Validate canonical 152B TDR1 POST body & headers sent by os_client on request #1! */
    assert(strcmp(g_last_ctype_hdr, "Content-Type: application/octet-stream\r\n") == 0);
    assert(strcmp(g_last_seq_hdr, "X-Toob-Seq: 1\r\n") == 0);
    assert(g_last_post_body_len == TOOB_TDR1_MAX_SIZE);
    assert(toob_wire_get_le32(&g_last_post_body[0]) == TOOB_TDR1_MAGIC);
    assert(toob_wire_get_le64(&g_last_post_body[32]) == 1ULL);
    assert(toob_wire_get_le32(&g_last_post_body[40]) == 5U);
    assert(toob_wire_get_le32(&g_last_post_body[44]) == 77U);
    assert(toob_wire_get_le32(&g_last_post_body[48]) == 5U);
    assert(toob_wire_get_le32(&g_last_post_body[52]) == 2U);
    uint32_t post_crc = toob_wire_get_le32(&g_last_post_body[148]);
    assert(toob_lib_crc32(g_last_post_body, 148U) == post_crc);

    /* 2b. Replayed seq_echo mismatch (seq = 2 sent, frame echoes 1) -> TOOB_ERR_VERIFY */
    g_mock_tci1_resp_len = build_tci1_frame(
        g_mock_tci1_resp, init_tok, dev_id, 1ULL, TOOB_TCI1_HDR_SIZE, TOOB_TCI1_SLOT_APP, 0U,
        6U, 100U, 640U, dummy_sha, dummy_asgn, "/v1/blobs/fw.tbm1", NULL, NULL, 0U);
    assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_ERR_VERIFY);
    assert(g_get_calls == 0U);

    /* 2c. Closed RFC-3986 DFA rejects scheme, dot-traversal, percent-encoding, and CRLF smuggling (seq = 3..6) */
    const char *bad_paths[4] = {
        "http://evil.local/fw.bin",
        "/v1/../fw.bin",
        "/v1/fw%2fbin",
        "/v1/fw\r\nHost:evil"
    };
    for (uint32_t i = 0U; i < 4U; i++) {
        uint64_t expected_seq = 3ULL + i;
        g_mock_tci1_resp_len = build_tci1_frame(
            g_mock_tci1_resp, init_tok, dev_id, expected_seq, TOOB_TCI1_HDR_SIZE, TOOB_TCI1_SLOT_APP, 0U,
            6U, 100U, 640U, dummy_sha, dummy_asgn, bad_paths[i], NULL, NULL, 0U);
        assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_ERR_VERIFY);
        assert(g_get_calls == 0U);
    }

    /* 2d. Unknown flag bit (seq = 7) */
    g_mock_tci1_resp_len = build_tci1_frame(
        g_mock_tci1_resp, init_tok, dev_id, 7ULL, TOOB_TCI1_HDR_SIZE, TOOB_TCI1_SLOT_APP, 0x0080U,
        6U, 100U, 640U, dummy_sha, dummy_asgn, "/v1/blobs/fw.tbm1", NULL, NULL, 0U);
    assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_ERR_VERIFY);
    assert(g_get_calls == 0U);

    /* 3. Control-only TCI1 frame (total_size == 0, seq = 8): XOR Token Rotation + TCC1 Cloud Command!
     *    TCI1-08: Staging a TCC1 cloud command signals TOOB_ERR_REQUIRES_RESET for immediate Stage-1 execution! */
    uint8_t rotated_tok[32];
    memset(rotated_tok, 0x5C, sizeof(rotated_tok));

    uint8_t tcc1_env[128];
    memset(tcc1_env, 0, sizeof(tcc1_env));
    toob_cloud_cmd_hdr_t cmd_hdr;
    memset(&cmd_hdr, 0, sizeof(cmd_hdr));
    cmd_hdr.magic = TOOB_CLOUD_CMD_MAGIC;
    cmd_hdr.version = TOOB_CLOUD_CMD_VERSION;
    cmd_hdr.command = 2U;
    cmd_hdr.counter_min = 9U;
    cmd_hdr.issued_at = 1700001234U;
    cmd_hdr.params_len = 0U;
    cmd_hdr.total_len = sizeof(tcc1_env);
    memset(cmd_hdr.device_id, 0x42, 32U);
    cmd_hdr.crc32 = toob_lib_crc32((const uint8_t *)&cmd_hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);
    memcpy(tcc1_env, &cmd_hdr, sizeof(cmd_hdr));
    memset(tcc1_env + 64U, 0xDD, 64U);

    g_mock_tci1_resp_len = build_tci1_frame(
        g_mock_tci1_resp, init_tok, dev_id, 8ULL, TOOB_TCI1_HDR_SIZE, 0U, 0U,
        0U, 0U, 0U, NULL, NULL, NULL, rotated_tok, tcc1_env, (uint16_t)sizeof(tcc1_env));
    assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_ERR_REQUIRES_RESET);
    assert(g_get_calls == 0U);
    assert(memcmp(&g_flash[CHIP_CLOUD_CMD_SLOT_ABS_ADDR], tcc1_env, sizeof(tcc1_env)) == 0);
    toob_device_cred_t after_ctrl;
    assert(toob_cred_load(&after_ctrl) == TOOB_OK);
    assert(memcmp(after_ctrl.device_token, rotated_tok, 32U) == 0);
    assert(after_ctrl.checkin_seq == 8ULL);

    /* 4. TCI1-04 Pre-Write HTTP Status Gate: 404 error body MUST write ZERO bytes to Staging Flash! (seq = 9) */
    memset(g_mock_blob, 0xA5, 640U);
    toob_wire_put_le32(&g_mock_blob[0], 0x314D4254U); /* "TBM1" */
    g_mock_blob_len = 640U;
    uint8_t blob_sha[32];
    compute_sha256(g_mock_blob, g_mock_blob_len, blob_sha);

    g_flash_write_calls = 0U;
    g_mock_get_status = 404U;
    g_mock_tci1_resp_len = build_tci1_frame(
        g_mock_tci1_resp, rotated_tok, dev_id, 9ULL, TOOB_TCI1_HDR_SIZE, TOOB_TCI1_SLOT_APP, 0U,
        5U, 78U, (uint32_t)g_mock_blob_len, blob_sha, dummy_asgn, "/v1/blobs/app_v5_b78.tbm1", NULL, NULL, 0U);
    assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_ERR_NOT_FOUND);
    assert(g_get_calls == 1U);
    assert(g_flash_write_calls == 0U); /* Zero error-body bytes hit flash! */

    /* 5. TCI1-01 Stage 1 Slot SVN Independence (target_slot == 3, remote_svn = 3 > installed_stage1_svn = 2,
     *    even though current_svn == 5!) + Forward-compatible TCI1 header_size == 96! (seq = 10) */
    g_mock_get_status = 200U;
    g_mock_tci1_resp_len = build_tci1_frame(
        g_mock_tci1_resp, rotated_tok, dev_id, 10ULL, 96U, TOOB_TCI1_SLOT_STAGE1, 0U,
        3U, 200U, (uint32_t)g_mock_blob_len, blob_sha, dummy_asgn, "/v1/blobs/s1_v3.tbm1?ch=prod&v=3", NULL, NULL, 0U);
    assert(toob_network_trigger_ota("http://ota.toob.local") == TOOB_OK);
    assert(g_get_calls == 2U);
    assert(g_last_get_range == 0U);
    assert(strcmp(g_last_get_url, "http://ota.toob.local/v1/blobs/s1_v3.tbm1?ch=prod&v=3") == 0);
    assert(strstr(g_last_auth_hdr, "5c5c5c5c") != NULL);
    assert(strcmp(g_last_seq_hdr, "X-Toob-Seq: 10\r\n") == 0);
    assert(memcmp(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR], g_mock_blob, g_mock_blob_len) == 0);

    printf("=========================================================\n");
    printf("   ALL OS_CLIENT TDR1 / TCI1 CONFORMANCE TESTS PASSED!\n");
    printf("=========================================================\n");
    return 0;
}
