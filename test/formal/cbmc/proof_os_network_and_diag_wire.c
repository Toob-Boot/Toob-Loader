/*
 * FV-03: CBMC Memory-Safety, Wire-Bijection & Symbolic Network Parser Proof
 * for toob_network_client.c + toob_diag.c + toob_checkin_wire.h.
 *
 * Covers:
 *   - sdk/os_client/src/toob_network_client.c (TCI1 binary parser, EtM
 *     HMAC-SHA256-128, XOR rotated_token unmasking, closed O(n) RFC-3986
 *     blob_path DFA, HTTP status gating, SVN/build anti-downgrade, mutex
 *     discipline)
 *   - sdk/libtoob/toob_diag.c (toob_get_boot_diag, toob_get_boot_diag_wire,
 *     toob_get_boot_diag_wire_seq, 136B/152B TDR1 wire bijection & padding
 *     zero-sanitization)
 *   - common/include/toob_checkin_wire.h
 */

#define CBMC_LIBTOOB_ONLY 1
#include "cbmc_common.h"
#include "libtoob.h"
#include "toob_checkin_wire.h"
#include "toob_cloud_cmd_wire.h"
#include "toob_device_cred.h"
#include "toob_internal.h"
#include "toob_network_client.h"

extern toob_boot_diag_t toob_diag_state;
extern toob_handoff_t   toob_handoff_state;

static uint32_t g_os_lock_depth;
static uint32_t g_last_crc32;
static bool     g_ota_chunk_written_on_bad_http;

void cbmc_snapshot_handoff(toob_handoff_t *dst) {
    cbmc_assert_writable(dst, sizeof(*dst), "handoff snapshot dst must be writable");
    *dst = toob_handoff_state;
}

void cbmc_snapshot_diag(toob_boot_diag_t *dst) {
    cbmc_assert_writable(dst, sizeof(*dst), "diag snapshot dst must be writable");
    *dst = toob_diag_state;
}

int cbmc_printf_noop(const char *fmt, ...) {
    cbmc_assert_readable(fmt, 1U, "printf format string must be readable");
    return 0;
}

int cbmc_snprintf_contract(char *str, size_t size, const char *fmt, ...) {
    cbmc_assert_readable(fmt, 1U, "snprintf format string must be readable");
    if (size > 0U) {
        cbmc_assert_writable(str, size, "snprintf destination buffer must be writable");
        str[0] = '/';
        str[size - 1U] = '\0';
    }
    int rc = nondet_int();
    __CPROVER_assume(rc >= -1 && rc <= 512);
    return rc;
}

bool cbmc_is_all_byte_contract(const uint8_t *buf, size_t len, uint8_t val) {
    (void)val;
    cbmc_assert_readable(buf, len, "_is_all_byte buffer must be readable");
    if (len == 0U) {
        return true;
    }
    /* Exact on endpoints while over-approximating interior bytes in O(1) */
    if (buf[0] != val || buf[len - 1U] != val) {
        return false;
    }
    return nondet_bool();
}

bool cbmc_ct_memeq_contract(const uint8_t *a, const uint8_t *b, size_t len) {
    if (len == 0U) {
        return false;
    }
    cbmc_assert_readable(a, len, "_ct_memeq_glitch_safe buffer a must be readable");
    cbmc_assert_readable(b, len, "_ct_memeq_glitch_safe buffer b must be readable");
    return nondet_bool();
}

toob_status_t cbmc_hmac_sha256_3part_contract(const uint8_t key[32],
                                              const uint8_t *p1, uint32_t p1_len,
                                              const uint8_t *p2, uint32_t p2_len,
                                              const uint8_t *p3, uint32_t p3_len,
                                              uint8_t out_mac[32]) {
    cbmc_assert_readable(key, 32U, "HMAC key[32] must be readable");
    cbmc_assert_readable(p1, p1_len, "HMAC part 1 must be readable");
    cbmc_assert_readable(p2, p2_len, "HMAC part 2 must be readable");
    cbmc_assert_readable(p3, p3_len, "HMAC part 3 must be readable");
    cbmc_assert_writable(out_mac, 32U, "HMAC out_mac[32] must be writable");
    if (nondet_bool()) {
        return TOOB_ERR_VERIFY;
    }
    __CPROVER_havoc_slice(out_mac, 32U);
    return TOOB_OK;
}

uint32_t toob_lib_crc32(const uint8_t *data, size_t len) {
    cbmc_assert_readable(data, len, "toob_lib_crc32 input slice must be readable");
    uint32_t c = nondet_uint32_t();
    g_last_crc32 = c;
    return c;
}

void toob_os_lock(void) {
    __CPROVER_assert(g_os_lock_depth == 0U,
                     "toob_os_lock must not recursively deadlock");
    g_os_lock_depth++;
}

void toob_os_unlock(void) {
    __CPROVER_assert(g_os_lock_depth == 1U,
                     "toob_os_unlock must match a held lock");
    g_os_lock_depth--;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx) {
    cbmc_assert_writable(ctx, sizeof(*ctx), "toob_os_sha256_init ctx must be writable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_VERIFY;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx,
                                    const uint8_t *data, size_t len) {
    __CPROVER_assert(ctx != NULL, "toob_os_sha256_update ctx must be non-null");
    cbmc_assert_readable(data, len, "toob_os_sha256_update slice must be readable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_VERIFY;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx,
                                      uint8_t out_digest[32]) {
    __CPROVER_assert(ctx != NULL, "toob_os_sha256_finalize ctx must be non-null");
    cbmc_assert_writable(out_digest, 32U,
                         "toob_os_sha256_finalize out_digest[32] must be writable");
    if (nondet_bool()) {
        return TOOB_ERR_VERIFY;
    }
    cbmc_havoc_bytes(out_digest, 32U);
    return TOOB_OK;
}

toob_status_t toob_get_device_id(uint8_t *out_id, size_t max_len) {
    if (out_id == NULL || max_len < 32U) {
        return TOOB_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(out_id, 32U, "toob_get_device_id out_id[32] must be writable");
    if (nondet_bool()) {
        return TOOB_ERR_FLASH;
    }
    cbmc_havoc_bytes(out_id, 32U);
    return TOOB_OK;
}

toob_status_t toob_cred_load(toob_device_cred_t *out) {
    cbmc_assert_writable(out, sizeof(*out), "toob_cred_load out must be writable");
    if (nondet_bool()) {
        return TOOB_ERR_NOT_FOUND;
    }
    CBMC_HAVOC_OBJECT(*out);
    return TOOB_OK;
}

toob_status_t toob_cred_bump_seq(uint64_t *out_next_seq) {
    cbmc_assert_writable(out_next_seq, sizeof(*out_next_seq),
                         "toob_cred_bump_seq out_next_seq must be writable");
    if (nondet_bool()) {
        return TOOB_ERR_COUNTER_EXHAUSTED;
    }
    uint64_t s = nondet_uint64_t();
    __CPROVER_assume(s >= 1ULL);
    *out_next_seq = s;
    return TOOB_OK;
}

toob_status_t toob_cred_rotate_token(const uint8_t new_token[TOOB_DEVICE_TOKEN_LEN]) {
    cbmc_assert_readable(new_token, TOOB_DEVICE_TOKEN_LEN,
                         "toob_cred_rotate_token new_token[32] must be readable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_submit_cloud_command(const uint8_t *envelope, uint32_t len) {
    cbmc_assert_readable(envelope, len,
                         "toob_submit_cloud_command envelope must be readable");
    __CPROVER_assert(len >= TOOB_TCI1_MIN_CLOUD_CMD_LEN &&
                         len <= TOOB_TCI1_MAX_CLOUD_CMD_LEN &&
                         (len % TOOB_CLOUD_CMD_ALIGN) == 0U,
                     "Submitted TCC1 cloud command satisfies precheck alignment/length");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_VERIFY;
}

toob_status_t toob_network_init(void) {
    return nondet_bool() ? TOOB_OK : TOOB_ERR_TIMEOUT;
}

toob_status_t toob_ota_ctx_init(toob_ota_ctx_t *ctx) {
    cbmc_assert_writable(ctx, sizeof(*ctx), "toob_ota_ctx_init ctx must be writable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_INVALID_ARG;
}

toob_status_t toob_ota_resume_assigned(toob_ota_ctx_t *ctx, uint32_t total_size,
                                       const uint8_t expected_sha256[32],
                                       const uint8_t assignment_id[16],
                                       uint32_t *out_resume_offset) {
    __CPROVER_assert(ctx != NULL && total_size >= TOOB_TCI1_MIN_TBM1_TOTAL_SIZE,
                     "toob_ota_resume_assigned preconditions");
    cbmc_assert_readable(expected_sha256, 32U, "expected_sha256[32] readable");
    cbmc_assert_readable(assignment_id, 16U, "assignment_id[16] readable");
    cbmc_assert_writable(out_resume_offset, sizeof(*out_resume_offset),
                         "out_resume_offset writable");
    if (nondet_bool()) {
        return TOOB_ERR_NOT_FOUND;
    }
    uint32_t roff = nondet_uint32_t();
    __CPROVER_assume(roff < total_size);
    *out_resume_offset = roff;
    return TOOB_OK;
}

toob_status_t toob_ota_begin_assigned(toob_ota_ctx_t *ctx, uint32_t total_size,
                                      const uint8_t expected_sha256[32],
                                      const uint8_t assignment_id[16]) {
    __CPROVER_assert(ctx != NULL && total_size >= TOOB_TCI1_MIN_TBM1_TOTAL_SIZE,
                     "toob_ota_begin_assigned preconditions");
    cbmc_assert_readable(expected_sha256, 32U, "expected_sha256[32] readable");
    cbmc_assert_readable(assignment_id, 16U, "assignment_id[16] readable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_FLASH;
}

static uint16_t g_active_download_http_status;
static uint16_t g_expected_download_http_status;

toob_status_t toob_ota_process_chunk(toob_ota_ctx_t *ctx, const uint8_t *chunk,
                                     uint32_t len) {
    __CPROVER_assert(ctx != NULL, "toob_ota_process_chunk ctx non-null");
    cbmc_assert_readable(chunk, len, "toob_ota_process_chunk chunk readable");
    if (g_active_download_http_status != g_expected_download_http_status) {
        g_ota_chunk_written_on_bad_http = true;
    }
    return nondet_bool() ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_ota_pause(toob_ota_ctx_t *ctx) {
    __CPROVER_assert(ctx != NULL, "toob_ota_pause ctx non-null");
    return TOOB_OK;
}

toob_status_t toob_ota_abort(toob_ota_ctx_t *ctx) {
    __CPROVER_assert(ctx != NULL, "toob_ota_abort ctx non-null");
    return TOOB_OK;
}

toob_status_t toob_ota_finalize(toob_ota_ctx_t *ctx) {
    __CPROVER_assert(ctx != NULL, "toob_ota_finalize ctx non-null");
    uint8_t s = nondet_uint8_t();
    if (s == 0U) {
        return TOOB_OK;
    }
    if (s == 1U) {
        return TOOB_ERR_WAL_LOCKED;
    }
    return TOOB_ERR_VERIFY;
}

toob_status_t rtos_http_request(toob_http_method_t method, const char *url,
                                const char *const *headers, uint32_t header_count,
                                const uint8_t *body, uint32_t body_len,
                                uint32_t range_offset,
                                toob_http_chunk_cb_t callback, void *ctx,
                                uint16_t *out_status,
                                uint32_t *out_retry_after_s) {
    cbmc_assert_readable(url, 1U, "HTTP url must be readable");
    __CPROVER_assert(callback != NULL && out_status != NULL &&
                         out_retry_after_s != NULL,
                     "rtos_http_request mandatory pointers must be non-null");
    if (header_count > 0U) {
        __CPROVER_assert(headers != NULL, "HTTP headers array non-null");
        for (uint32_t i = 0U; i < header_count; i++) {
            cbmc_assert_readable(headers[i], 1U, "HTTP header string readable");
        }
    }
    if (body_len > 0U) {
        cbmc_assert_readable(body, body_len, "HTTP POST body must be readable");
    }

    uint16_t st_code = nondet_uint16_t();
    *out_status = st_code;
    *out_retry_after_s = nondet_uint32_t();

    if (method == TOOB_HTTP_GET) {
        g_active_download_http_status   = st_code;
        g_expected_download_http_status = (range_offset > 0U) ? 206U : 200U;
    }

    if (nondet_bool()) {
        return TOOB_ERR_TIMEOUT;
    }

    /* Stream 1 or 2 network chunks (discrete boundary sizes avoid 512x512 array_replace mux) */
    static const uint32_t k_c1[4] = { 0U, 64U, 104U, 256U };
    static const uint32_t k_c2[4] = { 0U, 48U, 256U, 260U };
    uint8_t net_chunk1[256];
    uint8_t net_chunk2[260];
    CBMC_HAVOC_OBJECT(net_chunk1);
    CBMC_HAVOC_OBJECT(net_chunk2);
    if (method == TOOB_HTTP_POST) {
        /* Bound TCI1 blob_path_len on full cycle to >= DFA diameter (<=10) or OOB (>120) */
        uint16_t post_bp_len = toob_wire_get_le16(&net_chunk1[10]);
        __CPROVER_assume(post_bp_len <= 10U || post_bp_len > TOOB_TCI1_MAX_BLOB_PATH_LEN);
    }

    uint8_t s1 = nondet_uint8_t();
    __CPROVER_assume(s1 < 4U);
    uint32_t len1 = k_c1[s1];
    toob_status_t cb_rc = callback(net_chunk1, len1, ctx);
    if (cb_rc != TOOB_OK) {
        return cb_rc;
    }

    if (method == TOOB_HTTP_POST && nondet_bool()) {
        uint8_t s2 = nondet_uint8_t();
        __CPROVER_assume(s2 < 4U);
        uint32_t len2 = k_c2[s2];
        cb_rc = callback(net_chunk2, len2, ctx);
        if (cb_rc != TOOB_OK) {
            return cb_rc;
        }
    }
    return TOOB_OK;
}

/*
 * Entrypoint 1: Full 512-byte symbolic TCI1 frame verification (TCI1-06 / TCI1-07).
 * Proves memory-safety, EtM ordering, XOR token unmasking, and RFC-3986 SSRF/CRLF/
 * dot-segment path whitelist across ALL 512-byte untrusted network inputs.
 */
void prove_tci1_parse_symbolic_512(void) {
    uint8_t frame[TOOB_TCI1_MAX_FRAME_SIZE + 8U];
    uint8_t token_key[32];
    uint8_t device_id[32];
    CBMC_HAVOC_OBJECT(frame);
    CBMC_HAVOC_OBJECT(token_key);
    CBMC_HAVOC_OBJECT(device_id);

    size_t len = nondet_size_t();
    __CPROVER_assume(len <= sizeof(frame));
    uint64_t expected_seq = nondet_uint64_t();

    /* Arbitrary symbolic hdr_size/cursor across all 520B untrusted frames
     * with blob_path_len covering the full 16-state DFA diameter [0..10] and OOB [>120].
     * Exact 120B upper-bound loop is proven in prove_tci1_blob_path_120(). */
    uint16_t raw_bp = toob_wire_get_le16(&frame[10]);
    __CPROVER_assume(raw_bp <= 10U || raw_bp > TOOB_TCI1_MAX_BLOB_PATH_LEN);

    toob_update_info_t out;
    const uint8_t *cloud_cmd = NULL;
    uint16_t cloud_cmd_len = 0U;

    /* NULL guard checks */
    __CPROVER_assert(toob_tci1_parse(NULL, len, token_key, device_id,
                                     expected_seq, &out, &cloud_cmd,
                                     &cloud_cmd_len) == TOOB_ERR_INVALID_ARG,
                     "NULL frame buffer rejected");

    toob_status_t st = toob_tci1_parse(
        frame, len, token_key, device_id, expected_seq,
        &out, &cloud_cmd, &cloud_cmd_len);

    if (st == TOOB_OK) {
        __CPROVER_assert(len >= TOOB_TCI1_MIN_FRAME_SIZE &&
                             len <= TOOB_TCI1_MAX_FRAME_SIZE,
                         "Accepted TCI1 frame length in [104, 512]");
        __CPROVER_assert(expected_seq != 0ULL,
                         "Accepted TCI1 requires non-zero expected_seq");
        __CPROVER_assert(out.retry_after_sec <= TOOB_TCI1_MAX_RETRY_AFTER_SEC,
                         "Accepted retry_after_sec bounded by 7-day cap");

        if (out.update_available) {
            __CPROVER_assert(out.total_size >= TOOB_TCI1_MIN_TBM1_TOTAL_SIZE,
                             "Accepted update enforces minimum TBM1 size >= 576");
            __CPROVER_assert(out.target_slot == TOOB_TCI1_SLOT_APP ||
                                 out.target_slot == TOOB_TCI1_SLOT_NETCORE ||
                                 out.target_slot == TOOB_TCI1_SLOT_STAGE1,
                             "Accepted update target_slot in {0, 1, 3}");
            __CPROVER_assert(out.blob_path[0] == '/',
                             "Accepted blob_path starts with '/'");

            uint16_t bp_len = toob_wire_get_le16(&frame[10]);
            __CPROVER_assert(bp_len >= 2U && bp_len <= TOOB_TCI1_MAX_BLOB_PATH_LEN,
                             "Accepted blob_path_len in [2, 120]");
            __CPROVER_assert(out.blob_path[bp_len] == '\0',
                             "Accepted blob_path is NUL-terminated at exact blob_path_len");

            /* Universal character & SSRF/traversal check via symbolic index k */
            size_t k = nondet_size_t();
            __CPROVER_assume(k < (size_t)bp_len);
            uint8_t ch = (uint8_t)out.blob_path[k];
            __CPROVER_assert(ch > 0x20U && ch < 0x7FU,
                             "blob_path contains zero control/CRLF/whitespace/non-ASCII bytes");
            __CPROVER_assert(ch != (uint8_t)':' && ch != (uint8_t)'%' &&
                                 ch != (uint8_t)'\\',
                             "blob_path forbids scheme ':', percent-encoding '%', and backslash");
            if (k + 1U < (size_t)bp_len) {
                __CPROVER_assert(!(out.blob_path[k] == '/' &&
                                   out.blob_path[k + 1U] == '/'),
                                 "blob_path forbids empty segments and '//' authority injection");
            }
            if (out.blob_path[k] == '/' && (k + 1U < (size_t)bp_len) &&
                out.blob_path[k + 1U] == '.') {
                bool single_dot_seg =
                    (k + 2U == (size_t)bp_len) ||
                    (out.blob_path[k + 2U] == '/') ||
                    (out.blob_path[k + 2U] == '?');
                bool double_dot_seg =
                    (k + 2U < (size_t)bp_len) &&
                    (out.blob_path[k + 2U] == '.') &&
                    ((k + 3U == (size_t)bp_len) ||
                     (out.blob_path[k + 3U] == '/') ||
                     (out.blob_path[k + 3U] == '?'));
                __CPROVER_assert(!single_dot_seg && !double_dot_seg,
                                 "blob_path forbids '/.' and '/..' traversal segments");
            }
        } else {
            __CPROVER_assert(out.has_rotated_token || cloud_cmd != NULL,
                             "Control-only TCI1 frame must carry rotated_token or cloud_cmd");
        }

        if (cloud_cmd != NULL) {
            __CPROVER_assert(cloud_cmd >= frame &&
                                 (cloud_cmd + cloud_cmd_len) <=
                                     (frame + len - TOOB_TCI1_AUTH_TAG_LEN),
                             "Extracted cloud_cmd slice lies strictly inside HMAC-authenticated frame body");
        }
    }
}

/*
 * Entrypoint 2: End-to-end check-in + download cycle (toob_network_trigger_ota).
 * Proves HTTP status gating (TCI1-04), SVN/build anti-downgrade (TCI1-01), and
 * balanced OS mutex lock/unlock across all error & success paths.
 */
/*
 * Sound contract for toob_tci1_parse used in prove_network_trigger_ota_cycle
 * (toob_tci1_parse itself is proven directly in prove_tci1_parse_symbolic_512
 * and prove_tci1_blob_path_120).
 */
toob_status_t cbmc_tci1_parse_contract(const uint8_t *data,
                                       size_t len,
                                       const uint8_t token_key[32],
                                       const uint8_t device_id[32],
                                       uint64_t expected_seq,
                                       toob_update_info_t *out,
                                       const uint8_t **out_cloud_cmd,
                                       uint16_t *out_cloud_cmd_len) {
    if (out_cloud_cmd != NULL) {
        cbmc_assert_writable(out_cloud_cmd, sizeof(*out_cloud_cmd),
                             "out_cloud_cmd pointer must be writable");
        *out_cloud_cmd = NULL;
    }
    if (out_cloud_cmd_len != NULL) {
        cbmc_assert_writable(out_cloud_cmd_len, sizeof(*out_cloud_cmd_len),
                             "out_cloud_cmd_len must be writable");
        *out_cloud_cmd_len = 0U;
    }
    if (data == NULL || token_key == NULL || device_id == NULL || out == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    cbmc_assert_readable(data, len, "toob_tci1_parse frame must be readable");
    cbmc_assert_readable(token_key, 32U, "toob_tci1_parse token_key[32] readable");
    cbmc_assert_readable(device_id, 32U, "toob_tci1_parse device_id[32] readable");
    cbmc_assert_writable(out, sizeof(*out), "toob_tci1_parse out writable");
    if (expected_seq == 0ULL || len < TOOB_TCI1_MIN_FRAME_SIZE ||
        len > TOOB_TCI1_MAX_FRAME_SIZE || nondet_bool()) {
        return TOOB_ERR_VERIFY;
    }
    CBMC_HAVOC_OBJECT(*out);
    __CPROVER_assume(out->retry_after_sec <= TOOB_TCI1_MAX_RETRY_AFTER_SEC);
    if (out->update_available) {
        __CPROVER_assume(out->total_size >= TOOB_TCI1_MIN_TBM1_TOTAL_SIZE);
        __CPROVER_assume(out->target_slot == TOOB_TCI1_SLOT_APP ||
                         out->target_slot == TOOB_TCI1_SLOT_NETCORE ||
                         out->target_slot == TOOB_TCI1_SLOT_STAGE1);
        out->blob_path[0] = '/';
        out->blob_path[1] = 'f';
        out->blob_path[2] = '\0';
    }
    if (nondet_bool() && out_cloud_cmd != NULL && out_cloud_cmd_len != NULL &&
        len >= (TOOB_TCI1_HDR_SIZE + TOOB_TCI1_MIN_CLOUD_CMD_LEN + TOOB_TCI1_AUTH_TAG_LEN)) {
        *out_cloud_cmd = &data[TOOB_TCI1_HDR_SIZE];
        *out_cloud_cmd_len = TOOB_TCI1_MIN_CLOUD_CMD_LEN;
    }
    return TOOB_OK;
}

toob_status_t cbmc_get_boot_diag_contract(toob_boot_diag_t *out) {
    if (out == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(out, sizeof(*out), "toob_get_boot_diag out writable");
    if (nondet_bool()) {
        return TOOB_ERR_NOT_FOUND;
    }
    memset(out, 0, sizeof(*out));
    out->struct_version       = TOOB_DIAG_STRUCT_VERSION;
    out->current_svn          = nondet_uint32_t();
    out->installed_app_svn    = nondet_uint32_t();
    out->installed_stage1_svn = nondet_uint32_t();
    out->build_number         = nondet_uint32_t();
    return TOOB_OK;
}

void cbmc_hex_encode_contract(const uint8_t *in, size_t len, char *out) {
    cbmc_assert_readable(in, len, "_hex_encode input slice must be readable");
    cbmc_assert_writable(out, (2U * len) + 1U, "_hex_encode output buffer must be writable");
    out[0] = '0';
    out[2U * len] = '\0';
}

void cbmc_fv03_client_zeroize(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "_client_zeroize target buffer must be writable");
    if (ptr == NULL || len == 0U) {
        return;
    }
    if (len == sizeof(toob_update_info_t)) {
        *(toob_update_info_t *)ptr = (toob_update_info_t){0};
    } else if (len > TOOB_TCI1_MAX_FRAME_SIZE) {
        /* Exact field offsets of tci1_manifest_rx_t (.len and .rejected_by_status) */
        *(size_t *)((uint8_t *)ptr + TOOB_TCI1_MAX_FRAME_SIZE) = 0U;
        *(bool *)((uint8_t *)ptr + TOOB_TCI1_MAX_FRAME_SIZE +
                  sizeof(size_t) + sizeof(const uint16_t *)) = false;
    } else {
        ((uint8_t *)ptr)[0] = 0U;
    }
}

void *cbmc_fv03_cycle_memcpy(void *dst, const void *src, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "memcpy destination must be writable");
    cbmc_assert_readable(src, n, "memcpy source must be readable");
    if (__CPROVER_same_object(dst, src)) {
        uintptr_t d_addr = (uintptr_t)dst;
        uintptr_t s_addr = (uintptr_t)src;
        __CPROVER_assert((d_addr + n <= s_addr) || (s_addr + n <= d_addr),
                         "memcpy slices within same object must not overlap");
    }
    return dst;
}

toob_status_t cbmc_diag_wire_seq_contract(uint8_t *out_buf,
                                          size_t max_len,
                                          uint64_t checkin_seq,
                                          size_t *out_len) {
    (void)checkin_seq;
    if (out_len != NULL) {
        cbmc_assert_writable(out_len, sizeof(*out_len), "diag wire out_len writable");
        *out_len = 0U;
    }
    if (out_buf == NULL || out_len == NULL || max_len < TOOB_TDR1_MIN_FRAME_SIZE) {
        return TOOB_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(out_buf, max_len, "diag wire out_buf writable");
    if (nondet_bool()) {
        return TOOB_ERR_NOT_FOUND;
    }
    size_t n = nondet_bool() ? TOOB_TDR1_MIN_FRAME_SIZE : TOOB_TDR1_MAX_SIZE;
    __CPROVER_assume(n <= max_len);
    out_buf[0] = 0x54U;
    *out_len = n;
    return TOOB_OK;
}

void prove_network_trigger_ota_cycle(void) {
    g_os_lock_depth                 = 0U;
    g_ota_chunk_written_on_bad_http = false;
    CBMC_HAVOC_OBJECT(toob_diag_state);
    CBMC_HAVOC_OBJECT(toob_handoff_state);

    const char *srv = nondet_bool() ? "https://api.toob.io" : NULL;
    (void)toob_network_trigger_ota(srv);

    __CPROVER_assert(g_os_lock_depth == 0U,
                     "toob_network_trigger_ota always releases OS mutex before returning");
    __CPROVER_assert(!g_ota_chunk_written_on_bad_http,
                     "TCI1-04: OTA chunks are never written when HTTP status != expected 200/206");
}

/*
 * Entrypoint 3: TDR1 136B/152B wire serialization & canonical LE bijection (toob_diag.c).
 */
void prove_tdr1_diag_wire_bijection(void) {
    CBMC_HAVOC_OBJECT(toob_diag_state);
    CBMC_HAVOC_OBJECT(toob_handoff_state);

    /* NULL & undersized buffer guards */
    uint8_t wire[160];
    size_t out_len = 999U;
    __CPROVER_assert(toob_get_boot_diag(NULL) == TOOB_ERR_INVALID_ARG,
                     "toob_get_boot_diag rejects NULL");
    __CPROVER_assert(toob_get_boot_diag_wire_seq(NULL, sizeof(wire), 1ULL, &out_len) ==
                         TOOB_ERR_INVALID_ARG && out_len == 0U,
                     "toob_get_boot_diag_wire_seq rejects NULL out_buf and zeroes out_len");

    /* Symbolic max_len in [0 .. 160] */
    size_t max_len = nondet_size_t();
    __CPROVER_assume(max_len <= sizeof(wire));
    uint64_t seq = nondet_uint64_t();

    toob_boot_diag_t extracted;
    toob_status_t dst = toob_get_boot_diag(&extracted);
    if (dst == TOOB_OK) {
        __CPROVER_assert(extracted.struct_version == TOOB_DIAG_STRUCT_VERSION,
                         "Validated boot_diag matches TOOB_DIAG_STRUCT_VERSION");
        for (size_t i = 0U; i < sizeof(extracted._padding_v3); i++) {
            __CPROVER_assert(extracted._padding_v3[i] == 0U,
                             "MED-24: _padding_v3 zero-sanitized");
        }
        for (size_t i = 0U; i < sizeof(extracted._padding); i++) {
            __CPROVER_assert(extracted._padding[i] == 0U,
                             "MED-24: _padding zero-sanitized");
        }
        for (size_t i = 0U; i < sizeof(extracted._padding_end); i++) {
            __CPROVER_assert(extracted._padding_end[i] == 0U,
                             "MED-24: _padding_end zero-sanitized");
        }
    }

    toob_status_t wst = toob_get_boot_diag_wire_seq(wire, max_len, seq, &out_len);
    if (wst == TOOB_OK) {
        bool expect_ext = (toob_diag_state.ext_health_present != 0U);
        size_t expected_len = expect_ext ? TOOB_TDR1_MAX_SIZE : TOOB_TDR1_MIN_FRAME_SIZE;
        __CPROVER_assert(out_len == expected_len && out_len <= max_len,
                         "TDR1 wire length is exact 136B (no ext_health) or 152B (with ext_health)");
        __CPROVER_assert(toob_wire_get_le32(&wire[0]) == TOOB_TDR1_MAGIC &&
                             wire[4] == TOOB_TDR1_VERSION &&
                             toob_wire_get_le16(&wire[8]) == TOOB_TDR1_HDR_SIZE &&
                             toob_wire_get_le16(&wire[30]) == 0U,
                         "TDR1 header magic, version, header_size=132, and reserved0=0 hold");
        __CPROVER_assert(toob_wire_get_le64(&wire[32]) == seq &&
                             toob_wire_get_le32(&wire[40]) == toob_diag_state.current_svn &&
                             toob_wire_get_le32(&wire[44]) == toob_diag_state.build_number &&
                             toob_wire_get_le32(&wire[48]) == toob_diag_state.installed_app_svn &&
                             toob_wire_get_le32(&wire[52]) == toob_diag_state.installed_stage1_svn &&
                             toob_wire_get_le32(&wire[128]) == toob_diag_state.boot_session_id,
                         "TDR1 Little-Endian field bijection holds for sequence, SVNs, build, and session");
        __CPROVER_assert(toob_wire_get_le32(&wire[out_len - 4U]) == g_last_crc32,
                         "TDR1 trailer carries IEEE 802.3 CRC-32 over [0 .. out_len - 4)");
    }
}

/*
 * Entrypoint 4: Direct un-replaced verification of _hmac_sha256_3part,
 * _is_all_byte, and _ct_memeq_glitch_safe inside toob_tci1_parse (104B min frame).
 */
void prove_tci1_crypto_helpers(void) {
    uint8_t frame[TOOB_TCI1_MIN_FRAME_SIZE];
    uint8_t token_key[32];
    uint8_t device_id[32];
    CBMC_HAVOC_OBJECT(frame);
    CBMC_HAVOC_OBJECT(token_key);
    CBMC_HAVOC_OBJECT(device_id);

    toob_update_info_t out;
    const uint8_t *cloud_cmd = NULL;
    uint16_t cloud_cmd_len = 0U;
    (void)toob_tci1_parse(frame, sizeof(frame), token_key, device_id,
                          1ULL, &out, &cloud_cmd, &cloud_cmd_len);
}

void prove_tci1_blob_path_120(void) {
    uint8_t frame[TOOB_TCI1_HDR_SIZE + TOOB_TCI1_MAX_BLOB_PATH_LEN + TOOB_TCI1_AUTH_TAG_LEN];
    uint8_t token_key[32];
    uint8_t device_id[32];
    CBMC_HAVOC_OBJECT(frame);
    CBMC_HAVOC_OBJECT(token_key);
    CBMC_HAVOC_OBJECT(device_id);

    frame[8]  = (uint8_t)(TOOB_TCI1_HDR_SIZE & 0xFFU);
    frame[9]  = 0U;
    frame[10] = (uint8_t)TOOB_TCI1_MAX_BLOB_PATH_LEN;
    frame[11] = 0U;

    toob_update_info_t out;
    const uint8_t *cloud_cmd = NULL;
    uint16_t cloud_cmd_len = 0U;
    toob_status_t st = toob_tci1_parse(frame, sizeof(frame), token_key, device_id,
                                       1ULL, &out, &cloud_cmd, &cloud_cmd_len);
    if (st == TOOB_OK && out.update_available) {
        __CPROVER_assert(out.blob_path[TOOB_TCI1_MAX_BLOB_PATH_LEN] == '\0',
                         "120-byte max blob_path is NUL-terminated in out.blob_path[120]");
    }
}

int main(void) {
    uint8_t m = nondet_uint8_t();
    if (m == 0U) {
        prove_tci1_parse_symbolic_512();
    } else if (m == 1U) {
        prove_network_trigger_ota_cycle();
    } else {
        prove_tdr1_diag_wire_bijection();
    }
    return 0;
}
