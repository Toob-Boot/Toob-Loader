#include "fuzz_common.h"

#include "boot_cloud_cmd.h"
#include "boot_cobs.h"
#include "boot_crc32.h"
#include "boot_identity.h"
#include "boot_journal.h"
#include "boot_panic.h"
#include "boot_rstore.h"
#include "monocypher-ed25519.h"

#define KDM_RSTORE_SLOT_COUNT 3U
#define KDM_RSTORE_MAGIC      0x4B444D51U

static uint8_t s_kdm_env[TOOB_CLOUD_CMD_MIN_SIZE + sizeof(toob_kdm_t)] __attribute__((aligned(8)));
static uint8_t s_cobs_work[512];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    fuzz_platform_reset(0x4B444D31ULL ^ (uint64_t)size);
    const boot_platform_t *plat = fuzz_platform_get();
    fuzz_keystore_set_dslc(0x01U);
    fuzz_keystore_set_monotonic(0U);
    fuzz_keystore_set_key(0U, g_fuzz_root_pk, true);
    fuzz_keystore_set_key(1U, NULL, false);

    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        (void)boot_journal_init(plat);
    }
    g_fuzz_trap_active = 0;

    static const uint32_t kdm_addrs[KDM_RSTORE_SLOT_COUNT] = TOOB_KDM_SLOT_ADDRS;
    static const size_t kdm_sizes[KDM_RSTORE_SLOT_COUNT] = TOOB_KDM_SLOT_SIZES;
    const boot_rstore_desc_t kdm_desc = {
        .slot_addrs = kdm_addrs,
        .slot_sizes = kdm_sizes,
        .slot_count = KDM_RSTORE_SLOT_COUNT,
        .record_size = sizeof(toob_kdm_t),
        .magic = KDM_RSTORE_MAGIC
    };

    /* 1. Populate the 3 KDM quorum flash slots directly from fuzz bytes to test
     *    torn headers, majority vote, CRC-32 validation, and bounded healing. */
    size_t slot_blob_sz = sizeof(boot_rstore_slot_header_t) + sizeof(toob_kdm_t);
    for (uint32_t i = 0U; i < KDM_RSTORE_SLOT_COUNT; i++) {
        fuzz_flash_fill_erased(kdm_addrs[i], kdm_sizes[i]);
        size_t off = (size_t)i * slot_blob_sz;
        if (off < size) {
            size_t avail = size - off;
            size_t wr = (avail > slot_blob_sz) ? slot_blob_sz : avail;
            fuzz_flash_write_raw(kdm_addrs[i], &data[off], wr);
        }
    }

    toob_kdm_t kdm_out;
    memset(&kdm_out, 0, sizeof(kdm_out));
    (void)boot_rstore_read(plat, &kdm_desc, &kdm_out);

    /* 2. Exercise ROTATE_KEY KDM floor & root-key signature path with fuzz KDM payload. */
    if (size >= sizeof(toob_kdm_t)) {
        memset(s_kdm_env, 0, sizeof(s_kdm_env));
        toob_cloud_cmd_hdr_t *hdr = (toob_cloud_cmd_hdr_t *)(void *)s_kdm_env;
        hdr->magic = TOOB_CLOUD_CMD_MAGIC;
        hdr->version = TOOB_CLOUD_CMD_VERSION;
        hdr->command = (uint8_t)TOOB_CMD_ROTATE_KEY;
        hdr->counter_min = 1U;
        hdr->issued_at = 2000U;
        hdr->params_len = (uint32_t)sizeof(toob_kdm_t);
        hdr->total_len = (uint32_t)sizeof(s_kdm_env);
        (void)boot_derive_device_id(plat, hdr->device_id);
        hdr->crc32 = compute_boot_crc32((const uint8_t *)hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);

        /* Seed a valid baseline KDM into quorum first so load_active_cloud_key succeeds. */
        toob_kdm_t base_kdm;
        memset(&base_kdm, 0, sizeof(base_kdm));
        base_kdm.sequence_number = 5U;
        memcpy(base_kdm.new_cloud_pubkey, g_fuzz_cloud_pk, 32U);
        crypto_ed25519_sign(base_kdm.signature_ed25519, g_fuzz_root_sk,
                            (const uint8_t *)(const void *)&base_kdm,
                            offsetof(toob_kdm_t, signature_ed25519));
        (void)boot_rstore_write(plat, &kdm_desc, &base_kdm);

        wal_tmr_payload_t tmr;
        if (boot_journal_get_tmr(plat, &tmr) == BOOT_OK) {
            tmr.kdm_seq_floor = 5U;
            (void)boot_journal_update_tmr(plat, &tmr);
        }

        toob_kdm_t cand_kdm;
        memcpy(&cand_kdm, data, sizeof(cand_kdm));
        if ((data[0] & 1U) != 0U) {
            crypto_ed25519_sign(cand_kdm.signature_ed25519, g_fuzz_root_sk,
                                (const uint8_t *)(const void *)&cand_kdm,
                                offsetof(toob_kdm_t, signature_ed25519));
        }
        memcpy(&s_kdm_env[TOOB_CLOUD_CMD_HDR_SIZE], &cand_kdm, sizeof(cand_kdm));
        size_t sig_off = sizeof(s_kdm_env) - TOOB_CLOUD_CMD_SIG_SIZE;
        crypto_ed25519_sign(&s_kdm_env[sig_off], g_fuzz_cloud_sk, s_kdm_env, sig_off);

        toob_cloud_cmd_t cmd_out = TOOB_CMD_NOP;
        g_fuzz_trap_active = 1;
        if (setjmp(g_fuzz_trap_jmp) == 0) {
            (void)boot_cloud_cmd_evaluate_buffer(plat, s_kdm_env, sizeof(s_kdm_env), crypto_arena,
                                                 &cmd_out);
        }
        g_fuzz_trap_active = 0;
    }

    /* 3. Exercise COBS-wrapped unlock / Stage 1.5 rescue auth envelope decoding. */
    if (size > 0U) {
        size_t clen = (size > sizeof(s_cobs_work)) ? sizeof(s_cobs_work) : size;
        memcpy(s_cobs_work, data, clen);
        size_t dec_len = 0U;
        if (boot_cobs_decode_in_place(s_cobs_work, clen, &dec_len) == BOOT_OK && dec_len > 0U) {
            if (dec_len == sizeof(stage15_auth_payload_t)) {
                uint32_t slot_id = 0U;
                uint32_t seq_id = 0U;
                memcpy(&slot_id, s_cobs_work + offsetof(stage15_auth_payload_t, slot_id),
                       sizeof(uint32_t));
                memcpy(&seq_id, s_cobs_work + offsetof(stage15_auth_payload_t, sequence_id),
                       sizeof(uint32_t));
                (void)slot_id;
                (void)seq_id;
                (void)plat->crypto->verify_signature(
                    s_cobs_work, offsetof(stage15_auth_payload_t, sig),
                    s_cobs_work + offsetof(stage15_auth_payload_t, sig), g_fuzz_root_pk);
            } else {
                toob_cloud_cmd_t unlock_cmd = TOOB_CMD_NOP;
                g_fuzz_trap_active = 1;
                if (setjmp(g_fuzz_trap_jmp) == 0) {
                    (void)boot_cloud_cmd_evaluate_buffer(plat, s_cobs_work, dec_len, crypto_arena,
                                                         &unlock_cmd);
                }
                g_fuzz_trap_active = 0;
            }
        }
    }

    boot_journal_zeroize_secrets();
    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("kdm")
