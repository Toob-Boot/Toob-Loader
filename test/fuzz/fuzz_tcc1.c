#include "fuzz_common.h"

#include "boot_cloud_cmd.h"
#include "boot_crc32.h"
#include "boot_identity.h"
#include "boot_journal.h"
#include "boot_rstore.h"
#include "monocypher-ed25519.h"

static uint8_t s_tcc_buf[TOOB_CLOUD_CMD_MAX_SIZE + 64U] __attribute__((aligned(8)));
static uint8_t s_signed_buf[TOOB_CLOUD_CMD_MAX_SIZE] __attribute__((aligned(8)));

static void setup_tcc1_environment(const boot_platform_t *plat, uint32_t otp_ctr, uint8_t dslc,
                                   uint32_t kdm_seq) {
    fuzz_keystore_set_dslc(dslc);
    fuzz_keystore_set_monotonic(otp_ctr);
    fuzz_keystore_set_key(0U, g_fuzz_root_pk, true);
    fuzz_keystore_set_key(1U, g_fuzz_cloud_pk, true);

    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        if (boot_journal_init(plat) == BOOT_OK && kdm_seq > 0U) {
            wal_tmr_payload_t tmr;
            if (boot_journal_get_tmr(plat, &tmr) == BOOT_OK) {
                tmr.kdm_seq_floor = kdm_seq;
                tmr.last_accepted_issued_at = 1000U;
                (void)boot_journal_update_tmr(plat, &tmr);
            }

            toob_kdm_t kdm;
            memset(&kdm, 0, sizeof(kdm));
            kdm.sequence_number = kdm_seq;
            memcpy(kdm.new_cloud_pubkey, g_fuzz_cloud_pk, 32U);
            crypto_ed25519_sign(kdm.signature_ed25519, g_fuzz_root_sk,
                                (const uint8_t *)(const void *)&kdm,
                                offsetof(toob_kdm_t, signature_ed25519));

            static const uint32_t kdm_addrs[3] = TOOB_KDM_SLOT_ADDRS;
            static const size_t kdm_sizes[3] = TOOB_KDM_SLOT_SIZES;
            const boot_rstore_desc_t kdm_desc = {
                .slot_addrs = kdm_addrs,
                .slot_sizes = kdm_sizes,
                .slot_count = 3U,
                .record_size = sizeof(toob_kdm_t),
                .magic = 0x4B444D51U
            };
            (void)boot_rstore_write(plat, &kdm_desc, &kdm);
        }
    }
    g_fuzz_trap_active = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    size_t copy_len = (size > sizeof(s_tcc_buf)) ? sizeof(s_tcc_buf) : size;
    fuzz_platform_reset(0x54434331ULL ^ (uint64_t)size);
    const boot_platform_t *plat = fuzz_platform_get();

    uint32_t init_ctr = (copy_len > 0U) ? (uint32_t)(data[0] & 0x0FU) : 0U;
    uint32_t kdm_seq = (copy_len > 1U) ? (uint32_t)((data[1] & 0x07U) + 1U) : 1U;
    setup_tcc1_environment(plat, init_ctr, 0x01U, kdm_seq);

    memset(s_tcc_buf, 0, sizeof(s_tcc_buf));
    if (copy_len > 0U) {
        memcpy(s_tcc_buf, data, copy_len);
    }

    /* 1. Untrusted raw buffer evaluation (must not burn OTP counter on reject). */
    toob_cloud_cmd_t out_cmd = TOOB_CMD_NOP;
    uint32_t pre_ctr = fuzz_keystore_get_monotonic();
    boot_status_t buf_st = BOOT_ERR_VERIFY;

    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        buf_st = boot_cloud_cmd_evaluate_buffer(plat, s_tcc_buf, copy_len, crypto_arena, &out_cmd);
    }
    g_fuzz_trap_active = 0;

    if (buf_st != BOOT_OK && fuzz_keystore_get_monotonic() != pre_ctr) {
        abort();
    }

    /* 2. Flash-slot TOCTOU evaluation path. */
    fuzz_flash_fill_erased(CHIP_CLOUD_CMD_SLOT_ABS_ADDR, CHIP_CLOUD_CMD_SLOT_SIZE);
    if (copy_len > 0U) {
        size_t flash_len = (copy_len > CHIP_CLOUD_CMD_SLOT_SIZE) ? CHIP_CLOUD_CMD_SLOT_SIZE : copy_len;
        fuzz_flash_write_raw(CHIP_CLOUD_CMD_SLOT_ABS_ADDR, s_tcc_buf, flash_len);
    }
    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        (void)boot_cloud_cmd_evaluate_flash(plat, crypto_arena, &out_cmd);
    }
    g_fuzz_trap_active = 0;

    /* 3. Authenticated post-signature path: fix header CRC and sign with test cloud key
     *    using real Monocypher Ed25519 so command dispatch, counter burn caps, and
     *    KDM floor boundaries are exercised under real signature verification. */
    if (copy_len >= TOOB_CLOUD_CMD_MIN_SIZE && copy_len <= TOOB_CLOUD_CMD_MAX_SIZE) {
        size_t aligned_len = copy_len & ~((size_t)(TOOB_CLOUD_CMD_ALIGN - 1U));
        if (aligned_len >= TOOB_CLOUD_CMD_MIN_SIZE) {
            memcpy(s_signed_buf, s_tcc_buf, aligned_len);
            toob_cloud_cmd_hdr_t *hdr = (toob_cloud_cmd_hdr_t *)(void *)s_signed_buf;
            hdr->magic = TOOB_CLOUD_CMD_MAGIC;
            hdr->version = TOOB_CLOUD_CMD_VERSION;
            hdr->flags = 0U;
            hdr->_reserved = 0U;
            hdr->total_len = (uint32_t)aligned_len;
            hdr->params_len = (uint32_t)(aligned_len - TOOB_CLOUD_CMD_MIN_SIZE);
            if ((data[0] & 0x10U) != 0U) {
                (void)boot_derive_device_id(plat, hdr->device_id);
            }
            hdr->crc32 = compute_boot_crc32((const uint8_t *)hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);
            size_t payload_sz = aligned_len - TOOB_CLOUD_CMD_SIG_SIZE;
            crypto_ed25519_sign(&s_signed_buf[payload_sz], g_fuzz_cloud_sk, s_signed_buf,
                                payload_sz);

            g_fuzz_trap_active = 1;
            if (setjmp(g_fuzz_trap_jmp) == 0) {
                (void)boot_cloud_cmd_evaluate_buffer(plat, s_signed_buf, aligned_len, crypto_arena,
                                                     &out_cmd);
            }
            g_fuzz_trap_active = 0;
        }
    }

    boot_journal_zeroize_secrets();
    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("tcc1")
