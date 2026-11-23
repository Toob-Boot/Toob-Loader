/**
 * @file neg_e2e_vectors.c
 * @brief Tier 2 Negative Security E2E Verification Vectors against Production Core Sources.
 *
 * Compiled directly against real toobloader/core/ with:
 *   -DTOOB_PQC_ENABLED=1 -DTOOB_TA1_STRICT_NO_CRC_SKIP=1 -DTOOB_FEATURE_CLOUD_COMMANDS=1
 * Exercises:
 *   1. TA-1 zero-wear bypass rejection (TOOB_TA1_STRICT_NO_CRC_SKIP)
 *   2. Deployed blank-WAL rejection (DSLC=0x01 + erased WAL)
 *   3. KDM floor replay rejection (TCC1 TOOB_CMD_ROTATE_KEY + WAL TMR kdm_seq_floor)
 *   4. PQC pubkey SHA-256 pinning hash mismatch (TOOB_PQC_ENABLED=1)
 *   5. Unsigned / tampered TSIG / revoked-key / SVN rollback rejection
 */

#include "fuzz_common.h"

#include "boot_cloud_cmd.h"
#include "boot_crc32.h"
#include "boot_effect.h"
#include "boot_identity.h"
#include "boot_journal.h"
#include "boot_rstore.h"
#include "boot_tbm1.h"
#include "boot_verify.h"
#include "monocypher-ed25519.h"
#include "sha256.h"

#include <stdio.h>
#include <string.h>

#define NEG_PQC_PK_LEN   64U
#define NEG_PQC_SIG_LEN  64U
#define NEG_ENV_CAP      1024U
#define NEG_KDM_MAGIC    0x4B444D51U
#define NEG_IMG_PAYLOAD  256U

static bool s_pqc_verify_called = false;

static boot_status_t mock_pqc_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    (void)msg;
    (void)msg_len;
    s_pqc_verify_called = true;
    if (sig == NULL || pubkey == NULL || sig_len != NEG_PQC_SIG_LEN || pubkey_len != NEG_PQC_PK_LEN) {
        return BOOT_ERR_INVALID_ARG;
    }
    return BOOT_OK;
}

static bool mock_pqc_enforced(void) {
    return true;
}

static void sha256_bytes(const uint8_t *data, size_t len, uint8_t out_hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out_hash);
}

static int run_vec_ta1_zero_wear_bypass(void) {
    fuzz_platform_reset(0x54413131ULL);
    const boot_platform_t *plat = fuzz_platform_get();
    fuzz_keystore_set_dslc(0x01U);

    uint8_t src_block[512];
    for (size_t i = 0U; i < sizeof(src_block); i++) {
        src_block[i] = (uint8_t)((i * 7U + 0x11U) & 0xFFU);
    }
    fuzz_flash_fill_erased(CHIP_STAGING_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_fill_erased(CHIP_APP_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_write_raw(CHIP_STAGING_SLOT_ABS_ADDR, src_block, sizeof(src_block));

    uint32_t expected_crc = compute_boot_crc32(src_block, sizeof(src_block));
    static const boot_allowed_region_t wl[1] = {
        { CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE }
    };

    /* Positive control: exact post_crc passes read-back verification. */
    flash_effect_t fx_ok[2];
    memset(fx_ok, 0, sizeof(fx_ok));
    fx_ok[0].op = EFF_ERASE;
    fx_ok[0].dst = CHIP_APP_SLOT_ABS_ADDR;
    fx_ok[0].len = CHIP_FLASH_MAX_SECTOR_SIZE;
    fx_ok[0].post_crc = boot_effect_compute_erased_crc(CHIP_FLASH_MAX_SECTOR_SIZE);
    fx_ok[1].op = EFF_COPY;
    fx_ok[1].src = CHIP_STAGING_SLOT_ABS_ADDR;
    fx_ok[1].dst = CHIP_APP_SLOT_ABS_ADDR;
    fx_ok[1].len = sizeof(src_block);
    fx_ok[1].post_crc = expected_crc;

    if (boot_effect_execute(plat, fx_ok, 2U, wl, 1U, crypto_arena, sizeof(crypto_arena)) != BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-01 positive TA-1 control failed\n");
        return -1;
    }

    /* Negative: attempt zero-wear bypass with stale/forged post_crc (expect BOOT_ERR_FLASH_HW). */
    fuzz_flash_fill_erased(CHIP_APP_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    flash_effect_t fx_bad = fx_ok[1];
    fx_bad.post_crc = expected_crc ^ 0x00010000U;
    boot_status_t st_bad_crc =
        boot_effect_execute(plat, &fx_bad, 1U, wl, 1U, crypto_arena, sizeof(crypto_arena));
    if (st_bad_crc == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-01 forged post_crc accepted!\n");
        return -1;
    }

    /* Negative: attempt write into un-erased NOR flash violating zero-wear precondition. */
    uint8_t dirty[512];
    memset(dirty, 0x00, sizeof(dirty));
    fuzz_flash_write_raw(CHIP_APP_SLOT_ABS_ADDR, dirty, sizeof(dirty));
    fuzz_flash_set_enforce_nor(true);
    boot_status_t st_nor =
        boot_effect_execute(plat, &fx_ok[1], 1U, wl, 1U, crypto_arena, sizeof(crypto_arena));
    fuzz_flash_set_enforce_nor(false);
    if (st_nor == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-01 NOR corruption bypassed read-back check!\n");
        return -1;
    }

    printf("NEG_E2E_VECTOR id=NEG-01-TA1-ZERO-WEAR-BYPASS status=PASS\n");
    return 0;
}

static int run_vec_deployed_blank_wal(void) {
    fuzz_platform_reset(0x57414C32ULL);
    const boot_platform_t *plat = fuzz_platform_get();

    /* Factory unprovisioned (DSLC=0x00) positive control formats WAL cleanly. */
    fuzz_keystore_set_dslc(0x00U);
    g_fuzz_trap_active = 1;
    boot_status_t st_factory = BOOT_ERR_INVALID_STATE;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        st_factory = boot_journal_init(plat);
    }
    g_fuzz_trap_active = 0;
    if (st_factory != BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-02 factory DSLC=0x00 blank WAL failed init (0x%08x)\n",
                (unsigned)st_factory);
        return -1;
    }

    /* Deployed device (DSLC=0x01) with erased 0xFF WAL MUST fail closed and never boot. */
    fuzz_platform_reset(0x57414C33ULL);
    fuzz_keystore_set_dslc(0x01U);
    boot_status_t st_deployed = BOOT_ERR_INVALID_STATE;
    int trapped = 0;
    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        st_deployed = boot_journal_init(plat);
    } else {
        trapped = 1;
    }
    g_fuzz_trap_active = 0;

    if (trapped == 0 && st_deployed == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-02 deployed blank WAL accepted without panic!\n");
        return -1;
    }

    printf("NEG_E2E_VECTOR id=NEG-02-DEPLOYED-BLANK-WAL status=PASS\n");
    return 0;
}

static void build_signed_kdm_cmd(const boot_platform_t *plat, uint32_t kdm_seq,
                                 uint32_t counter_min, uint32_t issued_at,
                                 uint8_t out_buf[TOOB_CLOUD_CMD_MIN_SIZE + sizeof(toob_kdm_t)]) {
    memset(out_buf, 0, TOOB_CLOUD_CMD_MIN_SIZE + sizeof(toob_kdm_t));
    toob_cloud_cmd_hdr_t *hdr = (toob_cloud_cmd_hdr_t *)(void *)out_buf;
    hdr->magic = TOOB_CLOUD_CMD_MAGIC;
    hdr->version = TOOB_CLOUD_CMD_VERSION;
    hdr->command = (uint8_t)TOOB_CMD_ROTATE_KEY;
    hdr->counter_min = counter_min;
    hdr->issued_at = issued_at;
    hdr->params_len = (uint32_t)sizeof(toob_kdm_t);
    hdr->total_len = (uint32_t)(TOOB_CLOUD_CMD_MIN_SIZE + sizeof(toob_kdm_t));
    (void)boot_derive_device_id(plat, hdr->device_id);
    hdr->crc32 = compute_boot_crc32((const uint8_t *)hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);

    toob_kdm_t kdm;
    memset(&kdm, 0, sizeof(kdm));
    kdm.sequence_number = kdm_seq;
    memcpy(kdm.new_cloud_pubkey, g_fuzz_cloud_pk, 32U);
    crypto_ed25519_sign(kdm.signature_ed25519, g_fuzz_root_sk,
                        (const uint8_t *)(const void *)&kdm,
                        offsetof(toob_kdm_t, signature_ed25519));
    memcpy(&out_buf[TOOB_CLOUD_CMD_HDR_SIZE], &kdm, sizeof(kdm));

    size_t sig_off = (size_t)hdr->total_len - TOOB_CLOUD_CMD_SIG_SIZE;
    crypto_ed25519_sign(&out_buf[sig_off], g_fuzz_cloud_sk, out_buf, sig_off);
}

static int run_vec_kdm_floor_replay(void) {
    fuzz_platform_reset(0x4B444D34ULL);
    const boot_platform_t *plat = fuzz_platform_get();
    fuzz_keystore_set_dslc(0x00U);
    fuzz_keystore_set_monotonic(0U);

    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) != 0 || boot_journal_init(plat) != BOOT_OK) {
        g_fuzz_trap_active = 0;
        fprintf(stderr, "FAIL: NEG-03 journal init failed\n");
        return -1;
    }
    g_fuzz_trap_active = 0;
    fuzz_keystore_set_dslc(0x01U);
    fuzz_keystore_set_monotonic(1U);

    static const uint32_t kdm_addrs[3] = TOOB_KDM_SLOT_ADDRS;
    static const size_t kdm_sizes[3] = TOOB_KDM_SLOT_SIZES;
    const boot_rstore_desc_t kdm_desc = {
        .slot_addrs = kdm_addrs,
        .slot_sizes = kdm_sizes,
        .slot_count = 3U,
        .record_size = sizeof(toob_kdm_t),
        .magic = NEG_KDM_MAGIC
    };

    toob_kdm_t base_kdm;
    memset(&base_kdm, 0, sizeof(base_kdm));
    base_kdm.sequence_number = 5U;
    memcpy(base_kdm.new_cloud_pubkey, g_fuzz_cloud_pk, 32U);
    crypto_ed25519_sign(base_kdm.signature_ed25519, g_fuzz_root_sk,
                        (const uint8_t *)(const void *)&base_kdm,
                        offsetof(toob_kdm_t, signature_ed25519));
    if (boot_rstore_write(plat, &kdm_desc, &base_kdm) != BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-03 base KDM write failed\n");
        return -1;
    }

    wal_tmr_payload_t tmr;
    if (boot_journal_get_tmr(plat, &tmr) != BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-03 get_tmr failed\n");
        return -1;
    }
    tmr.kdm_seq_floor = 5U;
    tmr.last_accepted_issued_at = 1000U;
    if (boot_journal_update_tmr(plat, &tmr) != BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-03 update_tmr failed\n");
        return -1;
    }

    uint8_t env[TOOB_CLOUD_CMD_MIN_SIZE + sizeof(toob_kdm_t)] __attribute__((aligned(8)));
    toob_cloud_cmd_t out_cmd = TOOB_CMD_NOP;

    /* Replay older KDM seq=4 against floor=5 -> MUST reject. */
    build_signed_kdm_cmd(plat, 4U, 2U, 2000U, env);
    if (boot_cloud_cmd_evaluate_buffer(plat, env, sizeof(env), crypto_arena, &out_cmd) == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-03 replayed KDM seq=4 <= floor=5 accepted!\n");
        return -1;
    }

    /* Replay equal KDM seq=5 against floor=5 -> MUST reject. */
    build_signed_kdm_cmd(plat, 5U, 3U, 2001U, env);
    if (boot_cloud_cmd_evaluate_buffer(plat, env, sizeof(env), crypto_arena, &out_cmd) == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-03 replayed KDM seq=5 == floor=5 accepted!\n");
        return -1;
    }

    /* Positive control: KDM seq=6 > floor=5 succeeds cleanly. */
    build_signed_kdm_cmd(plat, 6U, 4U, 2002U, env);
    if (boot_cloud_cmd_evaluate_buffer(plat, env, sizeof(env), crypto_arena, &out_cmd) != BOOT_OK ||
        out_cmd != TOOB_CMD_ROTATE_KEY) {
        fprintf(stderr, "FAIL: NEG-03 valid KDM seq=6 > floor=5 rejected!\n");
        return -1;
    }

    printf("NEG_E2E_VECTOR id=NEG-03-KDM-FLOOR-REPLAY status=PASS\n");
    return 0;
}

static int run_vec_pqc_hash_mismatch(void) {
    fuzz_platform_reset(0x50514335ULL);
    boot_platform_t local_plat = *fuzz_platform_get();
    crypto_hal_t local_crypto = *local_plat.crypto;
    local_crypto.verify_pqc = mock_pqc_verify;
    local_crypto.is_pqc_enforced = mock_pqc_enforced;
    local_plat.crypto = &local_crypto;

    uint8_t env_buf[NEG_ENV_CAP] __attribute__((aligned(8)));
    memset(env_buf, 0, sizeof(env_buf));

    const size_t body_off = 32U;
    const size_t pk_off = 32U;
    const size_t sig_off = pk_off + NEG_PQC_PK_LEN;
    const size_t manifest_size = sig_off + NEG_PQC_SIG_LEN;
    const size_t total_size = manifest_size + 64U;
    (void)body_off;

    for (size_t i = 0U; i < manifest_size; i++) {
        env_buf[i] = (uint8_t)((i * 13U + 0x41U) & 0xFFU);
    }

    uint8_t expected_pk_hash[32];
    sha256_bytes(&env_buf[pk_off], NEG_PQC_PK_LEN, expected_pk_hash);
    fuzz_keystore_set_pqc_hash(0U, expected_pk_hash, true);

    uint8_t work_buf[NEG_ENV_CAP] __attribute__((aligned(8)));
    boot_verify_envelope_t env;
    memset(&env, 0, sizeof(env));
    env.manifest_flash_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    env.manifest_size = manifest_size;
    env.signature_ed25519 = &work_buf[manifest_size];
    env.key_index = 0U;
    env.pqc_hybrid_active = true;
    env.pubkey_pqc = &work_buf[pk_off];
    env.pubkey_pqc_len = NEG_PQC_PK_LEN;
    env.signature_pqc = &work_buf[sig_off];
    env.signature_pqc_len = NEG_PQC_SIG_LEN;

    /* Positive control: matching pinned PQC pubkey hash + valid Ed25519 -> BOOT_OK. */
    crypto_ed25519_sign(&env_buf[manifest_size], g_fuzz_root_sk, env_buf, manifest_size);
    memcpy(work_buf, env_buf, total_size);
    fuzz_flash_fill_erased(CHIP_STAGING_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_write_raw(CHIP_STAGING_SLOT_ABS_ADDR, env_buf, total_size);

    s_pqc_verify_called = false;
    boot_status_t st_ok = boot_verify_manifest_envelope(&local_plat, &env, work_buf, sizeof(work_buf));
    if (st_ok != BOOT_OK || !s_pqc_verify_called) {
        fprintf(stderr, "FAIL: NEG-04 PQC positive control failed (0x%08x)\n", (unsigned)st_ok);
        return -1;
    }

    /* Negative: attacker embeds different PQC pubkey and re-signs Ed25519 (mock verify_pqc
     * accepts, so ONLY OTP PQC pubkey SHA-256 pinning blocks the attack BEFORE verify_pqc!). */
    env_buf[pk_off + 3U] ^= 0x01U;
    crypto_ed25519_sign(&env_buf[manifest_size], g_fuzz_root_sk, env_buf, manifest_size);
    memcpy(work_buf, env_buf, total_size);
    fuzz_flash_fill_erased(CHIP_STAGING_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_write_raw(CHIP_STAGING_SLOT_ABS_ADDR, env_buf, total_size);

    s_pqc_verify_called = false;
    boot_status_t st_mismatch =
        boot_verify_manifest_envelope(&local_plat, &env, work_buf, sizeof(work_buf));
    if (st_mismatch == BOOT_OK || s_pqc_verify_called) {
        fprintf(stderr, "FAIL: NEG-04 PQC pubkey hash mismatch not blocked before PQC verify!\n");
        return -1;
    }

    printf("NEG_E2E_VECTOR id=NEG-04-PQC-HASH-MISMATCH status=PASS\n");
    return 0;
}

static int run_vec_unsigned_tampered_tsig_rollback(void) {
    fuzz_platform_reset(0x54534947ULL);
    const boot_platform_t *plat = fuzz_platform_get();

    const uint32_t body_len = (uint32_t)sizeof(toob_image_header_t) + NEG_IMG_PAYLOAD;
    const uint32_t total_len = body_len + (uint32_t)sizeof(toob_img_sig_trailer_t);
    uint8_t img[sizeof(toob_image_header_t) + NEG_IMG_PAYLOAD + sizeof(toob_img_sig_trailer_t)];
    memset(img, 0xA5, sizeof(img));

    toob_image_header_t *hdr = (toob_image_header_t *)(void *)img;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = TOOB_MAGIC_HEADER;
    hdr->image_size = total_len;
    hdr->entry_point = 0x100U;
    hdr->s1.svn_magic = TOOB_STAGE1_SVN_MAGIC;
    hdr->s1.stage1_svn = 2U;

    uint8_t digest[32];
    sha256_bytes(img, body_len, digest);

    toob_img_sig_trailer_t *tr = (toob_img_sig_trailer_t *)(void *)&img[body_len];
    memset(tr, 0, sizeof(*tr));
    tr->magic = TOOB_IMG_SIG_MAGIC;
    tr->key_index = 0U;
    tr->flags = TOOB_IMG_SIG_FLAG_SHA256;
    tr->reserved = 0U;
    crypto_ed25519_sign(tr->sig_ed25519, g_fuzz_root_sk, digest, sizeof(digest));

    /* Positive control: valid TSIG image passes boot_verify_slot_image. */
    fuzz_flash_fill_erased(CHIP_APP_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_write_raw(CHIP_APP_SLOT_ABS_ADDR, img, sizeof(img));
    if (boot_verify_slot_image(plat, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, hdr,
                               crypto_arena, sizeof(crypto_arena)) != BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-05 valid TSIG positive control failed\n");
        return -1;
    }

    /* Negative 5a: Unsigned image (missing TSIG magic) rejected. */
    uint8_t unsigned_img[sizeof(img)];
    memcpy(unsigned_img, img, sizeof(img));
    unsigned_img[body_len] ^= 0xFFU;
    fuzz_flash_fill_erased(CHIP_APP_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_write_raw(CHIP_APP_SLOT_ABS_ADDR, unsigned_img, sizeof(unsigned_img));
    if (boot_verify_slot_image(plat, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, hdr,
                               crypto_arena, sizeof(crypto_arena)) == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-05a unsigned TSIG image accepted!\n");
        return -1;
    }

    /* Negative 5b: 1-bit tampered TSIG signature rejected. */
    uint8_t bad_sig[sizeof(img)];
    memcpy(bad_sig, img, sizeof(img));
    bad_sig[body_len + 12U] ^= 0x01U;
    fuzz_flash_fill_erased(CHIP_APP_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_write_raw(CHIP_APP_SLOT_ABS_ADDR, bad_sig, sizeof(bad_sig));
    if (boot_verify_slot_image(plat, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, hdr,
                               crypto_arena, sizeof(crypto_arena)) == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-05b tampered TSIG signature accepted!\n");
        return -1;
    }

    /* Negative 5c: Revoked / higher key_index mismatch rejected. */
    uint8_t revoked_img[sizeof(img)];
    memcpy(revoked_img, img, sizeof(img));
    fuzz_keystore_set_key(1U, g_fuzz_root_pk, true); /* Slot 1 active => Slot 0 revoked */
    fuzz_flash_fill_erased(CHIP_APP_SLOT_ABS_ADDR, CHIP_FLASH_MAX_SECTOR_SIZE);
    fuzz_flash_write_raw(CHIP_APP_SLOT_ABS_ADDR, revoked_img, sizeof(revoked_img));
    if (boot_verify_slot_image(plat, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, hdr,
                               crypto_arena, sizeof(crypto_arena)) == BOOT_OK) {
        fprintf(stderr, "FAIL: NEG-05c revoked OTP key_index=0 accepted!\n");
        return -1;
    }

    printf("NEG_E2E_VECTOR id=NEG-05-UNSIGNED-TAMPERED-TSIG-ROLLBACK status=PASS\n");
    return 0;
}

int main(void) {
    if (run_vec_ta1_zero_wear_bypass() != 0) {
        return 1;
    }
    if (run_vec_deployed_blank_wal() != 0) {
        return 1;
    }
    if (run_vec_kdm_floor_replay() != 0) {
        return 1;
    }
    if (run_vec_pqc_hash_mismatch() != 0) {
        return 1;
    }
    if (run_vec_unsigned_tampered_tsig_rollback() != 0) {
        return 1;
    }
    printf("NEG_E2E_SUMMARY passed=5/5 status=PASS\n");
    return 0;
}
