#include "fuzz_common.h"

#include "boot_crc32.h"
#include "boot_tbm1.h"
#include "boot_verify.h"

#define FUZZ_TBM1_MAX_BUF 16384U

static uint8_t s_aligned_buf[FUZZ_TBM1_MAX_BUF] __attribute__((aligned(8)));
static uint8_t s_unaligned_buf[FUZZ_TBM1_MAX_BUF + 8U];
static uint8_t s_repaired_buf[FUZZ_TBM1_MAX_BUF] __attribute__((aligned(8)));

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    size_t copy_len = (size > FUZZ_TBM1_MAX_BUF) ? FUZZ_TBM1_MAX_BUF : size;
    fuzz_platform_reset(0x54424D31ULL ^ (uint64_t)size);
    const boot_platform_t *plat = fuzz_platform_get();

    memset(s_aligned_buf, 0, sizeof(s_aligned_buf));
    if (copy_len > 0U) {
        memcpy(s_aligned_buf, data, copy_len);
    }

    uint32_t out_off[TBM1_MAX_IMAGES];
    memset(out_off, 0, sizeof(out_off));

    /* 1. Raw manifest validation against exact buffer capacity and staging slot capacity. */
    tbm1_reject_t rc1 = tbm1_validate(s_aligned_buf, copy_len, copy_len, out_off);
    (void)tbm1_reject_to_boot_status(rc1);

    tbm1_reject_t rc2 =
        tbm1_validate(s_aligned_buf, copy_len, CHIP_STAGING_SLOT_SIZE, out_off);
    (void)tbm1_reject_to_boot_status(rc2);

    /* 2. Deliberately unaligned (+1) pointer check when enough bytes exist. */
    if (copy_len > 0U) {
        memcpy(&s_unaligned_buf[1], s_aligned_buf, copy_len);
        tbm1_reject_t rc_unalign =
            tbm1_precheck(&s_unaligned_buf[1], copy_len);
        (void)rc_unalign;
    }

    /* 3. Exercise envelope signature verifier with TBM1 total_len bounds. */
    if (copy_len >= (size_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) {
        const tbm1_header_t *hdr = (const tbm1_header_t *)(const void *)s_aligned_buf;
        size_t signed_len = tbm1_signed_len(hdr);
        if (signed_len > 0U && signed_len + TBM1_SIG_LEN <= copy_len) {
            boot_verify_envelope_t env;
            memset(&env, 0, sizeof(env));
            env.manifest_flash_addr = CHIP_STAGING_SLOT_ABS_ADDR;
            env.manifest_size = signed_len;
            env.signature_ed25519 = &s_aligned_buf[signed_len];
            env.key_index = hdr->key_index;
            (void)boot_verify_manifest_envelope(plat, &env, s_aligned_buf, copy_len);
        }
    }

    /* 4. Recompute fixed_crc32 on a separate copy so mutations inside TLV/region/image
     *    descriptors penetrate past the CRC precheck into region & rdelta bounds checks. */
    if (copy_len >= (size_t)TBM1_FIXED_LEN) {
        memcpy(s_repaired_buf, s_aligned_buf, copy_len);
        tbm1_header_t *rh = (tbm1_header_t *)(void *)s_repaired_buf;
        rh->fixed_crc32 = compute_boot_crc32(s_repaired_buf, TBM1_CRC_LEN);
        tbm1_reject_t rc_rep =
            tbm1_validate(s_repaired_buf, copy_len, CHIP_STAGING_SLOT_SIZE, out_off);
        (void)tbm1_reject_to_boot_status(rc_rep);
        if (rc_rep == TBM1_OK) {
            (void)tbm1_find_region(rh, TBM1_REGION_NONE);
            (void)tbm1_find_region(rh, TBM1_REGION_CHUNK_HASHES);
            (void)tbm1_find_region(rh, TBM1_REGION_REVERSE_DELTA);
        }
    }

    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("tbm1")
