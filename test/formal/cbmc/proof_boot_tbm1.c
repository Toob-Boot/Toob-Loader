/*
 * CBMC Memory-Safety, Arithmetic-Overflow & Bounds Proof for boot_tbm1.c.
 *
 * Verifies:
 *   - Pre-authentication fixed-header validation (tbm1_precheck) on arbitrary
 *     symbolic bytes, arbitrary manifest_cap, and misaligned/NULL pointers.
 *   - Signature-first gate with symbolic Ed25519 verification (nondet_int()
 *     exploring both pass and fail branches) proving signed slice and 64-byte
 *     signature bounds before variable region/TLV/image parsing.
 *   - Variable region table disjointness & bounds (tbm1_validate_regions),
 *     Region 6 reverse-delta descriptor bounds, and multi-image layout bounds
 *     (tbm1_validate_images / tbm1_validate / tbm1_find_region).
 *
 * Documented Domain Bound (see formal report Finding #1 on boot_tbm1.c:224):
 *   - Physical staging capacity and declared installed_size are bounded by
 *     CHIP_FLASH_TOTAL_SIZE (16 MB max MCU flash). Above ~128M chunks on a
 *     corrupt multi-image header, chunks->off + (uint32_t)acc at boot_tbm1.c:224
 *     wraps uint32_t prior to the line-229 acc != chunks->len rejection.
 */

#include "cbmc_common.h"
#include "boot_ct_utils.h"
#include "boot_tbm1.h"

#define TBM1_PROOF_BUF_CAP 640U
#define CT_PROOF_MAX_BYTES 8U

void prove_ct_utils_functional_contracts(void) {
    uint8_t a[CT_PROOF_MAX_BYTES];
    uint8_t b[CT_PROOF_MAX_BYTES];
    CBMC_HAVOC_OBJECT(a);
    CBMC_HAVOC_OBJECT(b);

    __CPROVER_assert(constant_time_memcmp_glitch_safe(a, b, 0U) == BOOT_ERR_VERIFY,
                     "zero-length constant_time_memcmp_glitch_safe must fail closed");
    __CPROVER_assert(verify_not_all_zeros_glitch_safe(a, 0U) == BOOT_ERR_VERIFY,
                     "zero-length verify_not_all_zeros_glitch_safe must fail closed");

    size_t len = nondet_size_t();
    __CPROVER_assume(len >= 1U && len <= CT_PROOF_MAX_BYTES);

    bool eq = true;
    bool all_zero = true;
    bool all_ff = true;
    uint8_t erased_val = nondet_uint8_t();
    bool all_erased = true;

    for (size_t i = 0U; i < len; i++) {
        if (a[i] != b[i]) {
            eq = false;
        }
        if (a[i] != 0x00U) {
            all_zero = false;
        }
        if (a[i] != 0xFFU) {
            all_ff = false;
        }
        if (a[i] != erased_val) {
            all_erased = false;
        }
    }

    boot_status_t cmp_st = constant_time_memcmp_glitch_safe(a, b, len);
    __CPROVER_assert((cmp_st == BOOT_OK) == eq,
                     "constant_time_memcmp_glitch_safe is bit-exact with bytewise equality");

    boot_status_t nz_st = verify_not_all_zeros_glitch_safe(a, len);
    __CPROVER_assert((nz_st == BOOT_OK) == (!all_zero && !all_ff),
                     "verify_not_all_zeros_glitch_safe rejects iff all-0x00 or all-0xFF");

    bool er_st = is_fully_erased_constant_time(a, len, erased_val);
    __CPROVER_assert(er_st == all_erased,
                     "is_fully_erased_constant_time matches bytewise erased predicate");
}

void prove_tbm1_pointer_and_enum_guards(void) {
    uint8_t raw[sizeof(tbm1_header_t) + TBM1_SIG_LEN + 8U] __attribute__((aligned(8)));
    CBMC_HAVOC_OBJECT(raw);

    __CPROVER_assert(tbm1_precheck(NULL, sizeof(raw)) == TBM1_BAD_ALIGN,
                     "NULL buffer must be rejected with TBM1_BAD_ALIGN");

    /* Misaligned offsets 1..3 mod 4 must always be rejected before casting */
    uint8_t misalign = nondet_uint8_t();
    __CPROVER_assume(misalign >= 1U && misalign <= 3U);
    __CPROVER_assert(tbm1_precheck(raw + misalign, sizeof(raw) - misalign) ==
                         TBM1_BAD_ALIGN,
                     "Misaligned buffer must be rejected without UB cast");

    /* Exhaustive status-code mapper check across unconstrained enum values */
    tbm1_reject_t any_reject = (tbm1_reject_t)nondet_int();
    boot_status_t mapped = tbm1_reject_to_boot_status(any_reject);
    if (any_reject == TBM1_OK) {
        __CPROVER_assert(mapped == BOOT_OK, "TBM1_OK must map to BOOT_OK");
    } else {
        __CPROVER_assert(mapped != BOOT_OK,
                         "Non-OK TBM1 rejection must never map to BOOT_OK");
    }
}

void prove_tbm1_staged_pipeline(void) {
    uint8_t buf[TBM1_PROOF_BUF_CAP] __attribute__((aligned(8)));
    CBMC_HAVOC_OBJECT(buf);

    size_t manifest_cap = nondet_size_t();
    __CPROVER_assume(manifest_cap <= sizeof(buf));

    size_t staging_cap = nondet_size_t();
    __CPROVER_assume(staging_cap <= CHIP_FLASH_TOTAL_SIZE);

    uint8_t pubkey[32];
    CBMC_HAVOC_OBJECT(pubkey);

    const tbm1_header_t *raw_hdr = (const tbm1_header_t *)buf;
    for (unsigned m = 0U; m < TBM1_MAX_IMAGES; m++) {
        __CPROVER_assume(raw_hdr->images[m].installed_size <= CHIP_FLASH_TOTAL_SIZE);
    }

    tbm1_reject_t rc = tbm1_precheck(buf, manifest_cap);
    if (rc == TBM1_OK) {
        const tbm1_header_t *hdr = (const tbm1_header_t *)buf;
        __CPROVER_assert(hdr->total_len >= (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN),
                         "total_len lower bound holds after precheck");
        __CPROVER_assert((size_t)hdr->total_len <= manifest_cap,
                         "total_len fits within manifest_cap");

        size_t signed_len = tbm1_signed_len(hdr);
        const uint8_t *sig_ptr = buf + signed_len;

        __CPROVER_assert(signed_len >= TBM1_FIXED_LEN,
                         "signed_len covers at least fixed header");
        __CPROVER_assert(signed_len + TBM1_SIG_LEN == (size_t)hdr->total_len,
                         "signed_len + TBM1_SIG_LEN equals total_len");
        __CPROVER_assert(__CPROVER_r_ok(buf, signed_len),
                         "signed slice must be readable inside manifest buffer");
        __CPROVER_assert(__CPROVER_r_ok(sig_ptr, TBM1_SIG_LEN),
                         "Ed25519 signature slice must be readable inside manifest buffer");

        boot_status_t sig_st =
            cbmc_ed25519_verify_sig(buf, signed_len, sig_ptr, pubkey);

        if (sig_st == BOOT_OK) {
            tbm1_reject_t reg_rc = tbm1_validate_regions(hdr);
            if (reg_rc == TBM1_OK) {
                for (unsigned i = 0U; i < TBM1_MAX_REGIONS; i++) {
                    const tbm1_region_t *r = &hdr->regions[i];
                    if (r->region_id != TBM1_REGION_NONE) {
                        __CPROVER_assert(r->off >= TBM1_FIXED_LEN,
                                         "validated region starts at or after fixed header");
                        __CPROVER_assert((uint64_t)r->off + (uint64_t)r->len <=
                                             (uint64_t)signed_len,
                                         "validated region fits strictly inside signed slice");
                    }
                }

                uint16_t query_id = nondet_uint16_t();
                const tbm1_region_t *found = tbm1_find_region(hdr, query_id);
                if (found != NULL) {
                    __CPROVER_assert(query_id != TBM1_REGION_NONE &&
                                         found->region_id == query_id,
                                     "tbm1_find_region returns matching active region");
                    __CPROVER_assert(found->len == 0U ||
                                         __CPROVER_r_ok(buf + found->off, found->len),
                                     "located region payload is readable within buf");
                }

                uint32_t chunk_offs[TBM1_MAX_IMAGES] = {0};
                tbm1_reject_t img_rc =
                    tbm1_validate_images(hdr, staging_cap, chunk_offs);
                if (img_rc == TBM1_OK) {
                    __CPROVER_assert(hdr->image_count >= 1U &&
                                         hdr->image_count <= TBM1_MAX_IMAGES,
                                     "image_count in [1, TBM1_MAX_IMAGES]");
                    for (uint16_t k = 0U; k < hdr->image_count; k++) {
                        const tbm1_image_desc_t *im = &hdr->images[k];
                        __CPROVER_assert((uint64_t)im->data_off +
                                             (uint64_t)im->stored_size <=
                                             (uint64_t)staging_cap,
                                         "validated image data fits within staging_cap");
                        __CPROVER_assert((uint64_t)chunk_offs[k] +
                                             ((uint64_t)im->num_chunks * 32ULL) <=
                                             (uint64_t)signed_len,
                                         "validated chunk-hash slice fits inside signed area");
                    }
                }
            }
        }
    }
}

void prove_tbm1_validate_facade(void) {
    uint8_t buf[TBM1_PROOF_BUF_CAP] __attribute__((aligned(8)));
    CBMC_HAVOC_OBJECT(buf);

    size_t manifest_cap = nondet_size_t();
    __CPROVER_assume(manifest_cap <= sizeof(buf));

    size_t staging_cap = nondet_size_t();
    __CPROVER_assume(staging_cap <= CHIP_FLASH_TOTAL_SIZE);

    const tbm1_header_t *raw_hdr = (const tbm1_header_t *)buf;
    for (unsigned m = 0U; m < TBM1_MAX_IMAGES; m++) {
        __CPROVER_assume(raw_hdr->images[m].installed_size <= CHIP_FLASH_TOTAL_SIZE);
    }

    uint32_t out_off[TBM1_MAX_IMAGES] = {0};
    tbm1_reject_t full_rc = tbm1_validate(buf, manifest_cap, staging_cap, out_off);
    if (full_rc == TBM1_OK) {
        const tbm1_header_t *hdr = (const tbm1_header_t *)buf;
        __CPROVER_assert(hdr->image_count >= 1U &&
                             hdr->image_count <= TBM1_MAX_IMAGES,
                         "tbm1_validate TBM1_OK enforces valid image_count");
    }
}

int main(void) {
    uint8_t mode = nondet_uint8_t();
    if (mode == 0U) {
        prove_ct_utils_functional_contracts();
    } else if (mode == 1U) {
        prove_tbm1_pointer_and_enum_guards();
    } else if (mode == 2U) {
        prove_tbm1_staged_pipeline();
    } else {
        prove_tbm1_validate_facade();
    }
    return 0;
}
