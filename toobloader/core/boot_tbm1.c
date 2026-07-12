/**
 * @file boot_tbm1.c
 * @brief TBM1 v2 Manifest Validation Module
 *
 * Pure validation — no side effects, no flash I/O, no state machine coupling.
 * Input: raw buffer + staging capacity. Output: tbm1_reject_t.
 *
 * RECOMMENDED CALLER SEQUENCE (strict signature-first layering):
 *   1. tbm1_precheck(buf, cap)         — bounds total_len; safe to hash after this
 *   2. caller verifies Ed25519 over [0 .. tbm1_signed_len(h))
 *   3. tbm1_validate_regions(h)
 *   4. tbm1_validate_images(h, cap, offs)   — on now-authenticated data
 *
 * tbm1_validate() bundles steps 1,3,4 for callers that accept structural
 * parsing on pre-signature data. This is SAFE (total_len is bounded in the
 * precheck, so nothing can read out of bounds), but the sequence above lets
 * all detailed parsing run on authenticated bytes only.
 *
 * Signature verification itself is NOT part of this module — it stays in the
 * caller (stage_verify_envelope) because it needs crypto hardware access.
 */

#include "boot_tbm1.h"
#include "boot_crc32.h"
#include <stdint.h>   /* uintptr_t */

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Overflow-safe ceiling division: ceil(a / b).
 *
 * The naive form (a + b - 1) / b overflows uint32_t when a is near UINT32_MAX,
 * which would let a large image declare 0 chunks (0 hashes = no content
 * verification). This form never overflows. Precondition: b != 0.
 */
static inline uint32_t ceil_div_u32(uint32_t a, uint32_t b) {
  return a / b + (a % b != 0u ? 1u : 0u);
}

/* --------------------------------------------------------------------------
 * R2 — Structural Pre-Checks
 *
 * Must run before ANY field is trusted. Clamps attacker-controlled total_len
 * against physical staging capacity to prevent OOB reads during hashing.
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_precheck(const uint8_t *buf, size_t staging_cap) {
  /* Null / alignment guard. The header is read via a (tbm1_header_t *) cast;
   * a misaligned or null buffer is a hard-fault risk on ARMv6-M (M0/M0+).
   * Cheap belt-and-suspenders even though the struct is `packed`. */
  if (buf == NULL || ((uintptr_t)buf & (sizeof(uint32_t) - 1u)) != 0u)
    return TBM1_BAD_ALIGN;

  if (staging_cap < TBM1_FIXED_LEN)
    return TBM1_BAD_TOTAL_LEN;

  const tbm1_header_t *h = (const tbm1_header_t *)buf;

  if (h->magic != TBM1_MAGIC)
    return TBM1_BAD_MAGIC;

  if (h->fixed_len != TBM1_FIXED_LEN)
    return TBM1_BAD_FIXED_LEN;

  if (h->version_major != TBM1_VERSION_MAJOR)
    return TBM1_BAD_VERSION;

  /* total_len drives the signature hash loop — clamp BEFORE anything hashes. */
  if (h->total_len < (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN))
    return TBM1_BAD_TOTAL_LEN;
  if (h->total_len > staging_cap)
    return TBM1_BAD_TOTAL_LEN;

  /* Must-understand critical flags gate. */
  if ((h->flags_critical & ~(uint16_t)TBM1_CRIT_KNOWN_MASK) != 0)
    return TBM1_BAD_CRIT_FLAG;

  /* Reader version gate: reject if the manifest needs a newer reader. */
  if (h->min_reader_major > TBM1_VERSION_MAJOR ||
      (h->min_reader_major == TBM1_VERSION_MAJOR &&
       h->min_reader_minor > TBM1_VERSION_MINOR))
    return TBM1_BAD_READER_VERSION;

  /* CRC32 pre-check: separates "staging corrupt" from "signature invalid".
   * Non-security integrity only — the Ed25519 signature is the real anchor. */
  uint32_t crc = compute_boot_crc32(buf, TBM1_CRC_LEN);
  if (crc != h->fixed_crc32)
    return TBM1_BAD_CRC;

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * R3 — Region Directory Validation
 *
 * Overflow-safe bounds, ascending + non-overlapping order, no duplicate IDs.
 * No _rsvd zero-check (Reader-Tolerance: signed area, semantically ignored).
 *
 * NOTE: ascending-offset order is a CANONICAL rule — the encoder MUST emit the
 * directory sorted by region offset, or valid manifests are rejected here.
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_validate_regions(const tbm1_header_t *h) {
  size_t sig_start = tbm1_signed_len(h);
  if (sig_start == 0)
    return TBM1_BAD_TOTAL_LEN;

  uint32_t prev_end = TBM1_FIXED_LEN;   /* regions live after the fixed header */
  uint16_t seen_ids = 0;                /* dup bitset for standard IDs (0..15) */

  for (unsigned i = 0; i < TBM1_MAX_REGIONS; i++) {
    const tbm1_region_t *r = &h->regions[i];
    if (r->region_id == TBM1_REGION_NONE)
      continue;

    /* Duplicate detection for standard IDs (< 16) via bitset.
     * Vendor IDs (>= 16) are not dup-checked — documented limitation. */
    if (r->region_id < 16) {
      uint16_t bit = (uint16_t)(1u << r->region_id);
      if (seen_ids & bit)
        return TBM1_BAD_REGION_DUP;
      seen_ids |= bit;
    }

    /* Overflow-safe bounds: region must fit within the signed area. */
    if (r->off > (uint32_t)sig_start)
      return TBM1_BAD_REGION_BOUNDS;
    if (r->len > (uint32_t)sig_start - r->off)
      return TBM1_BAD_REGION_BOUNDS;

    /* Canonical order: ascending offsets, non-overlapping. */
    if (r->off < prev_end)
      return TBM1_BAD_REGION_ORDER;
    /* Alignment rule: region starts must be 8-byte aligned */
    if ((r->off & 7u) != 0u)
      return TBM1_BAD_REGION_ALIGN;
    prev_end = r->off + r->len;   /* no overflow: r->off + r->len <= sig_start */
  }

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * R4 + R5 (fused) — Image Descriptors + Chunk-Hash Partitioning
 *
 * One pass over the image descriptors validates consistency AND builds the
 * per-image chunk-hash offsets (prefix sum), then cross-checks the total
 * against the chunk-hash region length.
 *
 * Precondition: tbm1_validate_regions(h) has passed, so region bounds hold.
 * out_off must point to an array of at least TBM1_MAX_IMAGES uint32_t.
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_validate_images(const tbm1_header_t *h, size_t staging_cap,
                                   uint32_t *out_off) {
  if (h->image_count < 1 || h->image_count > TBM1_MAX_IMAGES)
    return TBM1_BAD_IMAGE_COUNT;

  if (h->key_index >= TOOB_DEVICE_KEY_SLOTS)
    return TBM1_BAD_KEY_INDEX;

  /* HW compatibility gate (compile-time device identity).
   * A production build MUST define TOOB_DEVICE_PRODUCT_ID (see boot_tbm1.h),
   * otherwise this check is compiled out and firmware ships without gating. */
#if TOOB_DEVICE_PRODUCT_ID != 0xFFFFU
  if (h->product_id != TOOB_DEVICE_PRODUCT_ID)
    return TBM1_BAD_HW_COMPAT;
  if (TOOB_DEVICE_HW_REV < h->hw_rev_min || TOOB_DEVICE_HW_REV > h->hw_rev_max)
    return TBM1_BAD_HW_COMPAT;
#endif

  const tbm1_region_t *chunks = tbm1_find_region(h, TBM1_REGION_CHUNK_HASHES);
  if (chunks == NULL)
    return TBM1_BAD_CHUNKHASH_LEN;

  uint64_t acc = 0;   /* running byte offset into the chunk-hash region */

  for (unsigned i = 0; i < h->image_count; i++) {
    const tbm1_image_desc_t *d = &h->images[i];

    /* --- chunk math (overflow-safe ceiling) --- */
    if (d->chunk_size == 0u)
      return TBM1_BAD_CHUNK_MATH;
    if (d->num_chunks != ceil_div_u32(d->installed_size, d->chunk_size))
      return TBM1_BAD_CHUNK_MATH;

    /* --- field plausibility (unknown enum/slot → reject) --- */
    if (d->target_slot > TBM1_SLOT_STAGE1)
      return TBM1_BAD_IMAGE_FIELD;
    if (d->compression_alg > TBM1_COMP_LZ4)
      return TBM1_BAD_IMAGE_FIELD;
    if (d->delta_alg > TBM1_DELTA_DETOOLS)
      return TBM1_BAD_IMAGE_FIELD;

    /* --- staging data-pointer bounds (overflow-safe, size_t arithmetic) --- */
    if ((size_t)d->data_off >= staging_cap)
      return TBM1_BAD_IMAGE_FIELD;
    if ((size_t)d->stored_size > staging_cap - (size_t)d->data_off)
      return TBM1_BAD_IMAGE_FIELD;

    /* --- chunk-hash partitioning: per-image offset via prefix sum ---
     * (uint32_t)acc is exact on the success path: on return TBM1_OK we have
     * acc == chunks->len <= UINT32_MAX, so every intermediate acc fits u32.
     * chunks->off + acc <= sig_start (region bounds) → no offset overflow. */
    out_off[i] = chunks->off + (uint32_t)acc;
    acc += (uint64_t)d->num_chunks * 32u;   /* 32 = SHA-256 digest bytes */
  }

  /* Exact length cross-check: region holds exactly Σ(num_chunks_i)×32 bytes. */
  if (acc != (uint64_t)chunks->len)
    return TBM1_BAD_CHUNKHASH_LEN;

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * Top-Level Validation Facade
 *
 * Bundles precheck → regions → images(+chunkhash). Convenience for callers
 * that accept structural parsing on pre-signature data (safe: total_len is
 * bounded in the precheck). For strict signature-first layering, call the
 * steps individually per the file header.
 *
 * out_off receives the per-image chunk-hash offsets (>= TBM1_MAX_IMAGES).
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_validate(const uint8_t *buf, size_t manifest_cap, size_t staging_cap,
                            uint32_t *out_off) {
  tbm1_reject_t rc;

  if ((rc = tbm1_precheck(buf, manifest_cap)) != TBM1_OK)
    return rc;

  const tbm1_header_t *h = (const tbm1_header_t *)buf;

  if ((rc = tbm1_validate_regions(h)) != TBM1_OK)
    return rc;

  if ((rc = tbm1_validate_images(h, staging_cap, out_off)) != TBM1_OK)
    return rc;

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * Reject → boot_status_t Mapping
 *
 * Coarse mapping for the pipeline error handler. NOTE: log the fine-grained
 * tbm1_reject_t to telemetry BEFORE calling this — the mapping is lossy and
 * the whole point of the taxonomy is field-side failure-mode distinction.
 * -------------------------------------------------------------------------- */
boot_status_t tbm1_reject_to_boot_status(tbm1_reject_t rc) {
  switch (rc) {
    case TBM1_OK:
      return BOOT_OK;

    case TBM1_BAD_CRC:
      return BOOT_ERR_MANIFEST_CORRUPT;

    case TBM1_BAD_HW_COMPAT:
      return BOOT_ERR_MANIFEST_PRODUCT;

    case TBM1_BAD_VERSION:
    case TBM1_BAD_CRIT_FLAG:
    case TBM1_BAD_READER_VERSION:
      return BOOT_ERR_MANIFEST_VERSION;

    default:
      /* magic, fixed_len, total_len, align, image_count, key_index,
       * chunk_math, image_field, region_*, chunkhash_len */
      return BOOT_ERR_INVALID_ARG;
  }
}