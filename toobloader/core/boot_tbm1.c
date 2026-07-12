/**
 * @file boot_tbm1.c
 * @brief TBM1 v2 Manifest Validation Module
 *
 * Pure validation — no side effects, no flash I/O, no state machine coupling.
 * Input: raw buffer + staging capacity. Output: tbm1_reject_t.
 *
 * Validation order: precheck → regions → images → chunkhash_slices.
 * Signature verification is NOT part of this module — it remains in the
 * caller (stage_verify_envelope) because it requires crypto hardware access.
 */

#include "boot_tbm1.h"
#include "boot_crc32.h"

/* --------------------------------------------------------------------------
 * R2 — Structural Pre-Checks
 *
 * Must run before ANY field is trusted. Clamps attacker-controlled total_len
 * against physical staging capacity to prevent OOB reads during hashing.
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_precheck(const uint8_t *buf, size_t staging_cap) {
  if (staging_cap < TBM1_FIXED_LEN)
    return TBM1_BAD_TOTAL_LEN;

  const tbm1_header_t *h = (const tbm1_header_t *)buf;

  if (h->magic != TBM1_MAGIC)
    return TBM1_BAD_MAGIC;

  if (h->fixed_len != TBM1_FIXED_LEN)
    return TBM1_BAD_FIXED_LEN;

  if (h->version_major != TBM1_VERSION_MAJOR)
    return TBM1_BAD_VERSION;

  /* total_len drives the hash loop — clamp BEFORE use */
  if (h->total_len < (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN))
    return TBM1_BAD_TOTAL_LEN;
  if (h->total_len > staging_cap)
    return TBM1_BAD_TOTAL_LEN;

  /* Must-understand critical flags gate */
  if ((h->flags_critical & ~(uint16_t)TBM1_CRIT_KNOWN_MASK) != 0)
    return TBM1_BAD_CRIT_FLAG;

  /* Reader version gate */
  if (h->min_reader_major > TBM1_VERSION_MAJOR ||
      (h->min_reader_major == TBM1_VERSION_MAJOR &&
       h->min_reader_minor > TBM1_VERSION_MINOR))
    return TBM1_BAD_READER_VERSION;

  /* CRC32 pre-check: separates "staging corrupt" from "signature invalid" */
  uint32_t crc = compute_boot_crc32(buf, TBM1_CRC_LEN);
  if (crc != h->fixed_crc32)
    return TBM1_BAD_CRC;

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * R3 — Region Directory Validation
 *
 * Overflow-safe bounds, ascending + non-overlapping order, no duplicate IDs.
 * No _rsvd zero-check (H1 Reader-Tolerance: signed area, semantically ignored).
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_validate_regions(const tbm1_header_t *h) {
  size_t sig_start = tbm1_signed_len(h);
  if (sig_start == 0)
    return TBM1_BAD_TOTAL_LEN;

  uint32_t prev_end = TBM1_FIXED_LEN;
  uint16_t seen_ids = 0;

  for (unsigned i = 0; i < TBM1_MAX_REGIONS; i++) {
    const tbm1_region_t *r = &h->regions[i];
    if (r->region_id == TBM1_REGION_NONE)
      continue;

    /* Duplicate detection for standard IDs (0..15) via bitset */
    if (r->region_id < 16) {
      uint16_t bit = (uint16_t)(1u << r->region_id);
      if (seen_ids & bit)
        return TBM1_BAD_REGION_DUP;
      seen_ids |= bit;
    }

    /* Overflow-safe bounds: region must fit within signed area */
    if (r->off > (uint32_t)sig_start)
      return TBM1_BAD_REGION_BOUNDS;
    if (r->len > (uint32_t)sig_start - r->off)
      return TBM1_BAD_REGION_BOUNDS;

    /* Canonical order: ascending offsets, non-overlapping */
    if (r->off < prev_end)
      return TBM1_BAD_REGION_ORDER;
    prev_end = r->off + r->len;
  }

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * R4 — Image Descriptor Consistency
 *
 * image_count bounds, key_index within provisioned slots, HW compatibility,
 * chunk math cross-check per image.
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_validate_images(const tbm1_header_t *h) {
  if (h->image_count < 1 || h->image_count > TBM1_MAX_IMAGES)
    return TBM1_BAD_IMAGE_COUNT;

  if (h->key_index >= TOOB_DEVICE_KEY_SLOTS)
    return TBM1_BAD_KEY_INDEX;

  /* HW compatibility gate (compile-time device identity) */
#if TOOB_DEVICE_PRODUCT_ID != 0xFFFFU
  if (h->product_id != TOOB_DEVICE_PRODUCT_ID)
    return TBM1_BAD_HW_COMPAT;
  if (TOOB_DEVICE_HW_REV < h->hw_rev_min || TOOB_DEVICE_HW_REV > h->hw_rev_max)
    return TBM1_BAD_HW_COMPAT;
#endif

  for (unsigned i = 0; i < h->image_count; i++) {
    const tbm1_image_desc_t *d = &h->images[i];

    if (d->chunk_size == 0)
      return TBM1_BAD_CHUNK_MATH;

    uint32_t expect = (d->installed_size + d->chunk_size - 1) / d->chunk_size;
    if (d->num_chunks != expect)
      return TBM1_BAD_CHUNK_MATH;

    if (d->target_slot > TBM1_SLOT_STAGE1)
      return TBM1_BAD_CHUNK_MATH;
  }

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * R5 — Chunk-Hash Partitioning
 *
 * Spec rule: REGION_CHUNK_HASHES contains per-image SHA-256 hashes
 * concatenated in descriptor order. Total length must equal Σ(num_chunks_i)×32.
 * Per-image offsets are computed via prefix sum and written to out_off[].
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_chunkhash_slices(const tbm1_header_t *h,
                                    uint32_t *out_off) {
  const tbm1_region_t *r = tbm1_find_region(h, TBM1_REGION_CHUNK_HASHES);
  if (!r)
    return TBM1_BAD_CHUNKHASH_LEN;

  uint64_t sum = 0;
  for (unsigned i = 0; i < h->image_count; i++) {
    out_off[i] = r->off + (uint32_t)sum;
    sum += (uint64_t)h->images[i].num_chunks * 32u;
  }

  /* Exact length cross-check */
  if (sum != r->len)
    return TBM1_BAD_CHUNKHASH_LEN;

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * R6 — Top-Level Validation Facade
 *
 * Defined order: precheck → regions → images → chunkhash.
 * Signature verification is NOT included — remains with the crypto caller
 * to keep this module pure (no hardware/flash dependency).
 * -------------------------------------------------------------------------- */
tbm1_reject_t tbm1_validate(const uint8_t *buf, size_t staging_cap) {
  tbm1_reject_t rc;

  if ((rc = tbm1_precheck(buf, staging_cap)) != TBM1_OK)
    return rc;

  const tbm1_header_t *h = (const tbm1_header_t *)buf;

  if ((rc = tbm1_validate_regions(h)) != TBM1_OK)
    return rc;

  if ((rc = tbm1_validate_images(h)) != TBM1_OK)
    return rc;

  uint32_t offs[TBM1_MAX_IMAGES];
  if ((rc = tbm1_chunkhash_slices(h, offs)) != TBM1_OK)
    return rc;

  return TBM1_OK;
}

/* --------------------------------------------------------------------------
 * Reject → boot_status_t Mapping
 *
 * Maps the fine-grained tbm1_reject_t to the coarser boot_status_t used by
 * the pipeline error handler and WAL reject topology.
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
      return BOOT_ERR_INVALID_ARG;
  }
}
