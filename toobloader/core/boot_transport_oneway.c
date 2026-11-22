/**
 * @file boot_transport_oneway.c
 * @brief Tier-3 provider: Two-Phase One-Way copy (raw + delta) (C17).
 *
 * Intended path: toobloader/core/boot_transport_oneway.c      (Ticket ST-031)
 *
 * ALGORITHM
 *   Phase BACKUP : dest (old app)      -> backup region   (FULL mode only)
 *   Phase DEPLOY : src  (new image)    -> dest
 *   Rollback     : backup (old app)    -> dest            (FULL mode)
 *                  reverse-delta(src)  -> dest            (REVERSE_DELTA mode)
 *                  escalate/not found                     (NONE mode)
 *
 * Both phases are pure one-way copies whose SOURCE is never modified by the
 * phase itself — every block is therefore redo-idempotent, which makes the
 * brownout-resume trivial-by-construction (no tearing deduction needed, unlike
 * the 3-phase exchange). 2 ops per changed sector instead of 3, no scratch
 * hotspot, and after apply the old app sits in the backup region — exactly
 * where rollback expects it. This provider is the structural fix for the
 * confirmed delta bug: delta output and copy temp never share an address.
 */

#include "boot_transport.h"

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY

#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_delta.h"
#include "boot_features.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_secure_zeroize.h"
#include "boot_swap.h"
#include "boot_tbm1.h"
#include "generated_boot_config.h"
#include <stddef.h>
#include <string.h>

/* Persist a clean transport state (phase slot cleared) so downstream users of
 * transfer_bitmap (multi-image) never see stale transport markers. */
static boot_status_t finish_and_clean(const boot_platform_t *p, wal_entry_payload_t *txn,
                                      uint32_t final_offset) {
  txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0;
  txn->delta_chunk_id = final_offset;
  return boot_journal_append(p, txn);
}

#if TOOB_ONEWAY_BACKUP_MODE == TOOB_ONEWAY_BACKUP_REVERSE_DELTA
#if !TOOB_FEATURE_DELTA
#error "TOOB_ONEWAY_BACKUP_REVERSE_DELTA requires TOOB_FEATURE_DELTA == 1"
#endif
static boot_status_t resolve_staging_rdelta(const boot_platform_t *platform, uint32_t hint_offset,
                                            tbm1_rdelta_desc_t *out_rdesc,
                                            uint32_t *out_rdelta_addr, uint32_t *out_base_addr,
                                            uint32_t *out_base_size,
                                            toob_tds_header_t *out_tds_hdr) {
  const uint32_t stg_base = CHIP_STAGING_SLOT_ABS_ADDR;
  const uint32_t stg_size = CHIP_STAGING_SLOT_SIZE;
  if (UINT32_MAX - stg_base < stg_size) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  const uint32_t stg_end = stg_base + stg_size;

  uint32_t tbm1_addr = stg_base;
  if (hint_offset >= stg_base && (hint_offset - stg_base) < stg_size) {
    tbm1_addr = hint_offset;
  }

  /* Auto-discover sector-aligned Trailer-TBM1 if hint points to raw image[0] */
  if (tbm1_addr == stg_base) {
    toob_image_header_t raw_hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&raw_hdr, sizeof(raw_hdr));
    if (platform->flash->read(stg_base, &raw_hdr, sizeof(raw_hdr)) == BOOT_OK &&
        raw_hdr.magic == TOOB_MAGIC_HEADER && raw_hdr.image_size > sizeof(toob_image_header_t) &&
        raw_hdr.image_size < stg_size) {
      uint32_t sec_mask = CHIP_FLASH_MAX_SECTOR_SIZE - 1U;
      if (UINT32_MAX - raw_hdr.image_size >= sec_mask) {
        uint32_t cand_off = (raw_hdr.image_size + sec_mask) & ~sec_mask;
        if (cand_off < stg_size &&
            (stg_size - cand_off) >= (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) {
          tbm1_addr = stg_base + cand_off;
        }
      }
    }
    boot_secure_zeroize(&raw_hdr, sizeof(raw_hdr));
  }

  if ((stg_end - tbm1_addr) < (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) {
    return BOOT_ERR_NOT_FOUND;
  }

  tbm1_header_t hdr __attribute__((aligned(8)));
  boot_secure_zeroize(&hdr, sizeof(hdr));
  boot_status_t st = platform->flash->read(tbm1_addr, &hdr, sizeof(hdr));
  if (st != BOOT_OK) {
    return st;
  }
  if (hdr.magic != TBM1_MAGIC || hdr.fixed_len != TBM1_FIXED_LEN ||
      hdr.total_len < (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN) ||
      hdr.total_len > (stg_end - tbm1_addr) ||
      compute_boot_crc32((const uint8_t *)&hdr, TBM1_CRC_LEN) != hdr.fixed_crc32) {
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return BOOT_ERR_NOT_FOUND;
  }

  const bool is_trailer = ((hdr.flags_critical & TBM1_CRIT_TRAILER_LAYOUT) != 0U);
  const uint32_t payload_base = is_trailer ? stg_base : tbm1_addr;

  const tbm1_region_t *r = tbm1_find_region(&hdr, TBM1_REGION_REVERSE_DELTA);
  if (r == NULL || r->len < sizeof(tbm1_rdelta_desc_t) || r->off < TBM1_FIXED_LEN ||
      r->off > (hdr.total_len - TBM1_SIG_LEN - (uint32_t)sizeof(tbm1_rdelta_desc_t))) {
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return BOOT_ERR_NOT_FOUND;
  }

  boot_secure_zeroize(out_rdesc, sizeof(*out_rdesc));
  st = platform->flash->read(tbm1_addr + r->off, out_rdesc, sizeof(*out_rdesc));
  if (st != BOOT_OK) {
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return st;
  }

  if (out_rdesc->delta_alg != TBM1_DELTA_TDS1 ||
      out_rdesc->stored_size < (uint32_t)(sizeof(toob_tds_header_t) + sizeof(toob_tds_instr_t)) ||
      out_rdesc->restored_size <= sizeof(toob_image_header_t) ||
      out_rdesc->restored_size > CHIP_APP_SLOT_SIZE ||
      UINT32_MAX - payload_base < out_rdesc->data_off) {
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return BOOT_ERR_VERIFY;
  }

  uint32_t rdelta_addr = payload_base + out_rdesc->data_off;
  if (rdelta_addr < stg_base || rdelta_addr >= stg_end ||
      out_rdesc->stored_size > (stg_end - rdelta_addr)) {
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return BOOT_ERR_VERIFY;
  }

  uint32_t base_addr = 0U;
  uint32_t base_size = 0U;
  if (hdr.image_count > 0U && hdr.images[0].compression_alg == TBM1_COMP_NONE &&
      hdr.images[0].delta_alg == TBM1_DELTA_NONE) {
    if (UINT32_MAX - payload_base < hdr.images[0].data_off) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }
    uint32_t img0_addr = payload_base + hdr.images[0].data_off;
    if (img0_addr < stg_base || img0_addr >= stg_end ||
        hdr.images[0].installed_size > (stg_end - img0_addr)) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }
    base_addr = img0_addr;
    base_size = hdr.images[0].installed_size;
  } else {
#if defined(CHIP_SCRATCH_SLOT_SIZE) && (CHIP_SCRATCH_SLOT_SIZE > 0)
    base_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
    base_size = CHIP_SCRATCH_SLOT_SIZE;
#endif
  }
  boot_secure_zeroize(&hdr, sizeof(hdr));

  toob_tds_header_t tds_hdr __attribute__((aligned(8)));
  boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
  st = platform->flash->read(rdelta_addr, &tds_hdr, sizeof(tds_hdr));
  if (st != BOOT_OK) {
    return st;
  }
  uint32_t calc_crc =
      compute_boot_crc32((const uint8_t *)&tds_hdr, offsetof(toob_tds_header_t, header_crc32));
  if (tds_hdr.magic != TOOB_TDS_MAGIC || calc_crc != tds_hdr.header_crc32 ||
      tds_hdr.expected_target_size != out_rdesc->restored_size || tds_hdr.base_size > base_size) {
    boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
    return BOOT_ERR_VERIFY;
  }

  if (out_tds_hdr != NULL) {
    *out_tds_hdr = tds_hdr;
  }
  boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));

  *out_rdelta_addr = rdelta_addr;
  *out_base_addr = base_addr;
  *out_base_size = base_size;
  return BOOT_OK;
}
#endif

/* --------------------------------------------------------------------------
 * PROVIDER ENTRY POINTS
 * -------------------------------------------------------------------------- */
static boot_status_t oneway_apply(const boot_platform_t *platform, const slot_caps_t *caps,
                                  slot_txn_t *txn, wal_entry_payload_t *open_txn, uint8_t *arena,
                                  size_t arena_len) {
  (void)caps;
  if (!platform || !platform->flash || !platform->flash->read || !platform->flash->write ||
      !platform->flash->get_sector_size || !txn || !open_txn || !arena || arena_len < 512) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (txn->length == 0) {
    return BOOT_OK;
  }

  /* Bounds proofs (subtractive, wrap-safe). */
  if (txn->length > txn->dest_region_size || txn->length > txn->src_region_size ||
      (txn->backup_addr != 0 && txn->length > txn->backup_region_size)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  if (UINT32_MAX - txn->src_addr < txn->length || UINT32_MAX - txn->dest_addr < txn->length ||
      (txn->backup_addr != 0 && UINT32_MAX - txn->backup_addr < txn->length)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  /* Verify-before-destruction gate. */
  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });

  TOOB_TXN_SET_TRANSPORT(open_txn, TOOB_TRANSPORT_ID_ONEWAY);

  boot_status_t status = BOOT_OK;
  uint32_t dest_erases = 0, backup_erases = 0;
  const uint32_t phase = open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE];

#if TOOB_ONEWAY_BACKUP_MODE == TOOB_ONEWAY_BACKUP_REVERSE_DELTA
  /* Reverse-Delta Gate: Validate that reverse-delta descriptor AND staged TDS1
   * reverse-delta header + ghost-base match BEFORE modifying dest_addr! */
  if (phase != TOOB_PHASE_ONEWAY_DEPLOY) {
    tbm1_rdelta_desc_t rdesc;
    toob_tds_header_t tds_hdr;
    uint32_t rdelta_addr = 0U;
    uint32_t rbase_addr = 0U;
    uint32_t rbase_size = 0U;

    status = resolve_staging_rdelta(platform, open_txn->offset, &rdesc, &rdelta_addr, &rbase_addr,
                                    &rbase_size, &tds_hdr);
    if (status != BOOT_OK) {
      boot_secure_zeroize(&rdesc, sizeof(rdesc));
      boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
      goto cleanup;
    }

    if (rdesc.restored_size > txn->dest_region_size) {
      boot_secure_zeroize(&rdesc, sizeof(rdesc));
      boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
      status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    /* Verify that the Reverse-Delta's base_fingerprint actually matches the
     * new image being deployed (so a future rollback cannot fail ghost-base). */
    if (tds_hdr.base_size > 0U && platform->crypto && platform->crypto->hash_init &&
        platform->crypto->hash_update && platform->crypto->hash_finish) {
      uint64_t hash_ctx[32] __attribute__((aligned(8)));
      uint8_t computed[32] __attribute__((aligned(8)));
      boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
      boot_secure_zeroize(computed, sizeof(computed));
      size_t ctx_sz = sizeof(hash_ctx);
      if (platform->crypto->get_hash_ctx_size != NULL) {
        size_t req = platform->crypto->get_hash_ctx_size();
        if (req > 0U && req <= sizeof(hash_ctx)) {
          ctx_sz = req;
        }
      }
      status = platform->crypto->hash_init(hash_ctx, ctx_sz);
      uint32_t rem = tds_hdr.base_size;
      uint32_t cur = rbase_addr;
      while (rem > 0U && status == BOOT_OK) {
        if (platform->wdt && platform->wdt->kick) {
          platform->wdt->kick();
        }
        size_t step = (rem > arena_len) ? arena_len : rem;
        status = platform->flash->read(cur, arena, step);
        if (status == BOOT_OK) {
          status = platform->crypto->hash_update(hash_ctx, arena, step);
          cur += (uint32_t)step;
          rem -= (uint32_t)step;
        }
      }
      size_t dlen = sizeof(computed);
      if (status == BOOT_OK) {
        status = platform->crypto->hash_finish(hash_ctx, computed, &dlen);
      }
      if (status == BOOT_OK) {
        status = constant_time_memcmp_glitch_safe(computed, tds_hdr.base_fingerprint, 8U);
      }
      boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
      boot_secure_zeroize(computed, sizeof(computed));
      if (status != BOOT_OK) {
        boot_secure_zeroize(&rdesc, sizeof(rdesc));
        boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
        status = BOOT_ERR_VERIFY;
        goto cleanup;
      }
    }
    boot_secure_zeroize(&rdesc, sizeof(rdesc));
    boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));

    /* Transition directly to DEPLOY without physical flash backup */
    open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_ONEWAY_DEPLOY;
    open_txn->delta_chunk_id = 0;
    status = boot_journal_append(platform, open_txn);
    if (status != BOOT_OK) {
      goto cleanup;
    }
  }
#elif TOOB_ONEWAY_BACKUP_MODE == TOOB_ONEWAY_BACKUP_NONE
  if (phase != TOOB_PHASE_ONEWAY_DEPLOY) {
    open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_ONEWAY_DEPLOY;
    open_txn->delta_chunk_id = 0;
    status = boot_journal_append(platform, open_txn);
    if (status != BOOT_OK) {
      goto cleanup;
    }
  }
#else /* TOOB_ONEWAY_BACKUP_FULL */
  /* ---- Phase 1: BACKUP (dest -> backup), skipped when already in DEPLOY ---- */
  if (txn->backup_addr != 0 && phase != TOOB_PHASE_ONEWAY_DEPLOY) {
    uint32_t backup_len = txn->length;
    uint8_t old_hdr_buf[32] __attribute__((aligned(8)));
    toob_image_header_t old_hdr;
    boot_secure_zeroize(old_hdr_buf, sizeof(old_hdr_buf));
    boot_secure_zeroize(&old_hdr, sizeof(old_hdr));
    if (platform->flash->read(txn->dest_addr, old_hdr_buf, sizeof(old_hdr_buf)) == BOOT_OK) {
      memcpy(&old_hdr, old_hdr_buf, sizeof(old_hdr));
      if (old_hdr.magic == TOOB_MAGIC_HEADER && old_hdr.image_size > backup_len &&
          old_hdr.image_size <= txn->dest_region_size &&
          old_hdr.image_size <= txn->backup_region_size &&
          UINT32_MAX - txn->dest_addr >= old_hdr.image_size &&
          UINT32_MAX - txn->backup_addr >= old_hdr.image_size) {
        backup_len = old_hdr.image_size;
      }
    }
    boot_secure_zeroize(old_hdr_buf, sizeof(old_hdr_buf));
    boot_secure_zeroize(&old_hdr, sizeof(old_hdr));

    boot_allowed_region_t wl_backup[1] = {{txn->backup_addr, txn->backup_region_size}};
    status = boot_swap_copy_region_resumable(platform, txn->dest_addr, txn->backup_addr, backup_len,
                                             TOOB_PHASE_ONEWAY_BACKUP, open_txn, wl_backup, 1,
                                             &backup_erases, arena, arena_len);
    if (status != BOOT_OK) {
      goto cleanup;
    }

    /* Phase transition — persisted, so a brownout right after lands in DEPLOY
     * at offset 0 instead of redoing the backup. */
    open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_ONEWAY_DEPLOY;
    open_txn->delta_chunk_id = 0;
    status = boot_journal_append(platform, open_txn);
    if (status != BOOT_OK) {
      goto cleanup;
    }
  }
#endif

  /* ---- Phase 2: DEPLOY (src -> dest) ---- */
  {
    boot_allowed_region_t wl_dest[1] = {{txn->dest_addr, txn->dest_region_size}};
    status = boot_swap_copy_region_resumable(platform, txn->src_addr, txn->dest_addr, txn->length,
                                             TOOB_PHASE_ONEWAY_DEPLOY, open_txn, wl_dest, 1,
                                             &dest_erases, arena, arena_len);
    if (status != BOOT_OK) {
      goto cleanup;
    }
  }

  status = finish_and_clean(platform, open_txn, txn->length);
  if (status != BOOT_OK) {
    goto cleanup;
  }

  /* Best-effort wear telemetry (functional success is already anchored). */
  if (dest_erases > 0 || backup_erases > 0) {
    wal_tmr_payload_t tmr __attribute__((aligned(8)));
    boot_secure_zeroize(&tmr, sizeof(tmr));
    if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
      tmr.active_transport_id = TOOB_TRANSPORT_ID_ONEWAY;
      if ((boot_dest_slot_t)txn->dest_slot == BOOT_DEST_SLOT_APP) {
        tmr.app_slot_erase_counter += dest_erases;
        tmr.staging_slot_erase_counter += backup_erases;
      } else {
        tmr.app_slot_erase_counter += backup_erases;
        tmr.staging_slot_erase_counter += dest_erases;
      }
      (void)boot_journal_update_tmr(platform, &tmr);
    }
    boot_secure_zeroize(&tmr, sizeof(tmr));
  }

cleanup:
  boot_secure_zeroize(arena, arena_len);
  return status;
}

static boot_status_t oneway_rollback(const boot_platform_t *platform, const slot_caps_t *caps,
                                     slot_txn_t *txn, uint8_t *arena, size_t arena_len) {
  (void)caps;
  if (!platform || !txn || !arena || arena_len < 512) {
    return BOOT_ERR_INVALID_ARG;
  }

#if TOOB_ONEWAY_BACKUP_MODE == TOOB_ONEWAY_BACKUP_NONE
  return BOOT_ERR_NOT_FOUND; /* nothing was preserved — TSM must escalate */
#elif TOOB_ONEWAY_BACKUP_MODE == TOOB_ONEWAY_BACKUP_REVERSE_DELTA
  /* Reverse-Delta Rollback: Reconstruct live WAL transaction so hint offset and
   * sector-aligned brownout checkpoints survive resets mid-rollback. */
  wal_entry_payload_t rb_txn __attribute__((aligned(8)));
  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  if (boot_journal_reconstruct_txn(platform, &rb_txn, NULL, NULL) != BOOT_OK) {
    rb_txn.magic = WAL_ENTRY_MAGIC;
    rb_txn.intent = WAL_INTENT_TXN_ROLLBACK_PENDING;
    rb_txn.offset = CHIP_STAGING_SLOT_ABS_ADDR;
  }

  tbm1_rdelta_desc_t rdesc;
  uint32_t rdelta_addr = 0U;
  uint32_t rbase_addr = 0U;
  uint32_t rbase_size = 0U;
  boot_status_t status = resolve_staging_rdelta(platform, rb_txn.offset, &rdesc, &rdelta_addr,
                                                &rbase_addr, &rbase_size, NULL);
  if (status != BOOT_OK) {
    boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
    return status;
  }
  if (rdesc.restored_size > txn->dest_region_size) {
    boot_secure_zeroize(&rdesc, sizeof(rdesc));
    boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
    return BOOT_ERR_VERIFY;
  }

  if (rb_txn.intent != (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING) {
    rb_txn.intent = (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING;
    rb_txn.delta_chunk_id = 0U;
    rb_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_STREAM_WRITE;
    status = boot_journal_append(platform, &rb_txn);
    if (status != BOOT_OK) {
      boot_secure_zeroize(&rdesc, sizeof(rdesc));
      boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
      return status;
    }
  }

  /* Apply reverse delta: base is intact new image in Staging/Scratch, dest is App slot */
  status =
      boot_delta_apply(platform, rdelta_addr, rdesc.stored_size, txn->dest_addr,
                       txn->dest_region_size, rbase_addr, rbase_size, &rb_txn, arena, arena_len);
  if (status != BOOT_OK) {
    boot_secure_zeroize(&rdesc, sizeof(rdesc));
    boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
    return status;
  }

  /* Verify restored destination against rdesc.restored_sha256 if crypto HAL available */
  if (platform->crypto && platform->crypto->hash_init && platform->crypto->hash_update &&
      platform->crypto->hash_finish) {
    uint64_t hash_ctx[32] __attribute__((aligned(8)));
    size_t ctx_sz = sizeof(hash_ctx);
    if (platform->crypto->get_hash_ctx_size) {
      size_t req = platform->crypto->get_hash_ctx_size();
      if (req > 0U && req <= sizeof(hash_ctx)) {
        ctx_sz = req;
      }
    }
    status = platform->crypto->hash_init(hash_ctx, ctx_sz);
    if (status == BOOT_OK) {
      uint32_t rem = rdesc.restored_size;
      uint32_t cur = txn->dest_addr;
      while (rem > 0 && status == BOOT_OK) {
        if (platform->wdt && platform->wdt->kick) {
          platform->wdt->kick();
        }
        size_t step = (rem > arena_len) ? arena_len : rem;
        status = platform->flash->read(cur, arena, step);
        if (status == BOOT_OK) {
          status = platform->crypto->hash_update(hash_ctx, arena, step);
          cur += (uint32_t)step;
          rem -= (uint32_t)step;
        }
      }
      uint8_t computed[32] __attribute__((aligned(8)));
      boot_secure_zeroize(computed, sizeof(computed));
      size_t dlen = sizeof(computed);
      if (status == BOOT_OK) {
        status = platform->crypto->hash_finish(hash_ctx, computed, &dlen);
      }
      if (status == BOOT_OK) {
        status = constant_time_memcmp_glitch_safe(computed, rdesc.restored_sha256, 32);
      }
      boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
      boot_secure_zeroize(computed, sizeof(computed));
      if (status != BOOT_OK) {
        boot_secure_zeroize(&rdesc, sizeof(rdesc));
        boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
        return BOOT_ERR_VERIFY;
      }
    }
  }

  rb_txn.intent = (uint32_t)WAL_INTENT_TXN_ROLLBACK;
  status = finish_and_clean(platform, &rb_txn, rdesc.restored_size);
  boot_secure_zeroize(&rdesc, sizeof(rdesc));
  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  boot_secure_zeroize(arena, arena_len);
  return status;

#else /* TOOB_ONEWAY_BACKUP_FULL */
  if (txn->backup_addr == 0) {
    return BOOT_ERR_NOT_FOUND; /* nothing was preserved — TSM must escalate */
  }
  if (!platform->flash || !platform->flash->read) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint8_t bkup_hdr_buf[32] __attribute__((aligned(8)));
  toob_image_header_t bkup_hdr;
  boot_secure_zeroize(bkup_hdr_buf, sizeof(bkup_hdr_buf));
  boot_secure_zeroize(&bkup_hdr, sizeof(bkup_hdr));
  if (platform->flash->read(txn->backup_addr, bkup_hdr_buf, sizeof(bkup_hdr_buf)) != BOOT_OK) {
    return BOOT_ERR_FLASH_HW;
  }
  memcpy(&bkup_hdr, bkup_hdr_buf, sizeof(bkup_hdr));
  boot_secure_zeroize(bkup_hdr_buf, sizeof(bkup_hdr_buf));
  bool bkup_ok =
      (bkup_hdr.image_size > sizeof(toob_image_header_t)) && (bkup_hdr.image_size != 0xFFFFFFFFU);
  BOOT_SECURE_REQUIRE(bkup_hdr.magic == TOOB_MAGIC_HEADER && bkup_ok, {
    boot_secure_zeroize(&bkup_hdr, sizeof(bkup_hdr));
    return BOOT_ERR_NOT_FOUND;
  });
  uint32_t restore_len = bkup_hdr.image_size;
  boot_secure_zeroize(&bkup_hdr, sizeof(bkup_hdr));

  if (restore_len > txn->dest_region_size || restore_len > txn->backup_region_size) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  /* Reconstruct live WAL entry so brownouts mid-rollback resume cleanly. */
  wal_entry_payload_t rb_txn __attribute__((aligned(8)));
  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  if (boot_journal_reconstruct_txn(platform, &rb_txn, NULL, NULL) != BOOT_OK) {
    rb_txn.magic = WAL_ENTRY_MAGIC;
    rb_txn.intent = WAL_INTENT_TXN_ROLLBACK_PENDING;
  }
  if (rb_txn.intent != (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING) {
    rb_txn.intent = (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING;
    rb_txn.delta_chunk_id = 0U;
    rb_txn.transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0U;
    boot_status_t log_st = boot_journal_append(platform, &rb_txn);
    if (log_st != BOOT_OK) {
      boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
      return log_st;
    }
  }

  boot_allowed_region_t wl_dest[1] = {{txn->dest_addr, txn->dest_region_size}};
  uint32_t erases = 0;
  boot_status_t status = boot_swap_copy_region_resumable(
      platform, txn->backup_addr, txn->dest_addr, restore_len, TOOB_PHASE_ONEWAY_RBACK, &rb_txn,
      wl_dest, 1, &erases, arena, arena_len);
  if (status == BOOT_OK) {
    rb_txn.intent = (uint32_t)WAL_INTENT_TXN_ROLLBACK;
    status = finish_and_clean(platform, &rb_txn, restore_len);
  }

  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  boot_secure_zeroize(arena, arena_len);
  return status;
#endif
}

const slot_transport_t g_toob_transport_oneway = {
    .name = "oneway",
    .tier = 3,
    .id = TOOB_TRANSPORT_ID_ONEWAY,
    .apply = oneway_apply,
    .rollback = oneway_rollback,
};

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY */