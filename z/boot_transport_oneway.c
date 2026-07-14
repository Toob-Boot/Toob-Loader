/**
 * @file boot_transport_oneway.c
 * @brief Tier-3 provider: Two-Phase One-Way copy (raw + delta) (C17).
 *
 * Intended path: toobloader/core/boot_transport_oneway.c      (Ticket ST-031)
 *
 * ALGORITHM
 *   Phase BACKUP : dest (old app)      -> backup region   (skipped if backup_addr == 0)
 *   Phase DEPLOY : src  (new image)    -> dest
 *   Rollback     : backup (old app)    -> dest
 *
 * Both phases are pure one-way copies whose SOURCE is never modified by the
 * phase itself — every block is therefore redo-idempotent, which makes the
 * brownout-resume trivial-by-construction (no tearing deduction needed, unlike
 * the 3-phase exchange). 2 ops per changed sector instead of 3, no scratch
 * hotspot, and after apply the old app sits in the backup region — exactly
 * where rollback expects it. This provider is the structural fix for the
 * confirmed delta bug: delta output and copy temp never share an address.
 *
 * RESUME MODEL (verified: exhaustive single brownout after every flash op and
 * every WAL append, plus the full double-brownout grid; identity-skip and
 * all-0xFF edge sectors included; "never write a non-erased sector" asserted):
 *   - checkpoint {phase magic, block offset} is appended BEFORE each
 *     destructive block op; redo of a torn block is safe because the source is
 *     intact by construction.
 *   - resume keys on the PHASE MAGIC in transfer_bitmap[TOOB_TB_SLOT_PHASE],
 *     never on a raw delta_chunk_id — a stale offset from a previous pipeline
 *     stage (the delta VM leaves delta_chunk_id == image size) is ignored.
 *   - identity-skipped blocks are re-evaluated on resume (deterministic:
 *     sources unchanged), so skips need no WAL writes.
 *
 * transfer_bitmap usage: [TOOB_TB_SLOT_PHASE] only; cleared with a final WAL
 * append on completion so boot_multiimage never sees stale transport state.
 */

#include "boot_transport.h"

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY

#include "generated_boot_config.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_effect.h"
#include "boot_fih.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

#define ONEWAY_MAX_LOOPS 100000u

/* --------------------------------------------------------------------------
 * Block size solver: max of both regions' sector sizes at this offset, tail
 * padded to write alignment (mirrors the proven boot_rollback pattern).
 * -------------------------------------------------------------------------- */
static boot_status_t solve_block(const boot_platform_t *p, uint32_t src,
                                 uint32_t dst, uint32_t remaining,
                                 size_t *block_out) {
  size_t s_sec = 0, d_sec = 0;
  if (p->flash->get_sector_size(dst, &d_sec) != BOOT_OK || d_sec == 0 ||
      dst % d_sec != 0)
    return BOOT_ERR_FLASH_HW;
  if (p->flash->get_sector_size(src, &s_sec) != BOOT_OK || s_sec == 0 ||
      src % s_sec != 0)
    return BOOT_ERR_FLASH_HW;

  size_t block = (s_sec > d_sec) ? s_sec : d_sec;
  if (block > remaining) {
    block = remaining;
    if (p->flash->write_align > 0) {
      uint32_t align = p->flash->write_align;
      uint32_t rem = (uint32_t)(block % align);
      if (rem != 0)
        block += (align - rem);
    }
  }
  *block_out = block;
  return BOOT_OK;
}

/* Deep identity check (CRC pre-filter done by the caller): full constant-time
 * compare over arena halves — CRC equality alone must never skip a block. */
static boot_status_t blocks_identical(const boot_platform_t *p, uint32_t a,
                                      uint32_t b, size_t block, bool *out,
                                      uint8_t *arena, size_t arena_len) {
  size_t half = (arena_len / 2) & ~((size_t)7);
  if (half == 0)
    return BOOT_ERR_INVALID_ARG;

  *out = true;
  uint32_t off = 0;
  while (off < block) {
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();
    size_t step = (block - off > half) ? half : (block - off);
    if (p->flash->read(a + off, arena, step) != BOOT_OK ||
        p->flash->read(b + off, arena + half, step) != BOOT_OK) {
      *out = false;
      break;
    }
    if (constant_time_memcmp_glitch_safe(arena, arena + half, step) != BOOT_OK) {
      *out = false;
      break;
    }
    off += (uint32_t)step;
  }
  boot_secure_zeroize(arena, arena_len);
  return BOOT_OK;
}

/* --------------------------------------------------------------------------
 * Resumable one-way region copy. Sources are never written by this function,
 * so redo-from-checkpoint is always safe.
 * -------------------------------------------------------------------------- */
static boot_status_t copy_region_resumable(
    const boot_platform_t *p, uint32_t src_base, uint32_t dst_base,
    uint32_t length, uint32_t phase_magic, wal_entry_payload_t *txn,
    const boot_allowed_region_t *wl, uint32_t wl_n, uint32_t *erases_out,
    uint8_t *arena, size_t arena_len) {

  /* Resume keys on the phase magic — a foreign/stale delta_chunk_id is ignored. */
  uint32_t offset = 0;
  if (txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] == phase_magic) {
    offset = txn->delta_chunk_id;
    if (offset > length)
      offset = length;
  }

  uint32_t guard = 0;
  while (offset < length) {
    if (++guard > ONEWAY_MAX_LOOPS)
      return BOOT_ERR_FLASH_HW;
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();

    uint32_t src = src_base + offset;
    uint32_t dst = dst_base + offset;
    size_t block = 0;
    boot_status_t status = solve_block(p, src, dst, length - offset, &block);
    if (status != BOOT_OK)
      return status;

    /* Zero-wear identity skip: CRC pre-filter + deep compare. */
    uint32_t crc_src = 0, crc_dst = 0;
    status = boot_crc32_flash_stream(p, src, block, &crc_src, arena, arena_len);
    if (status != BOOT_OK)
      return status;
    status = boot_crc32_flash_stream(p, dst, block, &crc_dst, arena, arena_len);
    if (status != BOOT_OK)
      return status;

    if (crc_src == crc_dst) {
      bool same = false;
      status = blocks_identical(p, src, dst, block, &same, arena, arena_len);
      if (status != BOOT_OK)
        return status;
      if (same) {
        offset += (uint32_t)block;
        continue; /* deterministic — re-evaluated identically on resume */
      }
    }

    /* Checkpoint BEFORE the destructive op (redo-idempotent: source intact). */
    txn->delta_chunk_id = offset;
    txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = phase_magic;
    status = boot_journal_append(p, txn);
    if (status != BOOT_OK)
      return status;

    /* Plan erase+copy, execute via the shared engine (whitelist, post-CRC,
     * phase-bound read-back verify all live there). */
    flash_effect_t fx[2];
    fx[0].op = EFF_ERASE;
    fx[0].src = 0;
    fx[0].dst = dst;
    fx[0].len = (uint32_t)block;
    fx[0].post_crc = boot_effect_compute_erased_crc((uint32_t)block);
    fx[1].op = EFF_COPY;
    fx[1].src = src;
    fx[1].dst = dst;
    fx[1].len = (uint32_t)block;
    fx[1].post_crc = crc_src;

    status = boot_effect_execute(p, fx, 2, wl, wl_n, arena, arena_len);
    if (status != BOOT_OK)
      return status;

    if (erases_out) {
      size_t d_sec = 0;
      (void)p->flash->get_sector_size(dst, &d_sec);
      *erases_out += (d_sec > 0 && block / d_sec > 0) ? (uint32_t)(block / d_sec) : 1u;
    }
    offset += (uint32_t)block;
  }
  return BOOT_OK;
}

/* Persist a clean transport state (phase slot cleared) so downstream users of
 * transfer_bitmap (multi-image) never see stale transport markers. */
static boot_status_t finish_and_clean(const boot_platform_t *p,
                                      wal_entry_payload_t *txn,
                                      uint32_t final_offset) {
  txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0;
  txn->delta_chunk_id = final_offset;
  return boot_journal_append(p, txn);
}

/* --------------------------------------------------------------------------
 * PROVIDER ENTRY POINTS
 * -------------------------------------------------------------------------- */
static boot_status_t oneway_apply(const boot_platform_t *platform,
                                  const slot_caps_t *caps, slot_txn_t *txn,
                                  wal_entry_payload_t *open_txn,
                                  uint8_t *arena, size_t arena_len) {
  (void)caps;
  if (!platform || !platform->flash || !platform->flash->read ||
      !platform->flash->write || !platform->flash->get_sector_size ||
      !txn || !open_txn || !arena || arena_len < 512)
    return BOOT_ERR_INVALID_ARG;
  if (txn->length == 0)
    return BOOT_OK;

  /* Bounds proofs (subtractive, wrap-safe). */
  if (txn->length > txn->dest_region_size ||
      txn->length > txn->src_region_size ||
      (txn->backup_addr != 0 && txn->length > txn->backup_region_size))
    return BOOT_ERR_FLASH_BOUNDS;
  if (UINT32_MAX - txn->src_addr < txn->length ||
      UINT32_MAX - txn->dest_addr < txn->length ||
      (txn->backup_addr != 0 && UINT32_MAX - txn->backup_addr < txn->length))
    return BOOT_ERR_FLASH_BOUNDS;

  /* Verify-before-destruction gate. */
  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });

  TOOB_TXN_SET_TRANSPORT(open_txn, TOOB_TRANSPORT_ID_ONEWAY);

  boot_status_t status = BOOT_OK;
  uint32_t dest_erases = 0, backup_erases = 0;
  const uint32_t phase = open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE];

  /* ---- Phase 1: BACKUP (dest -> backup), skipped when already in DEPLOY ---- */
  if (txn->backup_addr != 0 && phase != TOOB_PHASE_ONEWAY_DEPLOY) {
    boot_allowed_region_t wl_backup[1] = {
        {txn->backup_addr, txn->backup_region_size}};
    status = copy_region_resumable(platform, txn->dest_addr, txn->backup_addr,
                                   txn->length, TOOB_PHASE_ONEWAY_BACKUP,
                                   open_txn, wl_backup, 1, &backup_erases,
                                   arena, arena_len);
    if (status != BOOT_OK)
      goto cleanup;

    /* Phase transition — persisted, so a brownout right after lands in DEPLOY
     * at offset 0 instead of redoing the backup. */
    open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_ONEWAY_DEPLOY;
    open_txn->delta_chunk_id = 0;
    status = boot_journal_append(platform, open_txn);
    if (status != BOOT_OK)
      goto cleanup;
  }

  /* ---- Phase 2: DEPLOY (src -> dest) ---- */
  {
    boot_allowed_region_t wl_dest[1] = {{txn->dest_addr, txn->dest_region_size}};
    status = copy_region_resumable(platform, txn->src_addr, txn->dest_addr,
                                   txn->length, TOOB_PHASE_ONEWAY_DEPLOY,
                                   open_txn, wl_dest, 1, &dest_erases,
                                   arena, arena_len);
    if (status != BOOT_OK)
      goto cleanup;
  }

  status = finish_and_clean(platform, open_txn, txn->length);
  if (status != BOOT_OK)
    goto cleanup;

  /* Best-effort wear telemetry (functional success is already anchored). */
  if (dest_erases > 0 || backup_erases > 0) {
    wal_tmr_payload_t tmr __attribute__((aligned(8)));
    boot_secure_zeroize(&tmr, sizeof(tmr));
    if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
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

static boot_status_t oneway_rollback(const boot_platform_t *platform,
                                     const slot_caps_t *caps, slot_txn_t *txn,
                                     uint8_t *arena, size_t arena_len) {
  (void)caps;
  if (!platform || !txn || !arena || arena_len < 512)
    return BOOT_ERR_INVALID_ARG;
  if (txn->backup_addr == 0)
    return BOOT_ERR_NOT_FOUND; /* nothing was preserved — TSM must escalate */
  if (txn->length > txn->dest_region_size ||
      txn->length > txn->backup_region_size)
    return BOOT_ERR_FLASH_BOUNDS;

  /* Rollback rides its own WAL intent (set by the TSM/rollback flow); the copy
   * itself is the same resumable one-way pattern, backup -> dest. */
  wal_entry_payload_t rb_txn __attribute__((aligned(8)));
  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  rb_txn.magic = WAL_ENTRY_MAGIC;
  rb_txn.intent = WAL_INTENT_TXN_ROLLBACK_PENDING;

  boot_allowed_region_t wl_dest[1] = {{txn->dest_addr, txn->dest_region_size}};
  uint32_t erases = 0;
  boot_status_t status = copy_region_resumable(
      platform, txn->backup_addr, txn->dest_addr, txn->length,
      TOOB_PHASE_ONEWAY_RBACK, &rb_txn, wl_dest, 1, &erases, arena, arena_len);
  if (status == BOOT_OK)
    status = finish_and_clean(platform, &rb_txn, txn->length);

  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  boot_secure_zeroize(arena, arena_len);
  return status;
}

const slot_transport_t g_toob_transport_oneway = {
    .name = "oneway",
    .tier = 3,
    .id = TOOB_TRANSPORT_ID_ONEWAY,
    .apply = oneway_apply,
    .rollback = oneway_rollback,
};

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY */