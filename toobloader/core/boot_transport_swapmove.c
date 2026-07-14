/**
 * @file boot_transport_swapmove.c
 * @brief Tier-2 provider: in-place swap-move — the exchange without the
 *        scratch hotspot (C17).
 *
 * Intended path: toobloader/core/boot_transport_swapmove.c    (Ticket ST-032)
 *
 * ALGORITHM (MCUboot-style swap-using-move, N sectors, dest has one SPARE
 * sector at the top: dest region >= (N+1) * sector):
 *
 *   MOVE  (i = N-1 .. 0): erase P[i+1]; copy P[i] -> P[i+1]
 *          After the move, P[i+1] holds old_P[i] for all i.
 *   SWAP  (i = 0 .. N-1): (a) erase P[i]; copy S[i]     -> P[i]
 *                         (b) erase S[i]; copy P[i+1]   -> S[i]   (= old_P[i])
 *
 * Result: P holds the new image, S holds the old app (rollback source). Wear
 * is DISTRIBUTED — P sectors see at most 2 erases, S sectors 1; no single
 * sector is hammered once per block like the swap-scratch buffer. Honest
 * trade-off (documented; wear-aware selection may prefer swapscratch+skip for
 * tiny deltas): the move phase rewrites the whole primary once, so the
 * identity-skip win on unchanged sectors is lost — total ops equal
 * swap-scratch, the distribution is the gain.
 *
 * RESUME MODEL (verified: exhaustive single brownout after every erase, write
 * and WAL append, full double-brownout grid, FF-content edges included,
 * "never write a non-erased sector" asserted):
 *   - MOVE steps checkpoint {MOVE, idx} BEFORE each step; a redo is idempotent
 *     because P[i] is only modified by the LATER step i-1 (descending order).
 *     A content-equality pre-check skips already-completed steps on resume.
 *   - SWAP steps checkpoint {SWAP, idx, cs=CRC(S[i]), cp=CRC(P[i+1])} BEFORE
 *     sub-step (a). On resume the sub-state is DEDUCED from content:
 *     P[i]==cs -> (a) done; S[i]==cp -> (b) done. Sub-step (b) destroys (a)'s
 *     redo source, so this deduction (one WAL append per sector instead of
 *     two) is what makes single-append-per-index safe. CRC-equality standing
 *     in for content-equality carries the same collision acceptance as the
 *     legacy swap deduction.
 *
 * CONSTRAINTS: uniform sector size across dest and src regions (checked;
 * BOOT_ERR_NOT_SUPPORTED otherwise — codegen should then select another
 * provider), and the spare-sector geometry ((N+1)*sec <= dest_region_size).
 *
 * transfer_bitmap usage: [TOOB_TB_SLOT_PHASE]=phase, [AUX0]=cs, [AUX1]=cp;
 * all cleared with a final WAL append on completion.
 */

#include "boot_transport.h"

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPMOVE

#include "generated_boot_config.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_effect.h"
#include "boot_fih.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>

#define SM_MAX_LOOPS 100000u

typedef struct {
  const boot_platform_t *p;
  uint32_t P;        /* dest base (primary, N+1 sectors incl. spare) */
  uint32_t S;        /* src base (secondary, N sectors)              */
  uint32_t sec;      /* uniform sector size                          */
  uint32_t N;        /* image sectors                                */
  const boot_allowed_region_t *wl;
  uint32_t wl_n;
  uint8_t *arena;
  size_t arena_len;
  uint32_t p_erases;
  uint32_t s_erases;
} sm_ctx_t;

static uint32_t sm_crc(sm_ctx_t *c, uint32_t addr, boot_status_t *st) {
  uint32_t crc = 0;
  *st = boot_crc32_flash_stream(c->p, addr, c->sec, &crc, c->arena, c->arena_len);
  return crc;
}

/* erase+copy one sector via the shared effect engine (whitelist + post-CRC +
 * phase-bound read-back verify all live there). */
static boot_status_t sm_move_sector(sm_ctx_t *c, uint32_t src, uint32_t dst,
                                    uint32_t post_crc, uint32_t *erase_ctr) {
  flash_effect_t fx[2];
  fx[0].op = EFF_ERASE;
  fx[0].src = 0;
  fx[0].dst = dst;
  fx[0].len = c->sec;
  fx[0].post_crc = boot_effect_compute_erased_crc(c->sec);
  fx[1].op = EFF_COPY;
  fx[1].src = src;
  fx[1].dst = dst;
  fx[1].len = c->sec;
  fx[1].post_crc = post_crc;

  boot_status_t st =
      boot_effect_execute(c->p, fx, 2, c->wl, c->wl_n, c->arena, c->arena_len);
  if (st == BOOT_OK && erase_ctr)
    (*erase_ctr)++;
  return st;
}

static boot_status_t swapmove_apply(const boot_platform_t *platform,
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

  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });

  /* Geometry: uniform sector size, aligned bases, spare sector present. */
  size_t d_sec = 0, s_sec = 0;
  if (platform->flash->get_sector_size(txn->dest_addr, &d_sec) != BOOT_OK ||
      platform->flash->get_sector_size(txn->src_addr, &s_sec) != BOOT_OK ||
      d_sec == 0 || d_sec != s_sec)
    return BOOT_ERR_NOT_SUPPORTED;
  if (txn->dest_addr % d_sec != 0 || txn->src_addr % d_sec != 0)
    return BOOT_ERR_NOT_SUPPORTED;

  sm_ctx_t c;
  boot_secure_zeroize(&c, sizeof(c));
  c.p = platform;
  c.P = txn->dest_addr;
  c.S = txn->src_addr;
  c.sec = (uint32_t)d_sec;
  c.N = (txn->length + c.sec - 1u) / c.sec;
  c.arena = arena;
  c.arena_len = arena_len;

  if (c.N == 0 || (uint64_t)(c.N + 1u) * c.sec > txn->dest_region_size ||
      (uint64_t)c.N * c.sec > txn->src_region_size)
    return BOOT_ERR_FLASH_BOUNDS; /* spare-sector contract violated */

  boot_allowed_region_t wl[2] = {
      {txn->dest_addr, txn->dest_region_size},
      {txn->src_addr, txn->src_region_size},
  };
  c.wl = wl;
  c.wl_n = 2;

  TOOB_TXN_SET_TRANSPORT(open_txn, TOOB_TRANSPORT_ID_SWAPMOVE);

  boot_status_t status = BOOT_OK;
  uint32_t guard = 0;
  const uint32_t phase = open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE];
  bool in_swap = (phase == TOOB_PHASE_SWAPMOVE_SWAP);
  bool in_move = (phase == TOOB_PHASE_SWAPMOVE_MOVE);

  /* ==================== PHASE MOVE (descending) ==================== */
  if (!in_swap) {
    int32_t i = in_move ? (int32_t)open_txn->delta_chunk_id : (int32_t)c.N - 1;
    if (i > (int32_t)c.N - 1)
      i = (int32_t)c.N - 1;

    while (i >= 0) {
      if (++guard > SM_MAX_LOOPS) { status = BOOT_ERR_FLASH_HW; goto cleanup; }
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      uint32_t src = c.P + (uint32_t)i * c.sec;
      uint32_t dst = c.P + ((uint32_t)i + 1u) * c.sec;

      uint32_t crc_src = sm_crc(&c, src, &status);
      if (status != BOOT_OK) goto cleanup;
      uint32_t crc_dst = sm_crc(&c, dst, &status);
      if (status != BOOT_OK) goto cleanup;
      if (crc_src == crc_dst) { i--; continue; } /* step already done (resume) */

      open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_SWAPMOVE_MOVE;
      open_txn->delta_chunk_id = (uint32_t)i;
      status = boot_journal_append(platform, open_txn);
      if (status != BOOT_OK) goto cleanup;

      status = sm_move_sector(&c, src, dst, crc_src, &c.p_erases);
      if (status != BOOT_OK) goto cleanup;
      i--;
    }
  }

  /* ==================== PHASE SWAP (ascending) ==================== */
  {
    uint32_t i = in_swap ? open_txn->delta_chunk_id : 0u;
    bool have_wal_crcs = in_swap;

    while (i < c.N) {
      if (++guard > SM_MAX_LOOPS) { status = BOOT_ERR_FLASH_HW; goto cleanup; }
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      uint32_t p_i = c.P + i * c.sec;
      uint32_t p_n = c.P + (i + 1u) * c.sec;
      uint32_t s_i = c.S + i * c.sec;

      uint32_t cs, cp;
      if (have_wal_crcs && open_txn->delta_chunk_id == i) {
        cs = open_txn->transfer_bitmap[TOOB_TB_SLOT_AUX0];
        cp = open_txn->transfer_bitmap[TOOB_TB_SLOT_AUX1];
      } else {
        cs = sm_crc(&c, s_i, &status);
        if (status != BOOT_OK) goto cleanup;
        cp = sm_crc(&c, p_n, &status);
        if (status != BOOT_OK) goto cleanup;

        open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_SWAPMOVE_SWAP;
        open_txn->transfer_bitmap[TOOB_TB_SLOT_AUX0] = cs;
        open_txn->transfer_bitmap[TOOB_TB_SLOT_AUX1] = cp;
        open_txn->delta_chunk_id = i;
        status = boot_journal_append(platform, open_txn);
        if (status != BOOT_OK) goto cleanup;
      }
      have_wal_crcs = false;

      /* Sub-step deduction from content (see file header). */
      uint32_t crc_pi = sm_crc(&c, p_i, &status);
      if (status != BOOT_OK) goto cleanup;
      if (crc_pi != cs) { /* (a) pending: erase P[i], copy S[i] -> P[i] */
        status = sm_move_sector(&c, s_i, p_i, cs, &c.p_erases);
        if (status != BOOT_OK) goto cleanup;
      }
      uint32_t crc_si = sm_crc(&c, s_i, &status);
      if (status != BOOT_OK) goto cleanup;
      if (crc_si != cp) { /* (b) pending: erase S[i], copy P[i+1] -> S[i] */
        status = sm_move_sector(&c, p_n, s_i, cp, &c.s_erases);
        if (status != BOOT_OK) goto cleanup;
      }
      i++;
    }
  }

  /* Completion: clear transport slots and persist (bitmap hygiene for
   * multi-image), anchor the final offset. */
  open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0;
  open_txn->transfer_bitmap[TOOB_TB_SLOT_AUX0] = 0;
  open_txn->transfer_bitmap[TOOB_TB_SLOT_AUX1] = 0;
  open_txn->delta_chunk_id = txn->length;
  status = boot_journal_append(platform, open_txn);
  if (status != BOOT_OK)
    goto cleanup;

  /* Best-effort wear telemetry. */
  if (c.p_erases > 0 || c.s_erases > 0) {
    wal_tmr_payload_t tmr __attribute__((aligned(8)));
    boot_secure_zeroize(&tmr, sizeof(tmr));
    if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
      if ((boot_dest_slot_t)txn->dest_slot == BOOT_DEST_SLOT_APP) {
        tmr.app_slot_erase_counter += c.p_erases;
        tmr.staging_slot_erase_counter += c.s_erases;
      } else {
        tmr.app_slot_erase_counter += c.s_erases;
        tmr.staging_slot_erase_counter += c.p_erases;
      }
      (void)boot_journal_update_tmr(platform, &tmr);
    }
    boot_secure_zeroize(&tmr, sizeof(tmr));
  }

cleanup:
  boot_secure_zeroize(arena, arena_len);
  return status;
}

/* Rollback: after a completed swap-move, the old app sits in the secondary —
 * the exchange is symmetric, so restoring is the SAME algorithm run again with
 * a fresh transaction (new -> secondary, old -> primary). */
static boot_status_t swapmove_rollback(const boot_platform_t *platform,
                                       const slot_caps_t *caps, slot_txn_t *txn,
                                       uint8_t *arena, size_t arena_len) {
  wal_entry_payload_t rb_txn __attribute__((aligned(8)));
  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  rb_txn.magic = WAL_ENTRY_MAGIC;
  rb_txn.intent = WAL_INTENT_TXN_ROLLBACK_PENDING;

  slot_txn_t rb = *txn;
  rb.src_verified = true; /* restoring the previously verified+booted image */

  boot_status_t status =
      swapmove_apply(platform, caps, &rb, &rb_txn, arena, arena_len);
  boot_secure_zeroize(&rb_txn, sizeof(rb_txn));
  return status;
}

const slot_transport_t g_toob_transport_swapmove = {
    .name = "swapmove",
    .tier = 2,
    .id = TOOB_TRANSPORT_ID_SWAPMOVE,
    .apply = swapmove_apply,
    .rollback = swapmove_rollback,
};

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPMOVE */