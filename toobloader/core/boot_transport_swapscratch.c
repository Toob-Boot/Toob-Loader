/**
 * @file boot_transport_swapscratch.c
 * @brief Tier-4 fallback provider: adapter over the proven legacy swap (C17).
 *
 * Intended path: toobloader/core/boot_transport_swapscratch.c  (Ticket ST-030)
 *
 * BEHAVIOR-PRESERVING BY CONSTRUCTION: apply() delegates to boot_swap_apply(),
 * rollback() to boot_rollback_trigger_revert() — the exact code running today.
 * ST-030's bit-identical acceptance criterion is met because no swap logic is
 * duplicated; retiring boot_swap.c moves the code here in a later step.
 *
 * Two safety additions on top of the legacy behavior:
 *
 * 1. DELTA GUARD: the confirmed delta bug (SDVM output at CHIP_SCRATCH is also
 *    this provider's exchange buffer -> phase A erases the new image, and a
 *    later rollback copies the useless delta stream over the app). This
 *    provider therefore REFUSES delta-output sources; the TSM must route delta
 *    transactions to the oneway provider. The conflict is now unrepresentable
 *    instead of latent.
 *
 * 2. BITMAP CLEANUP: legacy swap leaves crc_src/crc_dest/shield in
 *    transfer_bitmap[0..2]; boot_multiimage_apply afterwards interprets those
 *    same words as component-completion bits — random CRC bits can silently
 *    skip components. After a successful apply we clear [0..2] and persist the
 *    cleaned txn with one WAL append, so multi-image never sees stale CRCs
 *    (fresh path AND resume path).
 */

#include "boot_transport.h"

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH

#include "boot_fih.h"
#include "boot_journal.h"
#include "boot_rollback.h"
#include "boot_secure_zeroize.h"
#include "boot_swap.h"
#include <stddef.h>

static boot_status_t swapscratch_apply(const boot_platform_t *platform,
                                       const slot_caps_t *caps,
                                       slot_txn_t *txn,
                                       wal_entry_payload_t *open_txn,
                                       uint8_t *arena, size_t arena_len) {
  (void)caps; /* legacy path needs no chip primitives */

  if (!platform || !txn || !open_txn || !arena)
    return BOOT_ERR_INVALID_ARG;

  /* Verify-before-destruction gate (uniform across all providers). */
  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });

  /* DELTA GUARD — see file header. Not a policy choice: with src ==
   * CHIP_SCRATCH the legacy 3-phase exchange is provably destructive. */
  if (txn->src_is_delta_output)
    return BOOT_ERR_NOT_SUPPORTED;

  TOOB_TXN_SET_TRANSPORT(open_txn, TOOB_TRANSPORT_ID_SWAPSCRATCH);

  boot_status_t status = boot_swap_apply(
      platform, txn->src_addr, txn->dest_addr, txn->length,
      (boot_dest_slot_t)txn->dest_slot, open_txn, arena, arena_len);
  if (status != BOOT_OK)
    return status;

  /* BITMAP CLEANUP — persist cleared [0..2] before multi-image runs. One extra
   * WAL append per update; intent stays untouched, only the deduction words
   * are cleared, so WAL semantics are unchanged. */
  if (open_txn->transfer_bitmap[0] != 0 || open_txn->transfer_bitmap[1] != 0 ||
      open_txn->transfer_bitmap[2] != 0) {
    open_txn->transfer_bitmap[0] = 0;
    open_txn->transfer_bitmap[1] = 0;
    open_txn->transfer_bitmap[2] = 0;
    status = boot_journal_append(platform, open_txn);
  }
  return status;
}

static boot_status_t swapscratch_rollback(const boot_platform_t *platform,
                                          const slot_caps_t *caps,
                                          slot_txn_t *txn,
                                          uint8_t *arena, size_t arena_len) {
  (void)caps;
  (void)txn; /* legacy revert derives everything from staging header + config */
  return boot_rollback_trigger_revert(platform, arena, arena_len);
}

const slot_transport_t g_toob_transport_swapscratch = {
    .name = "swapscratch",
    .tier = 4,
    .id = TOOB_TRANSPORT_ID_SWAPSCRATCH,
    .apply = swapscratch_apply,
    .rollback = swapscratch_rollback,
};

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH */