/**
 * @file boot_transport_pointer.c
 * @brief Tier-0/1 provider: zero-copy commit — the execution address follows
 *        the image (C17).
 *
 * Intended path: toobloader/core/boot_transport_pointer.c     (Ticket ST-033)
 *
 * PRINCIPLE: the new image is already resident AND verified in the target slot
 * (staging == the other bootable slot; the delta VM writes there directly).
 * apply() therefore moves ZERO bytes — it only commits the flip:
 *
 *   SLOT_EXEC_BANK_SWAP   -> caps->bank_flip(target)      (HW register, atomic)
 *   SLOT_EXEC_XIP_REMAP   -> caps->xip_remap_commit(src)  (MMU window)
 *   SLOT_EXEC_RELOCATABLE -> tmr.active_app_slot = target (TMR quorum = the
 *                            software boot pointer; requires ST-013)
 *   SLOT_EXEC_FIXED       -> BOOT_ERR_NOT_SUPPORTED (wrong provider selected)
 *
 * Wear: 1 erase + 1 write per NEW sector (the unavoidable staging write, done
 * upstream) and ZERO transport overhead. Rollback = flip back (0 wear, O(1)).
 *
 * COMMIT SEMANTICS: the flip is the single atomic commit point. Brownout
 * before it -> the old pointer survives (HW register / TMR quorum rotation)
 * and the old image boots. Brownout after -> the new verified image boots.
 * There is no intermediate state, which is why this tier needs no per-sector
 * resume logic at all.
 *
 * GLITCH MODEL: the flip DECISION is double-checked (BOOT_SECURE_REQUIRE on
 * the verify gate and on the target computation), and the flip RESULT is
 * read back via get_active_slot where the hardware offers it.
 */

#include "boot_transport.h"

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER

#include "generated_boot_config.h"
#include "boot_fih.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>

/* Read-back verification of a HW flip where the chip can report it. */
static boot_status_t verify_active(const slot_caps_t *caps,
                                   uint32_t expected_slot) {
  if (!caps->get_active_slot)
    return BOOT_OK; /* chip cannot report — primitive contract must be atomic */
  uint32_t active = 0xFFFFFFFFu;
  boot_status_t st = caps->get_active_slot(&active);
  if (st != BOOT_OK)
    return st;
  BOOT_SECURE_REQUIRE(active == expected_slot, { return BOOT_ERR_VERIFY; });
  return BOOT_OK;
}

/* Software boot pointer (Tier 1): the TMR is already the brownout-safe A/B
 * quorum store — the active-slot field lives there (ST-013), no parallel
 * pointer region. Compile-gated so bank/MMU chips build before ST-013 lands. */
static boot_status_t sw_pointer_flip(const boot_platform_t *platform,
                                     uint32_t target_slot) {
#ifdef TOOB_TMR_HAS_ACTIVE_APP_SLOT
  wal_tmr_payload_t tmr __attribute__((aligned(8)));
  boot_secure_zeroize(&tmr, sizeof(tmr));

  boot_status_t st = boot_journal_get_tmr(platform, &tmr);
  if (st != BOOT_OK) {
    boot_secure_zeroize(&tmr, sizeof(tmr));
    return st;
  }
  tmr.active_app_slot = (uint8_t)target_slot;
  st = boot_journal_update_tmr(platform, &tmr);

  /* Read-back: the flip must be observable before we report commit. */
  if (st == BOOT_OK) {
    wal_tmr_payload_t check __attribute__((aligned(8)));
    boot_secure_zeroize(&check, sizeof(check));
    st = boot_journal_get_tmr(platform, &check);
    if (st == BOOT_OK) {
      BOOT_SECURE_REQUIRE(check.active_app_slot == (uint8_t)target_slot,
                          { st = BOOT_ERR_VERIFY; });
    }
    boot_secure_zeroize(&check, sizeof(check));
  }
  boot_secure_zeroize(&tmr, sizeof(tmr));
  return st;
#else
  /* ST-013 not integrated yet: the relocatable software pointer cannot be
   * persisted. Fail loud and honest instead of pretending to commit. */
  (void)platform;
  (void)target_slot;
  return BOOT_ERR_NOT_SUPPORTED;
#endif
}

static boot_status_t pointer_commit(const boot_platform_t *platform,
                                    const slot_caps_t *caps,
                                    const slot_txn_t *txn,
                                    uint32_t target_slot) {
  switch (caps->exec_model) {
  case SLOT_EXEC_BANK_SWAP:
    if (!caps->bank_flip)
      return BOOT_ERR_NOT_SUPPORTED;
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    {
      boot_status_t st = caps->bank_flip(target_slot);
      if (st != BOOT_OK)
        return st;
    }
    return verify_active(caps, target_slot);

  case SLOT_EXEC_XIP_REMAP:
    if (!caps->xip_remap_commit)
      return BOOT_ERR_NOT_SUPPORTED;
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    {
      boot_status_t st = caps->xip_remap_commit(txn->src_addr);
      if (st != BOOT_OK)
        return st;
    }
    return verify_active(caps, target_slot);

  case SLOT_EXEC_RELOCATABLE:
    return sw_pointer_flip(platform, target_slot);

  case SLOT_EXEC_FIXED:
  default:
    /* A fixed-address chip cannot follow the image — codegen must never
     * select this provider for it. */
    return BOOT_ERR_NOT_SUPPORTED;
  }
}

static boot_status_t pointer_apply(const boot_platform_t *platform,
                                   const slot_caps_t *caps, slot_txn_t *txn,
                                   wal_entry_payload_t *open_txn,
                                   uint8_t *arena, size_t arena_len) {
  (void)arena;
  (void)arena_len;
  if (!platform || !caps || !txn || !open_txn)
    return BOOT_ERR_INVALID_ARG;
  if (caps->slot_count < 2)
    return BOOT_ERR_NOT_SUPPORTED;
  if (txn->target_slot_index > 1)
    return BOOT_ERR_INVALID_ARG;

  /* THE verify-before-flip gate. On this tier it is the whole safety story:
   * the flip makes the image live instantly, so nothing unverified may pass.
   * Double-checked (EMFI skip protection). */
  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });
  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });

  TOOB_TXN_SET_TRANSPORT(open_txn, TOOB_TRANSPORT_ID_POINTER);

  /* Anchor the intent BEFORE the flip: a brownout between append and flip
   * resumes here and simply re-commits (the flip is idempotent). */
  open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0;
  open_txn->delta_chunk_id = txn->length;
  boot_status_t status = boot_journal_append(platform, open_txn);
  if (status != BOOT_OK)
    return status;

  return pointer_commit(platform, caps, txn, (uint32_t)txn->target_slot_index);
}

static boot_status_t pointer_rollback(const boot_platform_t *platform,
                                      const slot_caps_t *caps, slot_txn_t *txn,
                                      uint8_t *arena, size_t arena_len) {
  (void)arena;
  (void)arena_len;
  if (!platform || !caps || !txn)
    return BOOT_ERR_INVALID_ARG;
  if (caps->slot_count < 2 || txn->target_slot_index > 1)
    return BOOT_ERR_NOT_SUPPORTED;

  /* Rollback = flip to the OTHER slot; the previous image never moved. The
   * txn still names the slot that was activated, so the rollback target is
   * its complement. src for XIP remap: the previous image's base = dest_addr
   * (the slot that was active before apply). */
  uint32_t previous_slot = (txn->target_slot_index == 0u) ? 1u : 0u;

  slot_txn_t back = *txn;
  back.target_slot_index = (uint8_t)previous_slot;
  back.src_addr = txn->dest_addr;

  return pointer_commit(platform, caps, &back, previous_slot);
}

const slot_transport_t g_toob_transport_pointer = {
    .name = "pointer",
    .tier = 0,
    .id = TOOB_TRANSPORT_ID_POINTER,
    .apply = pointer_apply,
    .rollback = pointer_rollback,
};

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER */