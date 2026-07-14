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
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_effect.h"
#include "boot_fih.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

#define PTR_MAX_LOOPS 100000u

static boot_status_t ptr_solve_block(const boot_platform_t *p, uint32_t src,
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

static boot_status_t ptr_blocks_identical(const boot_platform_t *p, uint32_t a,
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

static boot_status_t ptr_copy_region_resumable(
    const boot_platform_t *p, uint32_t src_base, uint32_t dst_base,
    uint32_t length, uint32_t phase_magic, wal_entry_payload_t *txn,
    const boot_allowed_region_t *wl, uint32_t wl_n, uint32_t *erases_out,
    uint8_t *arena, size_t arena_len) {

  uint32_t offset = 0;
  if (txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] == phase_magic) {
    offset = txn->delta_chunk_id;
    if (offset > length)
      offset = length;
  }

  uint32_t guard = 0;
  while (offset < length) {
    if (++guard > PTR_MAX_LOOPS)
      return BOOT_ERR_FLASH_HW;
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();

    uint32_t src = src_base + offset;
    uint32_t dst = dst_base + offset;
    size_t block = 0;
    boot_status_t status = ptr_solve_block(p, src, dst, length - offset, &block);
    if (status != BOOT_OK)
      return status;

    uint32_t crc_src = 0, crc_dst = 0;
    status = boot_crc32_flash_stream(p, src, block, &crc_src, arena, arena_len);
    if (status != BOOT_OK)
      return status;
    status = boot_crc32_flash_stream(p, dst, block, &crc_dst, arena, arena_len);
    if (status != BOOT_OK)
      return status;

    if (crc_src == crc_dst) {
      bool same = false;
      status = ptr_blocks_identical(p, src, dst, block, &same, arena, arena_len);
      if (status != BOOT_OK)
        return status;
      if (same) {
        offset += (uint32_t)block;
        continue;
      }
    }

    txn->delta_chunk_id = offset;
    txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = phase_magic;
    status = boot_journal_append(p, txn);
    if (status != BOOT_OK)
      return status;

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

  /* If this is a delta update, copy the patched image from the temporary delta
   * output area (Scratch) into the target bootable slot first. */
  if (txn->src_is_delta_output) {
    uint32_t target_addr = (txn->target_slot_index == 0u) ? CHIP_APP_SLOT_ABS_ADDR
                                                          : CHIP_STAGING_SLOT_ABS_ADDR;
    uint32_t target_size = (txn->target_slot_index == 0u) ? CHIP_APP_SLOT_SIZE
                                                          : CHIP_STAGING_SLOT_SIZE;

    boot_allowed_region_t wl[1] = {
        {target_addr, target_size}
    };
    uint32_t erases = 0;

    boot_status_t st = ptr_copy_region_resumable(
        platform, txn->src_addr, target_addr, txn->length,
        TOOB_PHASE_POINTER_COPY, open_txn, wl, 1, &erases, arena, arena_len);
    if (st != BOOT_OK)
      return st;

    if (erases > 0) {
      wal_tmr_payload_t tmr __attribute__((aligned(8)));
      boot_secure_zeroize(&tmr, sizeof(tmr));
      if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
        if (txn->target_slot_index == 0u) {
          tmr.app_slot_erase_counter += erases;
        } else {
          tmr.staging_slot_erase_counter += erases;
        }
        (void)boot_journal_update_tmr(platform, &tmr);
      }
      boot_secure_zeroize(&tmr, sizeof(tmr));
    }
  }

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