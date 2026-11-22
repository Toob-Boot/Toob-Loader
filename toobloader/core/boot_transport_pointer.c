/**
 * @file boot_transport_pointer.c
 * @brief Tier-0/1 provider: zero-copy commit — the execution address follows
 *        the image (C17).
 *
 * Intended path: toobloader/core/boot_transport_pointer.c     (Ticket ST-033)
 */

#include "boot_transport.h"

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER

#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_effect.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_secure_zeroize.h"
#include "boot_swap.h"
#include "generated_boot_config.h"
#include <stddef.h>
#include <string.h>

/* Read-back verification of a HW flip where the chip can report it. */
static boot_status_t verify_active(const slot_caps_t *caps, uint32_t expected_slot) {
  if (!caps->get_active_slot) {
    return BOOT_OK;
  }
  uint32_t active = 0xFFFFFFFFu;
  boot_status_t st = caps->get_active_slot(&active);
  if (st != BOOT_OK) {
    return st;
  }
  BOOT_SECURE_REQUIRE(active == expected_slot, { return BOOT_ERR_VERIFY; });
  return BOOT_OK;
}

/* Software boot pointer (Tier 1 & volatile HW remap): persisted via 3-sector TMR quorum. */
static boot_status_t sw_pointer_flip(const boot_platform_t *platform, uint32_t target_slot) {
#ifdef TOOB_TMR_HAS_ACTIVE_APP_SLOT
  wal_tmr_payload_t tmr __attribute__((aligned(8)));
  boot_secure_zeroize(&tmr, sizeof(tmr));

  boot_status_t st = boot_journal_get_tmr(platform, &tmr);
  if (st != BOOT_OK) {
    boot_secure_zeroize(&tmr, sizeof(tmr));
    return st;
  }
  tmr.active_app_slot = (uint8_t)target_slot;
  tmr.active_transport_id = TOOB_TRANSPORT_ID_POINTER;
  st = boot_journal_update_tmr(platform, &tmr);

  if (st == BOOT_OK) {
    wal_tmr_payload_t check __attribute__((aligned(8)));
    boot_secure_zeroize(&check, sizeof(check));
    st = boot_journal_get_tmr(platform, &check);
    if (st == BOOT_OK) {
      BOOT_SECURE_REQUIRE(check.active_app_slot == (uint8_t)target_slot, { st = BOOT_ERR_VERIFY; });
    }
    boot_secure_zeroize(&check, sizeof(check));
  }
  boot_secure_zeroize(&tmr, sizeof(tmr));
  return st;
#else
  (void)platform;
  (void)target_slot;
  return BOOT_ERR_NOT_SUPPORTED;
#endif
}

static boot_status_t pointer_commit(const boot_platform_t *platform, const slot_caps_t *caps,
                                    const slot_txn_t *txn, uint32_t target_slot) {
  boot_status_t status = BOOT_OK;
  switch (caps->exec_model) {
  case SLOT_EXEC_BANK_SWAP:
    if (!caps->ops.bank_swap.bank_flip) {
      return BOOT_ERR_NOT_SUPPORTED;
    }
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    {
      boot_status_t st = caps->ops.bank_swap.bank_flip(target_slot);
      if (st != BOOT_OK) {
        return st;
      }
    }
    status = verify_active(caps, target_slot);
    if (status == BOOT_OK) {
      status = sw_pointer_flip(platform, target_slot);
    }
    break;

  case SLOT_EXEC_XIP_REMAP:
    if (!caps->ops.xip_remap.xip_remap_commit) {
      return BOOT_ERR_NOT_SUPPORTED;
    }
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    {
      boot_status_t st = caps->ops.xip_remap.xip_remap_commit(txn->src_addr);
      if (st != BOOT_OK) {
        return st;
      }
    }
    status = verify_active(caps, target_slot);
    /* Persist active slot in TMR quorum when MMU remap is volatile across resets (e.g. ESP32). */
    if (status == BOOT_OK && caps->commit_persistence == SLOT_COMMIT_VOLATILE) {
      status = sw_pointer_flip(platform, target_slot);
    }
    break;

  case SLOT_EXEC_RELOCATABLE:
    if (caps->ops.relocatable.image_link_check && txn->length > 0u) {
      status = caps->ops.relocatable.image_link_check(txn->src_addr, txn->length);
      if (status != BOOT_OK) {
        return status;
      }
    }
    status = sw_pointer_flip(platform, target_slot);
    if (status == BOOT_OK && caps->ops.relocatable.exec_addr_select) {
      status = caps->ops.relocatable.exec_addr_select(txn->src_addr);
    }
    break;

  case SLOT_EXEC_FIXED:
  default:
    return BOOT_ERR_NOT_SUPPORTED;
  }

  if (status == BOOT_OK && platform && platform->soc) {
    if (platform->soc->flush_bus_matrix) {
      platform->soc->flush_bus_matrix();
    }
    if (platform->soc->invalidate_icache) {
      platform->soc->invalidate_icache();
    }
  }
  return status;
}

static boot_status_t pointer_apply(const boot_platform_t *platform, const slot_caps_t *caps,
                                   slot_txn_t *txn, wal_entry_payload_t *open_txn, uint8_t *arena,
                                   size_t arena_len) {
  if (!platform || !caps || !txn || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (caps->slot_count < 2) {
    return BOOT_ERR_NOT_SUPPORTED;
  }
  if (txn->target_slot_index > 1) {
    return BOOT_ERR_INVALID_ARG;
  }

  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });
  BOOT_SECURE_REQUIRE(txn->src_verified, { return BOOT_ERR_VERIFY; });

  TOOB_TXN_SET_TRANSPORT(open_txn, TOOB_TRANSPORT_ID_POINTER);

  /* If Delta/Decompression wrote to a temporary Scratch partition, copy to the
   * inactive bootable slot first and update txn->src_addr to that slot. */
  if (txn->src_is_delta_output) {
    uint32_t target_addr =
        (txn->target_slot_index == 0u) ? CHIP_APP_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;
    uint32_t target_size =
        (txn->target_slot_index == 0u) ? CHIP_APP_SLOT_SIZE : CHIP_STAGING_SLOT_SIZE;

    if (txn->length > target_size || UINT32_MAX - target_addr < txn->length) {
      return BOOT_ERR_FLASH_BOUNDS;
    }

    boot_allowed_region_t wl[1] = {{target_addr, target_size}};
    uint32_t erases = 0;

    boot_status_t st = boot_swap_copy_region_resumable(platform, txn->src_addr, target_addr,
                                                       txn->length, TOOB_PHASE_POINTER_COPY,
                                                       open_txn, wl, 1, &erases, arena, arena_len);
    if (st != BOOT_OK) {
      return st;
    }

    if (erases > 0) {
      uint32_t app_e = (txn->target_slot_index == 0u) ? erases : 0;
      uint32_t stg_e = (txn->target_slot_index == 0u) ? 0 : erases;
      (void)boot_swap_commit_wear(platform, app_e, stg_e, 0, arena, arena_len);
    }

    txn->src_addr = target_addr;
  }

  open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0;
  open_txn->delta_chunk_id = txn->length;
  boot_status_t status = boot_journal_append(platform, open_txn);
  if (status != BOOT_OK) {
    return status;
  }

  return pointer_commit(platform, caps, txn, (uint32_t)txn->target_slot_index);
}

static boot_status_t pointer_rollback(const boot_platform_t *platform, const slot_caps_t *caps,
                                      slot_txn_t *txn, uint8_t *arena, size_t arena_len) {
  (void)arena;
  (void)arena_len;
  if (!platform || !caps || !txn) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (caps->slot_count < 2 || txn->target_slot_index > 1) {
    return BOOT_ERR_NOT_SUPPORTED;
  }

  uint32_t previous_slot = (txn->target_slot_index == 0u) ? 1u : 0u;

  slot_txn_t back = *txn;
  back.target_slot_index = (uint8_t)previous_slot;
  back.src_addr = (previous_slot == 0u) ? CHIP_APP_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;
  back.length = 0u;

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
