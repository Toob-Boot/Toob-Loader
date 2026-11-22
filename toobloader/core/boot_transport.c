/**
 * @file boot_transport.c
 * @brief Selection glue: binds exactly one transport provider (C17).
 *
 * Intended path: toobloader/core/boot_transport.c            (Ticket ST-020)
 *
 * Each provider translation unit self-gates on TOOB_TRANSPORT_PROVIDER, so the
 * unselected providers do not even compile — stronger than --gc-sections and
 * lets the whole provider set land in-tree today while only the default
 * (swapscratch, behavior-preserving) is active.
 */

#include "boot_transport.h"
#include "boot_flash_guard.h"
#include "boot_journal.h"
#include "boot_slot_caps.h"
#include "generated_boot_config.h"
#include <stddef.h>

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH
extern const slot_transport_t g_toob_transport_swapscratch;
#define TOOB_ACTIVE_TRANSPORT (&g_toob_transport_swapscratch)
#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY
extern const slot_transport_t g_toob_transport_oneway;
#define TOOB_ACTIVE_TRANSPORT (&g_toob_transport_oneway)
#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPMOVE
extern const slot_transport_t g_toob_transport_swapmove;
#define TOOB_ACTIVE_TRANSPORT (&g_toob_transport_swapmove)
#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
extern const slot_transport_t g_toob_transport_pointer;
#define TOOB_ACTIVE_TRANSPORT (&g_toob_transport_pointer)
#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPOFFSET
extern const slot_transport_t g_toob_transport_swapoffset;
#define TOOB_ACTIVE_TRANSPORT (&g_toob_transport_swapoffset)
#else
#error "TOOB_TRANSPORT_PROVIDER: unknown provider selection"
#endif

const slot_transport_t *boot_transport_active(void) {
  return TOOB_ACTIVE_TRANSPORT;
}

const slot_transport_t *boot_transport_by_id(uint8_t id) {
  /* Resume safety (ST-041): a WAL transaction begun by a different provider
   * than the one compiled in must NOT be continued by guesswork. */
  const slot_transport_t *t = TOOB_ACTIVE_TRANSPORT;
  return (t->id == id) ? t : NULL;
}

boot_status_t boot_transport_resolve_active(const boot_platform_t *platform, uint8_t *active_slot,
                                            uint32_t *boot_addr) {
  if (!active_slot || !boot_addr) {
    return BOOT_ERR_INVALID_ARG;
  }
  const slot_caps_t *caps =
      (platform && platform->slot_caps) ? platform->slot_caps : boot_get_slot_caps();
  if (!caps) {
    *active_slot = 0;
    *boot_addr = CHIP_APP_SLOT_ABS_ADDR;
    return BOOT_OK;
  }

  switch (caps->exec_model) {
  case SLOT_EXEC_BANK_SWAP: {
    uint32_t active = 0;
    if (caps->commit_persistence == SLOT_COMMIT_VOLATILE) {
      wal_tmr_payload_t tmr;
      if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK && tmr.active_app_slot <= 1u) {
        *active_slot = tmr.active_app_slot;
      } else {
        *active_slot = 0;
      }
    } else if (caps->get_active_slot && caps->get_active_slot(&active) == BOOT_OK && active <= 1u) {
      *active_slot = (uint8_t)active;
    } else {
      *active_slot = 0;
    }
    *boot_addr = (*active_slot == 0) ? CHIP_APP_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;
    return BOOT_OK;
  }
  case SLOT_EXEC_XIP_REMAP: {
    /* For VOLATILE MMU hardware (e.g. ESP32), TMR active_app_slot is the persistent
     * source of truth across resets; boot_addr returns the physical flash slot base. */
    uint32_t active = 0;
    if (caps->commit_persistence == SLOT_COMMIT_VOLATILE) {
      wal_tmr_payload_t tmr;
      if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK && tmr.active_app_slot <= 1u) {
        *active_slot = tmr.active_app_slot;
      } else {
        *active_slot = 0;
      }
    } else if (caps->get_active_slot && caps->get_active_slot(&active) == BOOT_OK && active <= 1u) {
      *active_slot = (uint8_t)active;
    } else {
      wal_tmr_payload_t tmr;
      if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK && tmr.active_app_slot <= 1u) {
        *active_slot = tmr.active_app_slot;
      } else {
        *active_slot = 0;
      }
    }
    *boot_addr = (*active_slot == 0) ? CHIP_APP_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;
    return BOOT_OK;
  }
  case SLOT_EXEC_RELOCATABLE: {
    wal_tmr_payload_t tmr;
    if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK && tmr.active_app_slot <= 1u) {
      *active_slot = tmr.active_app_slot;
    } else {
      *active_slot = 0;
    }
    *boot_addr = (*active_slot == 0) ? CHIP_APP_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;
    return BOOT_OK;
  }
  case SLOT_EXEC_FIXED:
  default:
    *active_slot = 0;
    *boot_addr = CHIP_APP_SLOT_ABS_ADDR;
    return BOOT_OK;
  }
}

boot_status_t boot_transport_reassert(const boot_platform_t *platform, uint8_t active_slot) {
  const slot_caps_t *caps =
      (platform && platform->slot_caps) ? platform->slot_caps : boot_get_slot_caps();
  if (!caps) {
    return BOOT_OK;
  }

  uint32_t slot_phys = (active_slot == 0) ? CHIP_APP_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;

  if (caps->exec_model == SLOT_EXEC_BANK_SWAP) {
    if (active_slot > 1U) {
      return BOOT_ERR_INVALID_ARG;
    }
    if (caps->commit_persistence == SLOT_COMMIT_VOLATILE && caps->ops.bank_swap.bank_flip) {
      boot_status_t st = caps->ops.bank_swap.bank_flip(active_slot);
      if (st != BOOT_OK) {
        return st;
      }
    }
  } else if (caps->exec_model == SLOT_EXEC_XIP_REMAP) {
    if (caps->commit_persistence == SLOT_COMMIT_VOLATILE && caps->ops.xip_remap.xip_remap_commit) {
      boot_status_t st = caps->ops.xip_remap.xip_remap_commit(slot_phys);
      if (st != BOOT_OK) {
        return st;
      }
    }
  } else if (caps->exec_model == SLOT_EXEC_RELOCATABLE) {
    if (caps->ops.relocatable.exec_addr_select) {
      boot_status_t st = caps->ops.relocatable.exec_addr_select(slot_phys);
      if (st != BOOT_OK) {
        return st;
      }
    }
  }

  /* Cache & Pipeline Coherence Barrier (Cortex-M7/M55/Xtensa/RISC-V) */
  if (platform && platform->soc) {
    if (platform->soc->flush_bus_matrix) {
      platform->soc->flush_bus_matrix();
    }
    if (platform->soc->invalidate_icache) {
      platform->soc->invalidate_icache();
    }
  }
  return BOOT_OK;
}

#ifndef TOOB_CUSTOM_SLOT_CAPS
__attribute__((weak)) const slot_caps_t *boot_get_slot_caps(void) {
  static const slot_caps_t default_caps =
      TOOB_SLOT_CAPS_FIXED(1, .has_scratch = true,
#ifdef CHIP_SCRATCH_SLOT_SIZE
                           .scratch_size = CHIP_SCRATCH_SLOT_SIZE,
#endif
                           .max_erase_cycles = 100000u, );
  return &default_caps;
}
#endif