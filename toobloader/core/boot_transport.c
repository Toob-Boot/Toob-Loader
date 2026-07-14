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
#include "boot_slot_caps.h"
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

__attribute__((weak)) const slot_caps_t *boot_get_slot_caps(void) {
  static const slot_caps_t default_caps = {
      .exec_model = SLOT_EXEC_FIXED,
      .slot_count = 1,
      .has_scratch = true,
#ifdef CHIP_SCRATCH_SLOT_SIZE
      .scratch_size = CHIP_SCRATCH_SLOT_SIZE,
#else
      .scratch_size = 0,
#endif
      .max_erase_cycles = 100000u,
      .bank_flip = NULL,
      .xip_remap_commit = NULL,
      .exec_addr_select = NULL,
      .get_active_slot = NULL,
  };
  return &default_caps;
}