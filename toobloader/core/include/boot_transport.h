/**
 * @file boot_transport.h
 * @brief Compile-time transport-provider selection (Core side).
 *
 * Intended path: toobloader/core/include/boot_transport.h   (Ticket ST-020)
 *
 * The chip is fixed at build time, so the provider is too: the manifest
 * compiler derives TOOB_TRANSPORT_PROVIDER from the driver's slot_caps_t and
 * emits it into generated_boot_config.h. Exactly ONE provider translation unit
 * carries code (each provider .c self-gates on this macro); the interface stays
 * clean while unused strategies cost zero flash.
 */

#ifndef BOOT_TRANSPORT_H
#define BOOT_TRANSPORT_H

#include "boot_slot_transport.h"
#include "generated_boot_config.h"

/* Selection values (compile-time). Distinct from the wire-stable
 * TOOB_TRANSPORT_ID_* on purpose: these may be reordered, the IDs never. */
#ifndef TOOB_TRANSPORT_SWAPSCRATCH
#define TOOB_TRANSPORT_SWAPSCRATCH 1
#define TOOB_TRANSPORT_ONEWAY 2
#define TOOB_TRANSPORT_SWAPMOVE 3
#define TOOB_TRANSPORT_POINTER 4
#define TOOB_TRANSPORT_SWAPOFFSET 5
#endif

/* Oneway backup modes */
#ifndef TOOB_ONEWAY_BACKUP_NONE
#define TOOB_ONEWAY_BACKUP_NONE 0
#define TOOB_ONEWAY_BACKUP_FULL 1
#define TOOB_ONEWAY_BACKUP_REVERSE_DELTA 2
#endif

_Static_assert(TOOB_TRANSPORT_SWAPSCRATCH == 1 && TOOB_TRANSPORT_ONEWAY == 2 &&
                   TOOB_TRANSPORT_SWAPMOVE == 3 && TOOB_TRANSPORT_POINTER == 4 &&
                   TOOB_TRANSPORT_SWAPOFFSET == 5,
               "Transport provider selection ID drift");

#ifndef TOOB_ONEWAY_BACKUP_MODE
#define TOOB_ONEWAY_BACKUP_MODE TOOB_ONEWAY_BACKUP_FULL
#endif

/* Codegen emits this into generated_boot_config.h from slot_caps_t:
 *   exec_model BANK_SWAP/XIP_REMAP, or RELOCATABLE+2 slots -> POINTER
 *   FIXED + staging + secondary                            -> ONEWAY
 *   FIXED + 1.x slot (spare sector)                        -> SWAPMOVE / SWAPOFFSET
 *   otherwise                                              -> SWAPSCRATCH
 * Safe default: the legacy-equivalent fallback. */
#ifndef TOOB_TRANSPORT_PROVIDER
#define TOOB_TRANSPORT_PROVIDER TOOB_TRANSPORT_SWAPSCRATCH
#endif

/** @return The one compiled-in provider. Never NULL. */
const slot_transport_t *boot_transport_active(void);

extern const slot_transport_t g_toob_transport_swapscratch;
extern const slot_transport_t g_toob_transport_oneway;
extern const slot_transport_t g_toob_transport_swapmove;
extern const slot_transport_t g_toob_transport_swapoffset;
extern const slot_transport_t g_toob_transport_pointer;

/**
 * @brief Resume dispatch (ST-041): a resumed WAL transaction names the provider
 *        that began it via its stable id.
 * @return The active provider iff `id` matches it, else NULL — a mismatch means
 *         the build changed mid-transaction; the caller must abort safely, not
 *         guess.
 */
const slot_transport_t *boot_transport_by_id(uint8_t id);

/**
 * @brief Resolves which slot (0 or 1) and address is currently active for booting.
 */
boot_status_t boot_transport_resolve_active(const boot_platform_t *platform, uint8_t *active_slot,
                                            uint32_t *boot_addr);

/**
 * @brief Re-asserts volatile transport hardware state before OS handoff.
 */
boot_status_t boot_transport_reassert(const boot_platform_t *platform, uint8_t active_slot);

/* Fallback configuration for delta VM output addresses and sizes (ST-016 / ST-024) */
#ifndef TOOB_DELTA_OUTPUT_ADDR
#if defined(CHIP_SCRATCH_SLOT_SIZE) && (CHIP_SCRATCH_SLOT_SIZE > 0)
#define TOOB_DELTA_OUTPUT_ADDR CHIP_SCRATCH_SLOT_ABS_ADDR
#define TOOB_DELTA_OUTPUT_SIZE CHIP_SCRATCH_SLOT_SIZE
#else
#define TOOB_DELTA_OUTPUT_ADDR CHIP_STAGING_SLOT_ABS_ADDR
#define TOOB_DELTA_OUTPUT_SIZE CHIP_STAGING_SLOT_SIZE
#endif
#endif

#endif /* BOOT_TRANSPORT_H */
