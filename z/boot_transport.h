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

/* Selection values (compile-time). Distinct from the wire-stable
 * TOOB_TRANSPORT_ID_* on purpose: these may be reordered, the IDs never. */
#define TOOB_TRANSPORT_SWAPSCRATCH 1
#define TOOB_TRANSPORT_ONEWAY      2
#define TOOB_TRANSPORT_SWAPMOVE    3
#define TOOB_TRANSPORT_POINTER     4

/* Codegen emits this into generated_boot_config.h from slot_caps_t:
 *   exec_model BANK_SWAP/XIP_REMAP, or RELOCATABLE+2 slots -> POINTER
 *   FIXED + staging + secondary                            -> ONEWAY
 *   FIXED + 1.x slot (spare sector)                        -> SWAPMOVE
 *   otherwise                                              -> SWAPSCRATCH
 * Safe default: the legacy-equivalent fallback. */
#ifndef TOOB_TRANSPORT_PROVIDER
#define TOOB_TRANSPORT_PROVIDER TOOB_TRANSPORT_SWAPSCRATCH
#endif

/** @return The one compiled-in provider. Never NULL. */
const slot_transport_t *boot_transport_active(void);

/**
 * @brief Resume dispatch (ST-041): a resumed WAL transaction names the provider
 *        that began it via its stable id.
 * @return The active provider iff `id` matches it, else NULL — a mismatch means
 *         the build changed mid-transaction; the caller must abort safely, not
 *         guess.
 */
const slot_transport_t *boot_transport_by_id(uint8_t id);

#endif /* BOOT_TRANSPORT_H */