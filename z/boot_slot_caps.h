/**
 * @file boot_slot_caps.h
 * @brief Chip slot capabilities — the ONLY thing a chip driver must declare.
 *
 * Intended path: common/include/boot_slot_caps.h        (Ticket ST-010)
 *
 * Shared between the Core and registry-installed chip drivers. A generic chip
 * driver is PURE DATA (one slot_caps_t instance, no code). Chips with special
 * hardware additionally provide the matching primitive (bank_flip on HW
 * dual-bank parts, xip_remap_commit on MMU-remap parts, exec_addr_select on
 * relocatable dual-slot parts). The Core carries all transport algorithms and
 * selects a provider at compile time from these capabilities.
 *
 * DEPENDENCY NOTE: needs boot_status_t. It is pulled from boot_types.h (the
 * base types header) — NOT from boot_hal.h, because boot_hal.h will include
 * this header (ST-015) and a cycle must be impossible.
 */

#ifndef BOOT_SLOT_CAPS_H
#define BOOT_SLOT_CAPS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "boot_types.h" /* boot_status_t */

/**
 * @brief How the chip executes firmware relative to physical flash addresses.
 * This single value drives the compile-time transport-provider selection.
 */
typedef enum {
  SLOT_EXEC_FIXED       = 0, /* image must run from one fixed physical address  */
  SLOT_EXEC_RELOCATABLE = 1, /* image can run from either slot (dual-linked/PIC) */
  SLOT_EXEC_XIP_REMAP   = 2, /* execution address is MMU-remappable (e.g. ESP32) */
  SLOT_EXEC_BANK_SWAP   = 3  /* hardware dual-bank flip (e.g. STM32 BFB2)        */
} slot_exec_model_t;

/**
 * @brief Capability sheet of one chip. Filled by the registry-installed driver
 *        (generated glue exposes it via boot_get_slot_caps()).
 *
 * Function pointers are NULL when the hardware does not support the primitive;
 * a NULL pointer simply makes the corresponding tier unavailable. All
 * primitives MUST be glitch-conscious on their side (single register writes
 * where possible) — the Core wraps every call in double-check shields anyway.
 */
typedef struct {
  slot_exec_model_t exec_model;
  uint8_t  slot_count;        /* bootable slots: 1 (in-place) or 2 (A/B)        */
  uint8_t  _pad[3];
  bool     has_scratch;       /* dedicated scratch/temp region present          */
  uint8_t  _pad2[3];
  uint32_t scratch_size;      /* bytes; 0 if none                               */
  uint32_t max_erase_cycles;  /* flash endurance; 0 = unknown (no EOL gating)   */

  /* ---- optional chip primitives (the thin driver delta) ---- */

  /** HW dual-bank flip. target_bank: 0/1. Must be atomic in hardware. */
  boot_status_t (*bank_flip)(uint32_t target_bank);

  /** Commit an XIP/MMU remap so slot_phys_addr becomes the execution window. */
  boot_status_t (*xip_remap_commit)(uint32_t slot_phys_addr);

  /** Select the execution entry for a relocatable image (e.g. VTOR base).
   *  Called by the Core at handoff time, not at commit time. */
  boot_status_t (*exec_addr_select)(uint32_t slot_phys_addr);

  /** Read back which slot/bank is active (HW tiers). out_slot: 0/1. */
  boot_status_t (*get_active_slot)(uint32_t *out_slot);
} slot_caps_t;

/* ABI guards: this struct crosses the Core/driver boundary. */
_Static_assert(sizeof(slot_exec_model_t) == sizeof(int),
               "slot_exec_model_t must have int size (enum ABI)");
_Static_assert(offsetof(slot_caps_t, scratch_size) % 4 == 0,
               "slot_caps_t scalar block must stay 4-aligned");

/**
 * @brief Provided by the generated driver glue (Registry/manifest compiler).
 * @return The chip's capability sheet. Never NULL in a correctly generated
 *         build; the Core still NULL-checks defensively.
 */
const slot_caps_t *boot_get_slot_caps(void);

#endif /* BOOT_SLOT_CAPS_H */