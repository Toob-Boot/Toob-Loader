/**
 * @file slot_caps_reference.c
 * @brief Reference chip driver: the PURE-DATA case (C17).
 *
 * Intended path: drivers/reference/slot_caps_reference.c
 *
 * This is the entire slot driver for a generic fixed-address, single-slot
 * MCU with a scratch region — the most constrained chip class. Note what is
 * ABSENT: no code, no algorithms, no flash logic. The Core's compile-time-
 * selected provider (here: swapscratch or oneway) does all the work; this
 * file only DECLARES what the silicon can do.
 *
 * Richer chips extend exactly one dimension each:
 *   - STM32 dual-bank : exec_model = SLOT_EXEC_BANK_SWAP, slot_count = 2,
 *                       plus a ~30-line bank_flip() touching FLASH_OPTR/BFB2
 *                       and a get_active_slot() reading the same register.
 *   - ESP32-C6        : exec_model = SLOT_EXEC_XIP_REMAP, slot_count = 2,
 *                       plus xip_remap_commit() programming the flash MMU.
 *   - Cortex-M A/B    : exec_model = SLOT_EXEC_RELOCATABLE, slot_count = 2,
 *                       plus exec_addr_select() writing VTOR at handoff.
 *
 * In production this file is registry-installed per chip and the accessor
 * below is emitted by the manifest compiler into generated_slot_caps.c; the
 * hand-written reference exists so ST-010's "includable from a dummy driver"
 * acceptance criterion is testable in-tree.
 */

#include "boot_slot_caps.h"
#include "generated_boot_config.h"
#include <stddef.h>

static const slot_caps_t g_reference_caps =
    TOOB_SLOT_CAPS_FIXED(
        1,
        .has_scratch = true,
#ifdef CHIP_SCRATCH_SLOT_SIZE
        .scratch_size = CHIP_SCRATCH_SLOT_SIZE,
#endif
        .max_erase_cycles = 100000u,
    );

const slot_caps_t *boot_get_slot_caps(void) { return &g_reference_caps; }