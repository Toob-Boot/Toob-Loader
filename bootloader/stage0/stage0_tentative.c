/**
 * @file stage0_tentative.c
 * @brief Trial-Boot and Anti-Endless-Loop
 *
 * Trial-Boot Logic for Self-Updates and Anti-Endless-Loop by evaluating the
 * RESET_REASON register against the TOOB_STATE_TENTATIVE flag.
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_hal.h"
#include "libtoob_types.h"
#include "stage0_crypto.h"
#include "generated_boot_config.h"

extern TOOB_NOINIT toob_handoff_t toob_handoff_state;

uint32_t stage0_evaluate_tentative(const boot_platform_t *platform,
                                   uint32_t current_slot) {
  if (!platform || !platform->clock || !platform->clock->get_reset_reason)
    return current_slot;
  reset_reason_t reason = platform->clock->get_reset_reason();

  /* Wenn S1 im Tentative-Modus war und gecrasht ist... */
  if (toob_handoff_state.magic == TOOB_STATE_TENTATIVE) {
    if (reason == RESET_REASON_WATCHDOG || reason == RESET_REASON_HARD_FAULT ||
        reason == RESET_REASON_BROWNOUT) {
      /* 1. Atomares Zeroize des RTC-Flags (Anti-Death-Loop) */
      toob_handoff_state.magic = 0x00000000;
      __asm__ volatile("" ::: "memory");

      /* 2. Physischer Rollback auf die vorherige Bank */
      return (current_slot == CHIP_STAGE1A_ABS_ADDR)
                 ? CHIP_STAGE1B_ABS_ADDR
                 : CHIP_STAGE1A_ABS_ADDR;
    }
  }
  return current_slot;
}