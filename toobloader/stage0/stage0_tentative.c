/**
 * @file stage0_tentative.c
 * @brief Trial-Boot and Anti-Endless-Loop
 *
 * Evaluates the hardware reset cause against a CRC-verified .noinit
 * toob_handoff_state snapshot to roll back tentative Stage 1 self-updates
 * on crash/panic resets without false triggers from power-on SRAM noise.
 */

#include "boot_crc32.h"
#include "boot_flash_guard.h"
#include "boot_hal.h"
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include "libtoob_types.h"
#include "stage0_crypto.h"
#include <stddef.h>

extern TOOB_NOINIT toob_handoff_t toob_handoff_state;

uint32_t stage0_evaluate_tentative(const boot_platform_t *platform, uint32_t current_slot) {
  if (!platform || !platform->clock || !platform->clock->get_reset_reason) {
    return current_slot;
  }
  reset_reason_t reason = platform->clock->get_reset_reason();

  toob_handoff_t snap __attribute__((aligned(8)));
  const volatile uint8_t *src = (const volatile uint8_t *)&toob_handoff_state;
  uint8_t *dst = (uint8_t *)&snap;
  for (size_t i = 0U; i < sizeof(snap); i++) {
    dst[i] = src[i];
  }

  bool valid_tentative = false;
  if (snap.magic == TOOB_STATE_TENTATIVE && snap.struct_version == TOOB_HANDOFF_STRUCT_VERSION) {
    uint32_t calc_crc =
        compute_boot_crc32((const uint8_t *)&snap, offsetof(toob_handoff_t, crc32_trailer));
    valid_tentative = (calc_crc == snap.crc32_trailer);
  }
  boot_secure_zeroize(&snap, sizeof(snap));

  if (valid_tentative && (reason == RESET_REASON_WATCHDOG || reason == RESET_REASON_HARD_FAULT ||
                          reason == RESET_REASON_BROWNOUT || reason == RESET_REASON_SOFTWARE)) {
    boot_secure_zeroize(&toob_handoff_state, sizeof(toob_handoff_state));
    __asm__ volatile("" ::: "memory");

    return (current_slot == CHIP_STAGE1A_ABS_ADDR) ? CHIP_STAGE1B_ABS_ADDR : CHIP_STAGE1A_ABS_ADDR;
  }
  return current_slot;
}
