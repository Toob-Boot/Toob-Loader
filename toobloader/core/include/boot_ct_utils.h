/**
 * @file boot_ct_utils.h
 * @brief Constant-Time Comparison Utilities (Glitch-Protected)
 *
 * Provides a single shared implementation of the glitch-resistant
 * constant-time memory comparison used across the Core. Previously
 * duplicated as static inline in 5 translation units.
 *
 * SECURITY CONTRACT:
 * - Dual-accumulator (forward + reverse) prevents single-bit fault bypass
 * - Double-check gating via BOOT_GLITCH_DELAY() resists voltage faults
 * - Constant-time: no early exit on first mismatch (timing side-channel safe)
 */

#ifndef BOOT_CT_UTILS_H
#define BOOT_CT_UTILS_H

#include "boot_types.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Glitch-resistant constant-time memory comparison.
 *
 * Compares `len` bytes of `a` and `b` in both forward and reverse direction.
 * Returns BOOT_OK only if both accumulators agree on a full match.
 *
 * @param a   First buffer
 * @param b   Second buffer
 * @param len Number of bytes to compare
 * @return BOOT_OK on match, BOOT_ERR_VERIFY on mismatch or fault
 */
static inline boot_status_t constant_time_memcmp_glitch_safe(const uint8_t *a,
                                                             const uint8_t *b,
                                                             size_t len) {
  /* P10 Fault-Injection Guard: A glitched len=0 must never yield BOOT_OK.
   * Without this, both accumulators stay 0 → shields pass → silent bypass. */
  if (len == 0)
    return BOOT_ERR_VERIFY;

  volatile uint32_t acc_fwd = 0;
  volatile uint32_t acc_rev = 0;

  for (size_t i = 0; i < len; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[len - 1 - i] ^ b[len - 1 - i]);
  }

  volatile uint32_t shield_1 = 0, shield_2 = 0;
  if (acc_fwd == 0)
    shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (shield_1 == BOOT_OK && acc_rev == 0)
    shield_2 = BOOT_OK;

  if (shield_1 == BOOT_OK && shield_2 == BOOT_OK && shield_1 == shield_2)
    return BOOT_OK;
  return BOOT_ERR_VERIFY;
}

#endif /* BOOT_CT_UTILS_H */
