#ifndef TOOB_INTERNAL_H
#define TOOB_INTERNAL_H

/**
 * ==============================================================================
 * Toob-Boot libtoob: Internal Utilities (toob_internal.h)
 * ==============================================================================
 *
 * OS-side equivalent of the Bootloader's utility headers:
 * - boot_secure_zeroize.h  →  toob_secure_zeroize()
 * - boot_ct_utils.h        →  toob_ct_memcmp_glitch_safe()
 * - boot_types.h (GLITCH)  →  TOOB_GLITCH_DELAY()
 * - boot_crc32.h           →  toob_lib_crc32() (contract: toob_crc32_contract.h)
 *
 * ARCHITECTURE: libtoob must NEVER include bootloader-internal headers.
 * These are independent re-implementations that maintain Zero-Dependency
 * isolation while sharing the same security contract.
 */

#include "libtoob_types.h"
#include <stdint.h>
#include <stddef.h>

/* ==============================================================================
 * 1. Cross-Compiler Glitch-Delay Injection (Fault-Injection Defense)
 *
 * OS-side equivalent of BOOT_GLITCH_DELAY() from boot_types.h.
 * Inserts a NOP sled to resist voltage/clock faults that skip branch checks.
 * ============================================================================== */
#if defined(__GNUC__) || defined(__clang__)
  #define TOOB_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;" ::: "memory")
#elif defined(__ICCARM__)
  #include <intrinsics.h>
  #define TOOB_GLITCH_DELAY()                                                  \
    do {                                                                       \
      __no_operation();                                                        \
      __no_operation();                                                        \
      __no_operation();                                                        \
    } while (0)
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
  #define TOOB_GLITCH_DELAY()                                                  \
    do {                                                                       \
      __nop();                                                                 \
      __nop();                                                                 \
      __nop();                                                                 \
    } while (0)
#else
  #define TOOB_GLITCH_DELAY()                                                  \
    do {                                                                       \
      volatile uint32_t _delay = 0;                                            \
      _delay = 1;                                                              \
      (void)_delay;                                                            \
    } while (0)
#endif

/* ==============================================================================
 * 2. Secure Memory Zeroization (Anti-DCE)
 *
 * ABI-CONTRACT: Intentionally separate implementations exist:
 *   Core:  Assembly (boot_secure_zeroize.S) — DCE-proof by ISA guarantee.
 *   OS:    volatile + compiler barrier (below) — sufficient for RTOS guest
 *          context where the compiler is not cross-TU aware.
 * Both MUST zero exactly len bytes at ptr. Neither may return before completion.
 * ============================================================================== */
static inline void toob_secure_zeroize(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len--) {
    *p++ = 0;
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ volatile("" : : "g"(ptr) : "memory");
#endif
}

/* ==============================================================================
 * 3. Constant-Time Comparison (Glitch-Protected)
 *
 * OS-side equivalent of constant_time_memcmp_glitch_safe() from boot_ct_utils.h.
 * Dual-accumulator (forward + reverse) with double-check gating.
 *
 * SECURITY CONTRACT:
 * - No early exit on first mismatch (timing side-channel safe)
 * - len=0 is rejected (prevents glitched-length bypass)
 * - Double-check via TOOB_GLITCH_DELAY() resists voltage faults
 * ============================================================================== */
static inline toob_status_t toob_ct_memcmp_glitch_safe(const uint8_t *a,
                                                       const uint8_t *b,
                                                       size_t len) {
  if (len == 0)
    return TOOB_ERR_VERIFY;

  volatile uint32_t acc_fwd = 0;
  volatile uint32_t acc_rev = 0;

  for (size_t i = 0; i < len; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[len - 1 - i] ^ b[len - 1 - i]);
  }

  volatile uint32_t shield_1 = 0, shield_2 = 0;
  if (acc_fwd == 0)
    shield_1 = TOOB_OK;
  TOOB_GLITCH_DELAY();
  if (shield_1 == TOOB_OK && acc_rev == 0)
    shield_2 = TOOB_OK;

  if (shield_1 == TOOB_OK && shield_2 == TOOB_OK && shield_1 == shield_2)
    return TOOB_OK;
  return TOOB_ERR_VERIFY;
}

/* ==============================================================================
 * 4. CRC-32 (IEEE 802.3)
 *
 * OS-side equivalent of compute_boot_crc32() from boot_crc32.h.
 * Implementation lives in toob_crc32.c (not inlined due to table size).
 * ============================================================================== */
uint32_t toob_lib_crc32(const uint8_t *data, size_t length);

#include "toob_mailbox.h"

/* Private SDK Linkage: Hidden from public API to prevent unvalidated memory access */
extern TOOB_NOINIT toob_handoff_t toob_handoff_state;

#endif /* TOOB_INTERNAL_H */
