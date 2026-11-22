/**
 * @file toob_handoff.c
 * @brief Handoff Reader — reads bootloader diagnostic state from shared RAM.
 *
 * Validates and extracts the toob_handoff_t struct from the .noinit RAM
 * section. CRC-32 + magic verification with TOCTOU defense (local copy)
 * and glitch-resistant double-check patterns.
 */

#include "libtoob.h"
#include "toob_internal.h"
#include <string.h>

#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32) && !defined(__CYGWIN__)
#  define TOOB_WEAK __attribute__((weak))
#else
#  define TOOB_WEAK
#endif

/* ==============================================================================
 * Weak Default Concurrency Hooks (MED-23)
 * ==============================================================================
 * Single-threaded / bare-metal consumers link automatically with zero changes;
 * RTOS ports (FreeRTOS, Zephyr, ThreadX) may override with strong mutex hooks.
 * Note: PE/COFF (_WIN32) lacks ELF global weak definitions across TUs, so host
 * Windows builds emit regular defaults unless TOOB_CUSTOM_OS_LOCK is defined.
 */
#if !defined(_WIN32) && !defined(__CYGWIN__)
TOOB_WEAK void toob_os_lock(void) {}
TOOB_WEAK void toob_os_unlock(void) {}
#elif !defined(TOOB_CUSTOM_OS_LOCK)
void toob_os_lock(void) {}
void toob_os_unlock(void) {}
#endif

/* ==============================================================================
 * .noinit RAM Definition (GAP-39 / CRIT-26)
 * (Wird durch den Linker in die dedizierte .noinit.toob_handoff_state Sektion
 * gemappt)
 *
 * Arch-Note (Zero-Dependency): This library defines the OS-side boundary.
 * The Bootloader (S1) uses its own isolated definition. Since the OS and S1
 * are compiled into strictly separate binaries, there are no linker collisions.
 * ==============================================================================
 */
/* Arch-Note: Für Cross-Compilation Linker-Collisions (Unit Tests) */
#ifndef TOOB_MOCK_TEST
TOOB_NOINIT_VAR(toob_handoff_state) toob_handoff_t toob_handoff_state;
#endif

static void _volatile_snapshot_handoff(toob_handoff_t *dst) {
  const volatile uint8_t *src =
      (const volatile uint8_t *)&toob_handoff_state;
  uint8_t *out = (uint8_t *)dst;
  for (size_t i = 0U; i < sizeof(toob_handoff_t); i++) {
    out[i] = src[i];
  }
}

static bool _verify_handoff_snapshot(const toob_handoff_t *h) {
  bool magic_ok = (h->magic == TOOB_STATE_COMMITTED ||
                   h->magic == TOOB_STATE_TENTATIVE);
  bool version_ok = (h->struct_version == TOOB_HANDOFF_STRUCT_VERSION);
  if (!magic_ok || !version_ok) {
    return false;
  }
  size_t payload_len = offsetof(toob_handoff_t, crc32_trailer);
  uint32_t calc_crc = toob_lib_crc32((const uint8_t *)h, payload_len);
  return (calc_crc == h->crc32_trailer);
}

toob_status_t toob_get_handoff(toob_handoff_t *out_handoff) {
  /* P10 Pointer Zero-Trust Check */
  if (!out_handoff) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Snapshot 1 directly into caller buffer + single stack local_h2 (-80B stack, TDR1-07).
   * On any validation or glitch cross-check mismatch, out_handoff is zeroized before return. */
  toob_handoff_t local_h2 __attribute__((aligned(8)));
  toob_secure_zeroize(out_handoff, sizeof(toob_handoff_t));
  toob_secure_zeroize(&local_h2, sizeof(local_h2));

  _volatile_snapshot_handoff(out_handoff);

  volatile uint32_t shield_1 = 0U;
  volatile uint32_t shield_2 = 0U;

  if (_verify_handoff_snapshot(out_handoff)) {
    shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY();

  /* Snapshot 2: Independent volatile re-read + constant-time cross-check */
  _volatile_snapshot_handoff(&local_h2);

  if (shield_1 == TOOB_OK && _verify_handoff_snapshot(&local_h2) &&
      toob_ct_memcmp_glitch_safe((const uint8_t *)out_handoff,
                                 (const uint8_t *)&local_h2,
                                 sizeof(toob_handoff_t)) == TOOB_OK) {
    shield_2 = TOOB_OK;
  }

  toob_secure_zeroize(&local_h2, sizeof(local_h2));

  if (shield_1 != TOOB_OK || shield_2 != TOOB_OK || shield_1 != shield_2) {
    toob_secure_zeroize(out_handoff, sizeof(toob_handoff_t));
    return TOOB_ERR_VERIFY;
  }

  /* P10 Zero-Trust: Explicitly zeroize struct padding before exposing to OS */
  memset(out_handoff->_padding, 0, sizeof(out_handoff->_padding));
  return TOOB_OK;
}

toob_status_t toob_validate_handoff(void) {
  toob_handoff_t tmp __attribute__((aligned(8)));
  toob_status_t st = toob_get_handoff(&tmp);
  toob_secure_zeroize(&tmp, sizeof(tmp));
  return st;
}
