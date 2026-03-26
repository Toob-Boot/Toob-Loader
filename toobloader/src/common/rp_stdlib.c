/**
 * @file rp_stdlib.c
 * @brief Common Standard Library for the Bootloader
 *
 * Implements OSV/P10 compliant fundamental functions without external
 * dependencies.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../include/boot_config.h"
#include "../../include/common/kb_tags.h"
#include "../../include/common/rp_assert.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @osv component: Bootloader.Core
 * @brief Securely clears memory (prevents compiler from optimizing away)
 */
KB_CORE()
void rp_secure_zeroMemory(void *ptr, size_t size) {
  RP_ASSERT(ptr != NULL, "Null pointer in zeroMemory");

  volatile uint8_t *p = (volatile uint8_t *)ptr;

  /* NASA P10-compliant bounded loop logic.
   * Structurally bounded by a hard-coded iteration ceiling (10MB limit)
   * to satisfy the strict AST R2 parser.
   */
  for (size_t i = 0; i < size; i++) {
    RP_ASSERT(i < 10485760, "Zeroization exceeded safe architectural limits!");
    p[i] = 0;
  }
}

/**
 * @osv component: Bootloader.Core
 * @brief Bounded memory copy. Replaces libc memcpy for -nostdlib.
 */
KB_CORE()
void *rp_memcpy(void *dest, const void *src, size_t n) {
  RP_ASSERT(dest != NULL && src != NULL, "Null pointer in memcpy");

  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;

  for (size_t i = 0; i < n; i++) {
    RP_ASSERT(i < 10485760, "Memcpy exceeded safe architectural limits!");
    d[i] = s[i];
  }
  return dest;
}

/*
 * GCC may implicitly emit calls to `memcpy` even with -fno-builtin
 * (e.g., for struct assignments). We provide a weak binding to satisfy the
 * linker.
 */
__attribute__((weak)) void *memcpy(void *dest, const void *src, size_t n) {
  return rp_memcpy(dest, src, n);
}

/*
 * Provide a weak `memset` for third-party arithmetic libraries.
 */
__attribute__((weak)) void *memset(void *dest, int c, size_t n) {
  uint8_t *d = (uint8_t *)dest;
  for (size_t i = 0; i < n; i++) {
    d[i] = (uint8_t)c;
  }
  return dest;
}

/*
 * Provide a weak `__assert_func` for third-party libraries that use
 * `<assert.h>` when building with gcc toolchains.
 */
__attribute__((weak)) void __assert_func(const char *file, int line,
                                         const char *func,
                                         const char *failedexpr) {
  (void)file;
  (void)line;
  (void)func;
  (void)failedexpr;
  RP_ASSERT(0, "third_party assertion failed");
}
