#ifndef TOOB_BOOT_SECURE_ZEROIZE_H
#define TOOB_BOOT_SECURE_ZEROIZE_H

#include <stddef.h>

/**
 * @brief O(1) Memory Zeroization (P10 Compliant)
 *
 * ABI-CONTRACT: Intentionally separate implementations exist:
 *   Core:  Assembly (boot_secure_zeroize.S) — DCE-proof by ISA guarantee.
 *   OS:    volatile + compiler barrier in toob_internal.h — sufficient for
 *          RTOS guest context where the compiler is not cross-TU aware.
 * Both MUST zero exactly len bytes at ptr. Neither may return before completion.
 *
 * @param ptr Pointer to the SRAM material to be destroyed
 * @param len Number of bytes to zero
 */
void boot_secure_zeroize(void* ptr, size_t len);

#endif /* TOOB_BOOT_SECURE_ZEROIZE_H */
