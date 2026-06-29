#ifndef TOOB_BOOT_SECURE_ZEROIZE_H
#define TOOB_BOOT_SECURE_ZEROIZE_H

#include <stddef.h>

/**
 * @brief O(1) Memory Zeroization (P10 Compliant)
 * 
 * Verhindert, dass moderne C-Compiler (GCC/Clang) sicherheitskritische 
 * memset(0) Aufrufe am Ende von Funktionen wegoptimieren (DCE: Dead Code Elimination).
 * Zwingend vorgeschrieben in hals.md für alle Crypto-Materialien (Key-Residuen).
 * 
 * @param ptr Pointer auf das zu vernichtende SRAM-Material
 * @param len Anzahl der zu nullenden Bytes
 */
void boot_secure_zeroize(void* ptr, size_t len);

#endif /* TOOB_BOOT_SECURE_ZEROIZE_H */
