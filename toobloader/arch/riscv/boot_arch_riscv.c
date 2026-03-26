/**
 * @file boot_arch_riscv.c
 * @brief Bootloader Architecture Shim — RISC-V Specific
 *
 * Implements architecture-specific instructions like standard
 * nop delays and hardware barriers for RISC-V processors
 * (e.g., ESP32-C3/C6).
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../include/common/kb_tags.h"
#include <stdint.h>

/**
 * @osv
 * component: Bootloader.Arch
 * tag_status: auto
 */
KB_CORE()
void boot_arch_delay_nop(uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    __asm__ volatile("nop" ::: "memory");
  }
}

/**
 * @osv
 * component: Bootloader.Arch
 * tag_status: auto
 */
KB_CORE()
__attribute__((noreturn)) void boot_arch_halt(void) {
  for (;;) {
    __asm__ volatile("wfi" ::: "memory");
  }
}

/**
 * @osv
 * component: Bootloader.Arch
 * tag_status: auto
 */
/* @osv-ignore: r9_pointer_safety (Deliberate Architecture Exception) */
KB_CORE()
__attribute__((noreturn)) void boot_arch_jump(uint32_t final_entry_addr) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
  typedef void (*entry_fn_t)(void);
  entry_fn_t kernel_entry = (entry_fn_t)(uintptr_t)final_entry_addr;
#pragma GCC diagnostic pop
  kernel_entry();
  boot_arch_halt(); /* Should never return */
}
