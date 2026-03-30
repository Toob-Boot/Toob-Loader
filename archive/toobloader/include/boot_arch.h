#ifndef BOOTLOADER_BOOT_ARCH_H
#define BOOTLOADER_BOOT_ARCH_H

/**
 * @file boot_arch.h
 * @brief Bootloader Architecture Abstraction Header
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include <stdbool.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @osv component: Bootloader.Core
 * @brief Execute a tight assembler nop loop.
 * Implemented by the architecture specific boot_arch_*.c files.
 * @param count Number of nop instructions to execute.
 */
extern void boot_arch_delay_nop(uint32_t count);

/**
 * @osv component: Bootloader.Core
 * @brief Halts the CPU securely in an infinite wait-state.
 * Used for deterministic failures.
 */
__attribute__((noreturn)) extern void boot_arch_halt(void);

/**
 * @osv component: Bootloader.Core
 * @brief Abstracted Assembly/Pointer handoff to the targeted Kernel Address.
 * Resolves NASA P10 Rule 9 by moving absolute PC manipulation into Arch
 * isolated logic.
 * @param final_entry_addr The 32-bit execution pointer
 */
__attribute__((noreturn)) extern void boot_arch_jump(uint32_t final_entry_addr);

/**
 * @osv component: Bootloader.HAL
 * @brief Checks if the physical recovery button (e.g., Boot Button) is held
 * down. Used exclusively to force entry into Stage 2 Recovery.
 * @return true if button is pressed, false otherwise.
 */
extern bool boot_hal_is_recovery_button_pressed(void);

/**
 * @osv component: Bootloader.HAL
 * @brief Unified non-blocking UART direct character read.
 *
 * Hardware HALs implement this single primitive. The common HAL library
 * handles timeout logic, Watchdog feeding, and OSV Rule 2 Bounding.
 *
 * @param[out] c Pointer to the character received.
 * @return 0 on success (character received), non-zero on empty FIFO.
 */
extern int32_t boot_uart_rx_char(uint8_t *c);

/* ============================================================================
 * RP_BOOT_START_ROUTINE
 * Macro for zeroing the BSS segment to satisfy NASA P10 memory initialization.
 * Must be called as the very first instruction in every start_*.c or assembler
 * handoff. Relies on _bss_start and _bss_end provided by the linker scripts.
 * ========================================================================== */
extern uint32_t _bss_start;
extern uint32_t _bss_end;

#define RP_BOOT_START_ROUTINE()                                                \
  do {                                                                         \
    RP_ASSERT(&_bss_end >= &_bss_start, "Invalid BSS bounds");                 \
    uint32_t bss_len = (uint32_t)&_bss_end - (uint32_t)&_bss_start;            \
    (void)rp_secure_zeroMemory(&_bss_start, bss_len);                          \
  } while (0)

#ifdef __cplusplus
}
#endif

#endif /* BOOTLOADER_BOOT_ARCH_H */
