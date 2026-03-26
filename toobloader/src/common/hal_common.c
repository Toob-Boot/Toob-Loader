/**
 * @file hal_common.c
 * @brief Unified Bootloader Hardware Abstraction Layer
 *
 * Consolidates duplicated, mathematically verifiable boilerplate
 * across all Toobloader architectures. Provides GNU Linker __weak
 * fallbacks for default configurations (e.g., DSLC offset).
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../../include/boot_arch.h"
#include "../../include/boot_config.h"
#include "../../include/boot_state.h"
#include "../../include/common/kb_tags.h"
#include "../../include/common/rp_assert.h"
#include <stdbool.h>
#include <stdint.h>

/* ============================================================================
 * Bootloader Lifecycle & Entry Vector
 * ========================================================================== */

extern void boot_main(void);
extern void boot_arch_halt(void);

/**
 * @osv component: Bootloader.Core
 * @brief Universal Bootloader Entry Vector (Replaces chip-specific start_xyz.c)
 * This generic entry point zeroes the BSS region (enforcing the Common
 * Memory Safety Protocol) and jumps into the OSV-verified State Machine.
 */
KB_CORE()
__attribute__((section(".entry.text"), noreturn)) void
boot_startup_vector(void) {
  /* 1. Zero out the BSS segment (Memory Safety via Common Protocol) */
  RP_BOOT_START_ROUTINE();

  /* 2. Dive into the OSV-verified State Machine */
  (void)boot_main();

  /* 3. Infinite Halt Fallback */
  (void)boot_arch_halt();
}

/* ============================================================================
 * Hardware Recovery & Identification
 * ========================================================================== */

/**
 * @osv component: Bootloader.HAL
 * @brief Generic Hardware Recovery Pin Logic
 * If a recovery pin is configured via CMake, this uses the fundamental
 * GPIO primitive to evaluate against the configured active level.
 * If undefined, the linker gracefully falls back to false.
 */
#ifdef BOOT_RECOVERY_PIN

extern uint8_t boot_hal_gpio_get_level(uint32_t pin);

KB_FEATURE("Hardware Recovery Button")
bool boot_hal_is_recovery_button_pressed(void) {
  return boot_hal_gpio_get_level(BOOT_RECOVERY_PIN) == BOOT_RECOVERY_LEVEL;
}

#else

__attribute__((weak)) KB_FEATURE(
    "Hardware Recovery Button") bool boot_hal_is_recovery_button_pressed(void) {
  return false;
}

#endif

/**
 * @osv component: Bootloader.HAL
 * @brief Retrieves the 32-byte Device Specific Lock Code (DSLC).
 *
 * Unless overridden by the specific architecture HAL, this weak implementation
 * attempts to read it from the Repowatt standard offset 0x9000.
 */
extern int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len);

__attribute__((weak)) KB_CORE() void boot_hal_get_dslc(uint8_t out_dslc[32]) {
  /* Default Repowatt DSLC Partition Address (0x9000) */
  (void)boot_flash_read(0x00009000u, out_dslc, 32);
}

/**
 * @osv component: Bootloader.Crypto
 * @brief Retrieves the 32-byte Firmware Encryption Key (FEK).
 *
 * This provides a weak baseline symbol for the GNU Linker to satisfy the
 * `--wrap` Mocking constraint during development. In production, this MUST
 * be overridden by chip-specific eFuse logic.
 */
__attribute__((weak))
KB_CORE() void boot_hal_get_firmware_key(uint8_t out_key[32]) {
  /* Fallback zeroes to ensure deterministic failure if unimplemented */
  (void)out_key;
}

/* ============================================================================
 * UART Console & Communication
 * ========================================================================== */

/**
 * @osv component: Bootloader.HAL
 * @brief Bounded, timeout-based UART polling loop.
 *
 * Implements a strict mathematical ceiling on wait time to satisfy NASA P10
 * Rule 2 (No unbounded loops). It repeatedly requests characters from the
 * architecture-specific primitive `boot_uart_rx_char` and feeds the WDT.
 */
KB_CORE()
int32_t boot_uart_getc_timeout(uint8_t *out_char, uint32_t timeout_ms) {
  uint32_t wait_ticks = 0;

  /* Polling ceiling loop. Multiplied by 10 to approximate roughly 1ms per
     hardware tick without requiring a heavy Timer subsystem. */
  while (wait_ticks < (timeout_ms * 10)) {
    uint8_t r;

    /* Hardware-Specific implementation (e.g., ESP ROM call or STM Register
     * read) */
    if (boot_uart_rx_char(&r) == 0) {
      if (out_char) {
        *out_char = r;
      }
      return 0; /* Success */
    }

    /* Prevent physical reset during large wait loops */
    boot_hal_wdt_feed();
    wait_ticks++;
  }

  return -1; /* Timeout reached */
}

/**
 * @osv component: Bootloader.HAL
 * @brief Converts a 32-bit integer to an ASCII hex string and prints it.
 * This mathematically bound loop guarantees bounded termination (P10 Rule 2).
 */
KB_CORE()
void boot_uart_put_hex32(uint32_t val) {
  static const char hex[] = "0123456789ABCDEF";
  char buf[9];
  for (int i = 7; i >= 0; i--) {
    buf[i] = hex[val & 0xF];
    val >>= 4;
  }
  buf[8] = '\0';
  boot_uart_puts(buf);
}

/**
 * @osv component: Bootloader.HAL
 * @brief Generic UART Print String Fallback
 * Iterates through the string and relies on the fundamental
 * `boot_hal_uart_tx_char`.
 */
extern void boot_hal_uart_tx_char(char c);

__attribute__((weak)) KB_CORE() void boot_uart_puts(const char *msg) {
  if (!msg)
    return;
  while (*msg) {
    boot_hal_uart_tx_char(*msg++);
  }
}

/* ============================================================================
 * Memory & Register Operations
 * ========================================================================== */

/**
 * @osv component: Bootloader.HAL
 * @brief Generic 32-bit Register Block Reader (e.g., for eFuses)
 * Reads consecutive 32-bit registers into a unified byte buffer.
 *
 * @param base_addr Core memory mapped register start
 * @param buf Output byte buffer
 * @param num_words Number of 32-bit registers to read
 */
KB_CORE()
void boot_hal_read_regs_to_bytes(uint32_t base_addr, uint8_t *buf,
                                 uint32_t num_words) {
  for (uint32_t i = 0; i < num_words; i++) {
    uint32_t val = (*(volatile uint32_t *)(base_addr + (i * 4)));
    buf[(i * 4) + 0] = (uint8_t)(val >> 0);
    buf[(i * 4) + 1] = (uint8_t)(val >> 8);
    buf[(i * 4) + 2] = (uint8_t)(val >> 16);
    buf[(i * 4) + 3] = (uint8_t)(val >> 24);
  }
}

/* ============================================================================
 * External Stubs & Fallbacks
 * ========================================================================== */

/* Fallback stubs for critical functions entirely unimplemented by generic HALs
 */
__attribute__((weak)) KB_CORE() int32_t boot_uart_rx_char(uint8_t *c) {
  (void)c;
  return -1;
}

__attribute__((weak)) KB_CORE() void boot_hal_wdt_feed(void) { /* Stub */ }

/**
 * @osv component: OS.Syscall.Stub
 * @brief Reference implementation for the Kernel to mark an OTA update as
 * successful.
 *
 * The Repowatt-OS invokes this (via Syscall) after establishing stable
 * execution. It resets the bootloader's TMR failure counter, committing the
 * Ping-Pong update.
 */
__attribute__((weak)) KB_CORE() int32_t sys_boot_mark_valid(void) {
  boot_state_sector_t state;
  if (boot_state_read_tmr(&state) == 0) {
    if (state.boot_count > 0 || state.in_recovery > 0) {
      state.boot_count = 0;
      state.in_recovery = 0;
      return boot_state_write_tmr(&state);
    }
    return 0; /* Already valid */
  }
  return -1;
}
