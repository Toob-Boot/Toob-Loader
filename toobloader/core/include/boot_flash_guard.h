/**
 * @file boot_flash_guard.h
 * @brief Central Flash Immutable-Boot Firewall for Stage 0 Non-Brickability.
 *
 * Enforces software write/erase bounds before dispatching to flash_hal_t so
 * neither Stage 1, Recovery, nor host-simulated callers can accidentally erase
 * or overwrite the immutable Stage 0 boot sector or wrap 32-bit flash addresses.
 */

#ifndef TOOB_BOOT_FLASH_GUARD_H
#define TOOB_BOOT_FLASH_GUARD_H

#include "boot_hal.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__has_include)
#if __has_include("generated_boot_config.h")
#include "generated_boot_config.h"
#endif
#if __has_include("boot_layout.h")
#include "boot_layout.h"
#endif
#endif

#ifndef CHIP_FLASH_IMMUTABLE_BOOT_END
#if defined(CHIP_STAGE0_ABS_ADDR) && defined(CHIP_STAGE0_SIZE) && ((CHIP_STAGE0_SIZE) > 0U)
#define CHIP_FLASH_IMMUTABLE_BOOT_END                                                              \
  ((uint64_t)(CHIP_STAGE0_ABS_ADDR) + (uint64_t)(CHIP_STAGE0_SIZE))
#else
#define CHIP_FLASH_IMMUTABLE_BOOT_END 0x00000000ULL
#endif
#endif

static inline bool boot_flash_range_hits_immutable_boot(uint32_t addr, size_t len) {
  uint64_t end_excl = (uint64_t)addr + (uint64_t)len;
  if (end_excl > 0x100000000ULL) {
    return true;
  }
  uint64_t imm_end = (uint64_t)(CHIP_FLASH_IMMUTABLE_BOOT_END);
  if ((imm_end > 0ULL) && ((uint64_t)addr < imm_end)) {
    return true;
  }
#if defined(CHIP_STAGE0_ABS_ADDR) && (defined(CHIP_STAGE0_BYTE_SIZE) || defined(CHIP_STAGE0_SIZE))
#ifdef CHIP_STAGE0_BYTE_SIZE
  uint64_t s0_len = (uint64_t)(CHIP_STAGE0_BYTE_SIZE);
#else
  uint64_t s0_len = (uint64_t)(CHIP_STAGE0_SIZE);
#endif
  if (s0_len > 0ULL) {
    uint64_t s0_start = (uint64_t)(CHIP_STAGE0_ABS_ADDR);
    uint64_t s0_end = s0_start + s0_len;
    uint64_t op_end = (len == 0U) ? ((uint64_t)addr + 1ULL) : end_excl;
    if (((uint64_t)addr < s0_end) && (op_end > s0_start)) {
      return true;
    }
  }
#endif
  return false;
}

boot_status_t boot_flash_write_guarded(const flash_hal_t *flash, uint32_t addr, const void *buf,
                                       size_t len);

boot_status_t boot_flash_erase_sector_guarded(const flash_hal_t *flash, uint32_t addr);

#endif /* TOOB_BOOT_FLASH_GUARD_H */
