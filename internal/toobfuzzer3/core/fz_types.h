#ifndef FZ_TYPES_H
#define FZ_TYPES_H

#include <stdbool.h>
#include <stdint.h>

/**
 * Universal Hardware Capability Profiler
 * Generated organically at link-time from AI Model extraction (TRM PDF).
 */
typedef struct {
  uint32_t user_flash_base; // Base of user executable
  uint32_t rom_base;        // Internal ROM hardware base

  uint8_t rdp_level;        // STM32 Opt-Bytes readout protection (0, 1, 2)
  bool flash_encrypted;     // ESP/nRF flash encryption active
  bool debug_access;        // JTAG/SWD unlocked vs disabled
  bool raw_flash_rw;        // True if we can natively blast SPI sectors
  bool bootrom_access;      // True if boot ROM mapping is readable
} fz_caps_t;

// Shims automatically injected via `linker_gen/chip_generator.py`
fz_caps_t chip_get_capabilities(void);

// --- LINKER BOUNDARY SYMBOLS (Phase 11 Self-Preservation) ---
// These symbols are generated dynamically by ld_generator.py in the .ld script
// We take their ADDRESS (&_text_start) to get the actual pointer value.
extern uint32_t _text_start;
extern uint32_t _text_end;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;

/**
 * Dynamic Memory Shielding
 * Defines mathematically exact barriers where the Fuzzer must skip O(1).
 */
typedef struct {
  uint32_t base;
  uint32_t size;
} fz_protect_region_t;

extern const fz_protect_region_t chip_protected_regions[];
extern const uint32_t chip_protected_count;

/**
 * Dynamic Application RAM Targeting
 * Open writable memory sections that should be aggressively scanned.
 */
typedef struct {
  uint32_t base;
  uint32_t size;
} fz_ram_region_t;

extern const fz_ram_region_t chip_testable_ram_regions[];
extern const uint32_t chip_testable_ram_count;

/**
 * Memory-Optimized MMIO Fuzzing Structure (Keelhaul Methodology)
 * Generated via `linker_gen/svd_to_c.py`
 */
typedef struct {
  uint32_t address;
  uint32_t reset_value;
  uint32_t write_mask; // Bitmask of writable bits (derived from SVD fields)
} keelhaul_reg_t;

// Shims automatically injected via `linker_gen/svd_to_c.py`
extern const keelhaul_reg_t keelhaul_svd_array[];
extern const uint32_t keelhaul_svd_count;

// Auto-Extracted Peripheral Base Addresses
extern const uint32_t keelhaul_uart_bases[];
extern const uint32_t keelhaul_uart_count;

extern const uint32_t keelhaul_wdt_bases[];
extern const uint32_t keelhaul_wdt_count;

#endif // FZ_TYPES_H
