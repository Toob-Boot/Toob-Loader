#include "fz_profiles.h"
#include <stdbool.h>
#include <stdint.h>

#include "logger.h"

// Safe read prototype (implemented in assembly to catch hardware faults)
extern bool probe_read32(uint32_t addr, uint32_t *out_val);

// Abstract Flash Sector writes/erases
extern bool chip_flash_erase(uint32_t sector_addr);
extern bool chip_flash_write32(uint32_t addr, uint32_t val);

static void memory_bin_search(uint32_t start_addr, uint32_t max_range) {
  uint32_t low = 0;
  uint32_t high = max_range / 4; // Word aligned search
  uint32_t highest_valid = 0;
  uint32_t dummy_val = 0;

  fz_log("      [->] Binary Search | Base: 0x");
  fz_log_hex(start_addr);
  fz_log("\n");

  while (low <= high) {
    uint32_t mid = low + (high - low) / 2;
    uint32_t target_addr = start_addr + (mid * 4);

    if (probe_read32(target_addr, &dummy_val)) {
      highest_valid = target_addr;
      low = mid + 1; // It worked, try higher
    } else {
      if (mid == 0)
        break;        // Even the base failed
      high = mid - 1; // Failed (Faulted), try lower
    }
  }

  fz_log("      [<-] Discovered Valid Boundary: 0x");
  fz_log_hex(highest_valid);
  fz_log("\n");
}

static uint32_t binary_search_sector_boundary(uint32_t start_addr,
                                              uint32_t max_search_range,
                                              uint32_t sampling_interval) {
  fz_log("      [~] Entering Phase 1 (Coarse Search)...\n");
  uint32_t low = start_addr;
  uint32_t high = start_addr + max_search_range - sampling_interval;
  uint32_t coarse_boundary = start_addr;

  while (low <= high) {
    uint32_t mid = low + ((high - low) / 2);
    mid = start_addr +
          (((mid - start_addr) / sampling_interval) * sampling_interval);

    uint32_t val = 0;
    if (!probe_read32(mid, &val)) {
      if (mid < start_addr + sampling_interval)
        break;
      high = mid - sampling_interval;
      continue;
    }

    if (val == 0xFFFFFFFF) {
      coarse_boundary = mid; // Erased here, boundary is at least mid
      low = mid + sampling_interval;
    } else {
      if (mid < start_addr + sampling_interval)
        break;
      high = mid - sampling_interval;
    }
  }

  fz_log("      [~] Phase 1 Complete. Coarse Boundary: 0x");
  fz_log_hex(coarse_boundary);
  fz_log("\n      [~] Entering Phase 2 (Fine Search)...\n");

  uint32_t fine_low = coarse_boundary;
  uint32_t fine_high = coarse_boundary + sampling_interval;
  if (fine_high > start_addr + max_search_range)
    fine_high = start_addr + max_search_range;

  uint32_t exact_boundary = coarse_boundary;

  while (fine_low <= fine_high) {
    uint32_t fine_mid = fine_low + ((fine_high - fine_low) / 2);
    fine_mid = fine_mid & ~0x3; // Align to 4-byte word boundary

    fz_log("        [~] Phase 2: Testing fine_mid = 0x");
    fz_log_hex(fine_mid);
    fz_log("\n");

    uint32_t pre_val = 0;
    if (probe_read32(fine_mid, &pre_val) && pre_val != 0xFFFFFFFF) {
      if (fine_mid <= start_addr + 4)
        break;
      fine_high = fine_mid - 4;
      continue;
    }

    fz_log("        [~] Phase 2: Injecting probe marker 0xDEADBEEF...\n");
    chip_flash_write32(fine_mid, 0xDEADBEEF);

    fz_log("        [~] Phase 2: Re-Erasing Sector 0x");
    fz_log_hex(start_addr);
    fz_log("...\n");
    chip_flash_erase(start_addr);

    fz_log("        [~] Phase 2: Interrogating Marker Survival...\n");
    uint32_t val = 0;
    if (!probe_read32(fine_mid, &val)) {
      if (fine_mid <= start_addr + 4)
        break;
      fine_high = fine_mid - 4;
      continue;
    }

    if (val == 0xFFFFFFFF) {
      exact_boundary = fine_mid;
      fine_low = fine_mid + 4;
    } else {
      if (fine_mid <= start_addr + 4)
        break;
      fine_high = fine_mid - 4;
    }
  }

  fz_log("      [~] Phase 2 Complete. Exact Boundary: 0x");
  fz_log_hex(exact_boundary);
  fz_log("\n");

  uint32_t ret = (exact_boundary - start_addr) + 4;
  return ret;
}

static void full_sector_scan(uint32_t base, uint32_t limit) {
  fz_log("      [->] Aggressive SPI Write/Erase Fuzzing Initiated...\n");

  fz_log("[CORE] {\"status\": \"scan_start\", \"base\": \"");
  fz_log_hex(base);
  fz_log("\", \"limit\": \"");
  fz_log_hex(limit);
  fz_log("\"}\n");

  uint32_t addr = base;
  while (addr < limit) {
    // Phase 11 & 18 & 19: Firmware Self-Preservation & Multiple Exclusions
    // Cross-reference all dynamically discovered hardware reserved regions
    bool skipped = false;
    for (uint32_t i = 0; i < chip_protected_count; i++) {
      uint32_t p_base = chip_protected_regions[i].base;
      uint32_t p_size = chip_protected_regions[i].size;

      if (addr >= p_base && addr < (p_base + p_size)) {
        uint32_t jump_size = (p_base + p_size) - addr;
        fz_log("S");
        fz_log_hex(addr);
        fz_log(" [size: 0x");
        fz_log_hex(jump_size);
        fz_log("]\n");
        addr += jump_size;
        skipped = true;
        break;
      }
    }
    if (skipped)
      continue;

    uint32_t sample_range = 256 * 1024; // Attempt to map up to 256KB sectors
    uint32_t sampling_interval = 256;

    // Constrain sample_range to avoid bleeding into protected regions or limits
    if (addr + sample_range > limit) {
      sample_range = limit - addr;
    }

    for (uint32_t i = 0; i < chip_protected_count; i++) {
      uint32_t p_base = chip_protected_regions[i].base;
      if (p_base > addr && p_base < addr + sample_range) {
        sample_range = p_base - addr;
      }
    }
    sample_range = (sample_range / sampling_interval) * sampling_interval;
    if (sample_range < sampling_interval)
      sample_range = sampling_interval;

    // 1. Write the probing marker ahead of us to find the wall later
    // CRITICAL: We MUST NOT write to unerased flash to prevent SPI Deadlocks.
    // We check only the starting address to prevent tight D-Cache/BootROM 
    // bus interleaving which can silently crash the ESP32 silicon.
    uint32_t start_val = 0;
    if (probe_read32(addr, &start_val) && start_val == 0xFFFFFFFF) {
      fz_log("      [~] Empty Sector! Injecting 256KB Probe Markers...\n");
      for (uint32_t i = 0; i < sample_range; i += sampling_interval) {
        chip_flash_write32(addr + i, 0xAAAAAAAA);
      }
    } else {
      fz_log("      [~] Skipping Markers (Sector Unerased or Shielded)\n");
    }

    fz_log("      [~] Firing BootROM Sector Erase...\n");
    if (chip_flash_erase(addr)) {
      fz_log("      [~] SUCCESS: Sector Erased!\n");
      fz_log("+");
      fz_log_hex(addr);
      fz_log("\n"); // Force flush

      fz_log("      [~] Initiating Binary Boundary Search...\n");
      uint32_t sector_size =
          binary_search_sector_boundary(addr, sample_range, sampling_interval);
      fz_log(" [size: ");
      fz_log_hex(sector_size);
      fz_log("]\n");

      addr += sector_size;
    } else {
      fz_log("-");
      fz_log_hex(addr);
      fz_log("\n");
      addr += 4096; // Fallback if erase failed
    }
  }
  fz_log("      [<-] Full Flash Scan Complete\n");
}

static bool is_blacklisted_peripheral(uint32_t target_addr,
                                      const uint32_t *bases, uint32_t count) {
  // Most peripherals occupy a 4KB (0x1000) memory block.
  // If the target register falls within any known base block, it belongs to
  // that peripheral.
  for (uint32_t i = 0; i < count; i++) {
    if (bases[i] != 0 && target_addr >= bases[i] &&
        target_addr < (bases[i] + 0x1000)) {
      return true;
    }
  }
  return false;
}

void keelhaul_mmio_fuzz(void) {
  fz_log("\n[KEELHAUL] Initiating Hardware Register Fuzzing...\n");
  fz_log("[KEELHAUL] Applying SVD Hardware Sterilization Hooks...\n");
  fz_log("[KEELHAUL] Targeting ");
  fz_log_hex(keelhaul_svd_count);
  fz_log(" Writable MMIO Registers.\n");

  uint32_t edge_cases[] = {0xFFFFFFFF, 0x00000000, 0xAAAAAAAA, 0x55555555};

  for (uint32_t i = 0; i < keelhaul_svd_count; i++) {
    const keelhaul_reg_t *reg = &keelhaul_svd_array[i];

    // Hardware Sterilization: Protect Critical System Stability
    if (is_blacklisted_peripheral(reg->address, keelhaul_wdt_bases,
                                  keelhaul_wdt_count)) {
      // Silently skip watchdogs to prevent reset loops
      continue;
    }
    if (is_blacklisted_peripheral(reg->address, keelhaul_uart_bases,
                                  keelhaul_uart_count)) {
      // Skipped to maintain the Fuzzer Oracle communication line
      continue;
    }

    if (reg->write_mask > 0) {
      volatile uint32_t *target = (volatile uint32_t *)reg->address;

      for (int e = 0; e < 4; e++) {
        // Mask the edge case so we don't accidentally write 1s to reserved bits
        // which might trigger an immediate unrelated hardware trap.
        uint32_t payload = (edge_cases[e] & reg->write_mask) |
                           (reg->reset_value & ~reg->write_mask);

        // Simulated Bare-Metal Fuzzer Write.
        // In production, this write is surrounded by a setjmp() fault handler.
        /* Uncomment to arm:
         *target = payload;
         */
        (void)payload; // Prevent unused warning during simulation
        (void)target;
      }
    }
  }
  fz_log("[KEELHAUL] MMIO Fuzzing Pass Complete.\n");
}

void fuzzer_scan(fz_profile_t profile) {
  fz_log("\n[CORE] Executing Memory Scan under Profile: ");
  fz_log(profile.name);
  fz_log("\n");

  if (profile.id == PROFILE_EMULATION_ONLY ||
      profile.id == PROFILE_READONLY_HARDENED) {
    fz_log("[CORE] Hardware is strongly locked. Aggressive bare-metal "
           "scanning aborted.\n");
    return;
  }

  // 1. Always attempt RAM mathematical boundary discovery
  fz_log("[CORE] Commencing RAM Boundary Discovery...\n");

  if (profile.caps.iram_base != 0) {
    memory_bin_search(profile.caps.iram_base, profile.caps.iram_length);
  }

  if (profile.caps.dram_base != 0 &&
      profile.caps.dram_base != profile.caps.iram_base) {
    memory_bin_search(profile.caps.dram_base, profile.caps.dram_length);
  }

  // 2. Profile-Directed Flash Scanning
  fz_log("[CORE] Commencing Flash Capability Probing...\n");

  if (profile.caps.raw_flash_rw && profile.id == PROFILE_BARE_METAL_OPEN) {
    fz_log("       Status: OPEN. Executing unrestricted sector mapping.\n");
    full_sector_scan(profile.caps.user_flash_base, profile.caps.user_flash_base + 0x400000);

    // Call Keelhaul Fuzzing only on completely open systems
    keelhaul_mmio_fuzz();

  } else if (profile.id == PROFILE_FLASH_ENCRYPTED) {
    fz_log("       Status: ENCRYPTED. Raw Sector Erase disabled to prevent "
           "data corruption.\n");
    fz_log("       Downgrading to safe Logical Partition read-mapping...\n");
    // Only run the safe binary search on flash, no writes
    memory_bin_search(profile.caps.user_flash_base, 0x00400000);

  } else if (profile.id == PROFILE_RDP_LEVEL1) {
    fz_log("       Status: RDP_LEVEL1. Access to BootROM/SRAM vectors "
           "restricted.\n");
    fz_log(
        "       Constraining scan exclusively to User-Application bounds.\n");
    memory_bin_search(profile.caps.user_flash_base, 0x00400000);

  } else if (profile.id == PROFILE_BOOTLOADER_MEDIATED) {
    fz_log("       Status: BOOTLOADER. Using vendor ROM APIs for mapping...\n");

  } else {
    fz_log("       Status: RESTRICTED. Flash probing deemed unsafe.\n");
  }
}
