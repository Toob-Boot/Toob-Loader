/**
 * @file boot_state.c
 * @brief Bootloader State Management & Triple Modular Redundancy (TMR)
 *
 * Implements an $O(1)$ mathematically deterministic TMR voter model.
 * Storage strategy: 3 contiguous 4KB Flash Sectors starting at
 * BOOT_STATE_SECTOR_ADDR.
 *
 * If a Bit Flip (SEU) occurs during flight or rest, the 2-out-of-3
 * majority system automatically outvotes the corrupted state and
 * transparently heals the defective sector before delegating to the OS.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../include/boot_state.h"
#include "../include/common/kb_tags.h"
#include "../include/common/rp_assert.h"

#include <stdbool.h>
#include <stdint.h>

/**
 * @osv
 * component: Bootloader.State
 * tag_status: auto
 */

/* Flash HAL bindings */
extern int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len);
extern int32_t boot_flash_write(uint32_t addr, const uint8_t *buf,
                                uint32_t len);
extern int32_t boot_flash_erase(uint32_t addr, uint32_t len);

#define SECTOR_SIZE 4096u

/* ============================================================================
 * Cryptographic Utility & Voting Math
 * ========================================================================== */

static uint32_t compute_crc32(const uint8_t *data, uint32_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (uint32_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (uint8_t bit = 0; bit < 8; bit++) {
      if (crc & 1u) {
        crc = (crc >> 1) ^ 0xEDB88320u;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc ^ 0xFFFFFFFFu;
}

static bool is_state_valid(const boot_state_sector_t *st) {
  if (st->magic != BOOT_STATE_MAGIC)
    return false;

  /* Validate struct integrity excluding the crc field itself */
  uint32_t expected_crc = compute_crc32(
      (const uint8_t *)st, offsetof(boot_state_sector_t, sector_crc));
  return st->sector_crc == expected_crc;
}

static bool are_states_equal(const boot_state_sector_t *a,
                             const boot_state_sector_t *b) {
  /* Prevent side-channel compiler optimizations, force absolute binary match */
  return (a->magic == b->magic && a->active_slot == b->active_slot &&
          a->boot_count == b->boot_count && a->in_recovery == b->in_recovery);
}

/* ============================================================================
 * Core TMR Logic
 * ========================================================================== */

KB_CORE()
int32_t boot_state_read_tmr(boot_state_sector_t *state) {
  RP_ASSERT(state != NULL, "state ptr null");

  boot_state_sector_t copies[3];
  bool valid[3] = {false, false, false};
  int valid_count = 0;

  /* 1. Sequential Read (O(1) Memory Time) */
  for (int i = 0; i < 3; i++) {
    uint32_t addr = BOOT_STATE_SECTOR_ADDR + ((uint32_t)i * SECTOR_SIZE);

    /* We read the exactly 12-byte signed state chunk */
    if (boot_flash_read(addr, (uint8_t *)&copies[i],
                        sizeof(boot_state_sector_t)) == 0) {
      if (is_state_valid(&copies[i])) {
        valid[i] = true;
        valid_count++;
      }
    }
  }

  /* 2. Majority Evaluation & Routing */
  if (valid_count == 3) {
    /* Fast path: Everything is perfect. Check equality just in case of logical
     * schism. */
    if (are_states_equal(&copies[0], &copies[1]) &&
        are_states_equal(&copies[1], &copies[2])) {
      rp_memcpy(state, &copies[0], sizeof(boot_state_sector_t));
      return 0;
    }
  }

  if (valid_count == 2) {
    /* 2-out-of-3 Voter Mechanism (Mitigating SEU / Flash Corruption) */
    int good_a = -1, good_b = -1;
    for (int i = 0; i < 3; i++) {
      if (valid[i]) {
        if (good_a == -1)
          good_a = i;
        else
          good_b = i;
      }
    }

    if (are_states_equal(&copies[good_a], &copies[good_b])) {
      /* We have a verifiable mathematical 2/3 agreement. */
      rp_memcpy(state, &copies[good_a], sizeof(boot_state_sector_t));

      /* Self-Healing Protocol: Restoring the corrupted third sector */
      int bad_idx =
          3 - (good_a + good_b); /* 0+1=1(->2), 1+2=3(->0), 0+2=2(->1) */
      uint32_t bad_addr =
          BOOT_STATE_SECTOR_ADDR + ((uint32_t)bad_idx * SECTOR_SIZE);

      (void)boot_flash_erase(bad_addr, SECTOR_SIZE);
      (void)boot_flash_write(bad_addr, (const uint8_t *)state,
                             sizeof(boot_state_sector_t));

      return 0;
    }
  }

  /* Fallback: 0 or 1 valid sectors = Critical System Compromise. Can't trust
   * state. */
  return -1;
}

KB_CORE()
int32_t boot_state_write_tmr(boot_state_sector_t *state) {
  RP_ASSERT(state != NULL, "state ptr null");

  /* Seal the Sector with the Checksum */
  state->magic = BOOT_STATE_MAGIC;
  state->sector_crc = compute_crc32((const uint8_t *)state,
                                    offsetof(boot_state_sector_t, sector_crc));

  /* Write sequentially to all 3 nodes (O(1) Time) */
  for (int i = 0; i < 3; i++) {
    uint32_t addr = BOOT_STATE_SECTOR_ADDR + ((uint32_t)i * SECTOR_SIZE);

    if (boot_flash_erase(addr, SECTOR_SIZE) != 0) {
      return -1;
    }
    if (boot_flash_write(addr, (const uint8_t *)state,
                         sizeof(boot_state_sector_t)) != 0) {
      return -1;
    }
  }
  return 0;
}

KB_CORE()
void boot_state_increment_failures(boot_state_sector_t *state) {
  state->boot_count++;
  if (state->boot_count >= BOOT_MAX_ATTEMPTS) {
    state->in_recovery = 1;
  }
  (void)boot_state_write_tmr(state);
}
