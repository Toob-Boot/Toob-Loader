/**
 * @file stage0_boot_pointer.c
 * @brief Boot Pointer Resolution via WAL
 *
 * Implements O(1) Majority-Vote over WAL sectors to find the active Stage 1 Bank
 * (Slot A/B) without the overhead of the full journal parser.
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_config_mock.h"
#include "boot_crc32.h"
#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"



/* O(1) Majority Vote über die Sektor-Header, um die aktive Boot-Bank zu finden,
 * OHNE die fette boot_journal_init() State-Machine aus Stage 1 laden zu müssen.
 */
uint32_t stage0_get_active_slot(const boot_platform_t *platform) {
  const uint32_t wal_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
  uint32_t highest_seq = 0;
  uint32_t active_slot = CHIP_APP_SLOT_ABS_ADDR; /* Default Fallback */

  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (platform->flash->read(wal_addrs[i], (uint8_t *)&hdr, sizeof(hdr)) ==
        BOOT_OK) {
      size_t crc_len = offsetof(wal_sector_header_t, header_crc32);
      uint32_t calc_crc =
          compute_boot_crc32((const uint8_t *)&hdr.data, crc_len);

      volatile uint32_t shield_1 = 0, shield_2 = 0;
      if (hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC &&
          calc_crc == hdr.data.header_crc32)
        shield_1 = BOOT_OK;
      BOOT_GLITCH_DELAY();
      if (shield_1 == BOOT_OK &&
          hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC &&
          calc_crc == hdr.data.header_crc32)
        shield_2 = BOOT_OK;

      if (shield_1 == BOOT_OK && shield_2 == BOOT_OK) {
        if (hdr.data.sequence_id > highest_seq) {
          highest_seq = hdr.data.sequence_id;
          /* FIX: Stage 0 wählt die Bootloader-Bank, NICHT das Feature-OS! */
          active_slot = (hdr.data.tmr_data.active_stage1_bank == 0)
                            ? CHIP_STAGE1A_ABS_ADDR
                            : CHIP_STAGE1B_ABS_ADDR;
        }
      }
    }
  }
  return active_slot;
}