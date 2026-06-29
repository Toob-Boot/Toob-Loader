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

#include "generated_boot_config.h"
#include "boot_crc32.h"
#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"
#include "boot_fih.h"



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
      uint32_t magic = hdr.data.sector_magic;
      uint32_t seq_id = 0;
      uint32_t bank = 0;
      bool valid = false;

      if (magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
        const wal_sector_header_v1_t *legacy_hdr = (const wal_sector_header_v1_t *)&hdr.data;
        uint32_t calc_crc = compute_boot_crc32((const uint8_t *)legacy_hdr, offsetof(wal_sector_header_v1_t, header_crc32));
        BOOT_SECURE_REQUIRE(calc_crc == legacy_hdr->header_crc32, {
          goto next_sector;
        });
        seq_id = legacy_hdr->sequence_id;
        bank = legacy_hdr->tmr_data.active_stage1_bank;
        valid = true;
      } else if (magic == WAL_ABI_VERSION_MAGIC_CURRENT) {
        uint32_t calc_crc = compute_boot_crc32((const uint8_t *)&hdr.data, offsetof(wal_sector_header_t, header_crc32));
        BOOT_SECURE_REQUIRE(calc_crc == hdr.data.header_crc32, {
          goto next_sector;
        });
        seq_id = hdr.data.sequence_id;
        bank = hdr.data.tmr_data.active_stage1_bank;
        valid = true;
      }

      if (valid && seq_id > highest_seq) {
        highest_seq = seq_id;
        /* FIX: Stage 0 wählt die Bootloader-Bank, NICHT das Feature-OS! */
        active_slot = (bank == 0)
                          ? CHIP_STAGE1A_ABS_ADDR
                          : CHIP_STAGE1B_ABS_ADDR;
      }
    }
next_sector:
    boot_secure_zeroize(&hdr, sizeof(hdr));
  }
  return active_slot;
}