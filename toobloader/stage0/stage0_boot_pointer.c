/**
 * @file stage0_boot_pointer.c
 * @brief Boot Pointer & SVN Resolution via WAL
 *
 * Implements O(1) scan over WAL sectors to extract the active Stage 1 Bank
 * (Slot A/B) and the persisted stage1_svn, without the overhead of the
 * full journal parser.
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

/**
 * @brief Unified O(1) WAL scan — extracts both bank and SVN in one pass.
 *
 * Finds the WAL sector with the highest sequence_id and extracts
 * active_stage1_bank and stage1_svn from it. v1 sectors have no
 * stage1_svn field — result defaults to 0 (no floor enforced).
 */
static void stage0_scan_wal_highest(const boot_platform_t *platform,
                                    uint32_t *out_bank,
                                    uint32_t *out_svn) {
  const uint32_t wal_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
  uint32_t highest_seq = 0;
  *out_bank = 0;
  *out_svn = 0;

  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (platform->flash->read(wal_addrs[i], (uint8_t *)&hdr, sizeof(hdr)) !=
        BOOT_OK) {
      goto next_sector;
    }

    uint32_t magic = hdr.data.sector_magic;
    uint32_t seq_id = 0;
    uint32_t bank = 0;
    uint32_t svn = 0;
    bool valid = false;

    if (magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
      const wal_sector_header_v1_t *legacy_hdr =
          (const wal_sector_header_v1_t *)&hdr.data;
      uint32_t calc_crc = compute_boot_crc32(
          (const uint8_t *)legacy_hdr,
          offsetof(wal_sector_header_v1_t, header_crc32));
      BOOT_SECURE_REQUIRE(calc_crc == legacy_hdr->header_crc32, {
        goto next_sector;
      });
      seq_id = legacy_hdr->sequence_id;
      bank = legacy_hdr->tmr_data.active_stage1_bank;
      svn = 0; /* v1 has no stage1_svn */
      valid = true;
    } else if (magic == WAL_ABI_VERSION_MAGIC_CURRENT) {
      uint32_t calc_crc = compute_boot_crc32(
          (const uint8_t *)&hdr.data,
          offsetof(wal_sector_header_t, header_crc32));
      BOOT_SECURE_REQUIRE(calc_crc == hdr.data.header_crc32, {
        goto next_sector;
      });
      seq_id = hdr.data.sequence_id;
      bank = hdr.data.tmr_data.active_stage1_bank;
      svn = hdr.data.tmr_data.stage1_svn;
      valid = true;
    }

    if (valid && seq_id > highest_seq) {
      highest_seq = seq_id;
      *out_bank = bank;
      *out_svn = svn;
    }

next_sector:
    boot_secure_zeroize(&hdr, sizeof(hdr));
  }
}

uint32_t stage0_get_active_slot(const boot_platform_t *platform) {
  uint32_t bank = 0, svn = 0;
  stage0_scan_wal_highest(platform, &bank, &svn);
  (void)svn;
  return (bank == 0) ? CHIP_STAGE1A_ABS_ADDR : CHIP_STAGE1B_ABS_ADDR;
}

uint32_t stage0_get_stage1_svn(const boot_platform_t *platform) {
  uint32_t bank = 0, svn = 0;
  stage0_scan_wal_highest(platform, &bank, &svn);
  (void)bank;
  return svn;
}