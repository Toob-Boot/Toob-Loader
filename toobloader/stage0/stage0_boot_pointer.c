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

#include "boot_crc32.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include "stage0_crypto.h"

static bool stage0_seq_is_newer(uint32_t candidate, uint32_t current) {
  uint32_t diff =
      (candidate >= current) ? (candidate - current) : ((UINT32_MAX - current) + candidate + 1U);
  return (candidate != current) && (diff < 0x80000000U);
}

/**
 * @brief O(1) WAL TMR quorum scan — extracts active_stage1_bank and stage1_svn.
 *
 * Enforces 2-of-3 TMR majority quorum across CRC-valid WAL sector headers
 * (HIGH-28). When migrating a single-sector legacy/fresh WAL (valid_count == 1),
 * accepts the single valid sector including sequence_id == 0. Under multi-sector
 * split-brain without quorum, fails safe to bank 0 while preserving max(svn).
 */
static void stage0_scan_wal_quorum(const boot_platform_t *platform, uint32_t *out_bank,
                                   uint32_t *out_svn) {
  *out_bank = 0U;
  *out_svn = 0U;

  if (!platform || !platform->flash || !platform->flash->read) {
    return;
  }

  const uint32_t wal_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
  uint32_t valid_seq[TOOB_WAL_SECTORS];
  uint32_t valid_bank[TOOB_WAL_SECTORS];
  uint32_t valid_svn[TOOB_WAL_SECTORS];
  uint32_t valid_count = 0U;
  uint32_t max_valid_svn = 0U;

  for (uint32_t i = 0U; i < TOOB_WAL_SECTORS; i++) {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (platform->flash->read(wal_addrs[i], (uint8_t *)&hdr, sizeof(hdr)) != BOOT_OK) {
      goto next_sector;
    }

    uint32_t magic = hdr.data.sector_magic;
    uint32_t seq_id = 0U;
    uint32_t bank = 0U;
    uint32_t svn = 0U;
    bool valid = false;

    if (magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
      const wal_sector_header_v1_t *legacy_hdr = (const wal_sector_header_v1_t *)&hdr.data;
      uint32_t calc_crc = compute_boot_crc32((const uint8_t *)legacy_hdr,
                                             offsetof(wal_sector_header_v1_t, header_crc32));
      BOOT_SECURE_REQUIRE(calc_crc == legacy_hdr->header_crc32, { goto next_sector; });
      seq_id = legacy_hdr->sequence_id;
      bank = (legacy_hdr->tmr_data.active_stage1_bank == 0U) ? 0U : 1U;
      svn = 0U;
      valid = true;
    } else if (magic == WAL_ABI_VERSION_MAGIC_CURRENT) {
      uint32_t calc_crc = compute_boot_crc32((const uint8_t *)&hdr.data,
                                             offsetof(wal_sector_header_t, header_crc32));
      BOOT_SECURE_REQUIRE(calc_crc == hdr.data.header_crc32, { goto next_sector; });
      seq_id = hdr.data.sequence_id;
      bank = (hdr.data.tmr_data.active_stage1_bank == 0U) ? 0U : 1U;
      svn = hdr.data.tmr_data.stage1_svn;
      valid = true;
    }

    if (valid) {
      valid_seq[valid_count] = seq_id;
      valid_bank[valid_count] = bank;
      valid_svn[valid_count] = svn;
      if (svn > max_valid_svn) {
        max_valid_svn = svn;
      }
      valid_count++;
    }

  next_sector:
    boot_secure_zeroize(&hdr, sizeof(hdr));
  }

  if (valid_count == 0U) {
    return;
  }

  if (valid_count == 1U) {
    *out_bank = valid_bank[0];
    *out_svn = valid_svn[0];
    return;
  }

  bool quorum_found = false;
  uint32_t best_seq = 0U;
  uint32_t best_bank = 0U;
  uint32_t best_svn = max_valid_svn;

  for (uint32_t i = 0U; i < valid_count; i++) {
    uint32_t matches = 0U;
    uint32_t group_newest_seq = valid_seq[i];
    for (uint32_t j = 0U; j < valid_count; j++) {
      if (valid_bank[j] == valid_bank[i] && valid_svn[j] == valid_svn[i]) {
        matches++;
        if (stage0_seq_is_newer(valid_seq[j], group_newest_seq)) {
          group_newest_seq = valid_seq[j];
        }
      }
    }
    if (matches >= 2U) {
      if (!quorum_found || stage0_seq_is_newer(group_newest_seq, best_seq)) {
        quorum_found = true;
        best_seq = group_newest_seq;
        best_bank = valid_bank[i];
        best_svn = valid_svn[i];
      }
    }
  }

  *out_bank = best_bank;
  *out_svn = best_svn;
}

uint32_t stage0_read_wal_boot_meta(const boot_platform_t *platform, uint32_t *out_svn) {
  uint32_t bank = 0U;
  uint32_t svn = 0U;
  stage0_scan_wal_quorum(platform, &bank, &svn);
  if (out_svn != NULL) {
    *out_svn = svn;
  }
  return (bank == 0U) ? CHIP_STAGE1A_ABS_ADDR : CHIP_STAGE1B_ABS_ADDR;
}
