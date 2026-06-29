/**
 * @file stage0_svn.c
 * @brief Stage-0 SVN Infrastructure for Self-Anti-Rollback (P7a)
 *
 * Provides O(1) WAL-scan functions for Stage 0 to retrieve the persisted
 * stage1_svn and evaluate per-bank boot eligibility. Stage 0 cannot use the
 * full boot_journal_get_tmr() machinery — this is a minimal extraction.
 *
 * Relevant Specs:
 * - docs/concept_fusion.md (Phase 7a)
 */

#include "generated_boot_config.h"
#include "boot_crc32.h"
#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"
#include "boot_fih.h"

/**
 * @brief Read stage1_svn from WAL TMR via O(1) sector header scan.
 *
 * Scans all WAL sectors, finds the one with the highest sequence_id,
 * and extracts tmr_data.stage1_svn. Returns 0 on blank/unreadable WAL
 * (safe baseline: no floor enforced).
 */
uint32_t stage0_get_stage1_svn(const boot_platform_t *platform) {
  const uint32_t wal_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
  uint32_t highest_seq = 0;
  uint32_t result_svn = 0;

  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (platform->flash->read(wal_addrs[i], (uint8_t *)&hdr, sizeof(hdr)) !=
        BOOT_OK) {
      goto next_sector;
    }

    uint32_t magic = hdr.data.sector_magic;
    uint32_t seq_id = 0;
    uint32_t svn = 0;
    bool valid = false;

    if (magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
      /* v1 sectors have no stage1_svn — baseline 0 */
      const wal_sector_header_v1_t *legacy_hdr =
          (const wal_sector_header_v1_t *)&hdr.data;
      uint32_t calc_crc = compute_boot_crc32(
          (const uint8_t *)legacy_hdr,
          offsetof(wal_sector_header_v1_t, header_crc32));
      BOOT_SECURE_REQUIRE(calc_crc == legacy_hdr->header_crc32, {
        goto next_sector;
      });
      seq_id = legacy_hdr->sequence_id;
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
      svn = hdr.data.tmr_data.stage1_svn;
      valid = true;
    }

    if (valid && seq_id > highest_seq) {
      highest_seq = seq_id;
      result_svn = svn;
    }

next_sector:
    boot_secure_zeroize(&hdr, sizeof(hdr));
  }
  return result_svn;
}
