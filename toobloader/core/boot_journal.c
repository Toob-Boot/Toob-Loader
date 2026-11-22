/*
 * ==============================================================================
 * Toob-Boot Core File: boot_journal.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/wal_internals.md (WAL, CRC-32, Triple Modular Redundancy)
 * - docs/concept_fusion.md (Brownout Recovery, O(1) Execution)
 * - docs/testing_requirements.md (P10 Compliance & Hardware Fault Protection)
 */

#include "boot_journal.h"
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_flash_guard.h"
#include "boot_identity.h"
#include "boot_merkle.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

#ifndef MAX_WAL_SECTORS
#define MAX_WAL_SECTORS 8
#endif

static uint32_t active_wal_index = 0;
static const uint32_t wal_sector_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
static const size_t wal_sector_sizes[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_SIZES;
static wal_sector_header_t current_active_header;
static wal_tmr_payload_t persisted_tmr_data;
static bool wal_initialized = false;
static bool tmr_defer_enabled = false;
static bool tmr_dirty = false;
static uint32_t cached_write_offset = 0;

/* K4: Device-bound journal chain state */
static uint8_t journal_key[WAL_CHAIN_TAG_BYTES];
static bool journal_key_valid = false;

/* ---- C5: Non-inline CRC helpers ---- */

static uint32_t sector_hdr_crc(const wal_sector_header_t *h) {
  return compute_boot_crc32((const uint8_t *)h, offsetof(wal_sector_header_t, header_crc32));
}

static uint32_t entry_crc(const wal_entry_payload_t *e) {
  return compute_boot_crc32((const uint8_t *)e, offsetof(wal_entry_payload_t, crc32_trailer));
}

/* ---- C4: Entry classification helper ---- */

typedef enum { WAL_E_ERASED, WAL_E_VALID, WAL_E_CORRUPT } wal_entry_state_t;

static wal_entry_state_t classify_entry(const wal_entry_aligned_t *e, uint8_t erased_val) {
  if (is_fully_erased_constant_time((const uint8_t *)e, sizeof(*e), erased_val)) {
    return WAL_E_ERASED;
  }
  if (e->data.magic == WAL_ENTRY_MAGIC && entry_crc(&e->data) == e->data.crc32_trailer) {
    return WAL_E_VALID;
  }
  return WAL_E_CORRUPT;
}

static void migrate_v1_tmr(wal_tmr_payload_t *dst, const wal_tmr_payload_v1_t *src) {
  boot_secure_zeroize(dst, sizeof(wal_tmr_payload_t));
  dst->struct_version = WAL_TMR_VERSION_CURRENT;
  dst->populated_size = WAL_TMR_POPULATED_SIZE;
  dst->primary_slot_id = src->primary_slot_id;
  dst->active_stage1_bank = src->active_stage1_bank;
  dst->app_svn = src->app_svn;
  dst->boot_failure_counter = src->boot_failure_counter;
  dst->svn_recovery_counter = src->svn_recovery_counter;
  dst->app_slot_erase_counter = src->app_slot_erase_counter;
  dst->staging_slot_erase_counter = src->staging_slot_erase_counter;
  dst->swap_buffer_erase_counter = src->swap_buffer_erase_counter;
  dst->active_nonce_lo = src->active_nonce_lo;
  dst->active_nonce_hi = src->active_nonce_hi;
  dst->_deprecated_kdm_sequence = src->kdm_sequence;
  dst->_deprecated_active_kdm_slot = src->active_kdm_slot;
  dst->stage1_svn = BOOT_STAGE1_SVN;
}

static void upgrade_tmr_payload(wal_tmr_payload_t *tmr) {
  if (tmr->struct_version < WAL_TMR_VERSION_2) {
    tmr->stage1_svn = BOOT_STAGE1_SVN;
  }
  if (tmr->struct_version < WAL_TMR_VERSION_4) {
    tmr->last_mbx_request_id = 0;
  }
  if (tmr->struct_version < WAL_TMR_VERSION_5) {
    tmr->recovery_failure_counter = 0;
  }
  if (tmr->struct_version < WAL_TMR_VERSION_6) {
    tmr->active_app_slot = 0;
    tmr->active_transport_id = 0;
  }
  if (tmr->struct_version < WAL_TMR_VERSION_7) {
    tmr->last_accepted_issued_at = 0;
  }
  if (tmr->struct_version < WAL_TMR_VERSION_8) {
    tmr->active_key_index = 0;
    tmr->pending_key_index = 0;
    tmr->app_build_number = 0;
    tmr->pending_build_number = 0;
    tmr->app_fw_major = 0;
    tmr->app_fw_minor = 0;
    tmr->app_fw_patch = 0;
    tmr->pending_fw_major = 0;
    tmr->pending_fw_minor = 0;
    tmr->pending_fw_patch = 0;
  }
  tmr->struct_version = WAL_TMR_VERSION_CURRENT;
  tmr->populated_size = WAL_TMR_POPULATED_SIZE;
}

/* ---- C2: Scatter-gather hash for K4 device-bound authentication ---- */

typedef struct {
  const uint8_t *p;
  size_t n;
} hash_seg_t;

static boot_status_t hash_chain_compute(const boot_platform_t *pf, const hash_seg_t *seg,
                                        size_t nseg, uint8_t out[WAL_CHAIN_TAG_BYTES]) {
  if (!pf || !pf->crypto || !pf->crypto->hash_init || !pf->crypto->hash_update ||
      !pf->crypto->hash_finish) {
    return BOOT_ERR_NOT_SUPPORTED;
  }
  uint8_t ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  boot_secure_zeroize(ctx, sizeof(ctx));
  boot_secure_zeroize(out, WAL_CHAIN_TAG_BYTES);

  boot_status_t s = pf->crypto->hash_init(ctx, sizeof(ctx));
  for (size_t i = 0; s == BOOT_OK && i < nseg; i++) {
    s = pf->crypto->hash_update(ctx, seg[i].p, seg[i].n);
  }

  uint8_t digest[32];
  size_t dl = sizeof(digest);
  if (s == BOOT_OK) {
    s = pf->crypto->hash_finish(ctx, digest, &dl);
    if (s == BOOT_OK) {
      memcpy(out, digest, WAL_CHAIN_TAG_BYTES);
    }
  } else {
    (void)pf->crypto->hash_finish(ctx, digest, &dl);
  }
  boot_secure_zeroize(digest, sizeof(digest));
  boot_secure_zeroize(ctx, sizeof(ctx));
  return s;
}

/**
 * @brief K4: Stateless device-bound MAC over wal_tmr_payload_t + eFuse epoch.
 *
 * Zeroes chain_tag in a local copy before hashing so verification on reboot
 * is deterministic across arbitrary sector rotations and brownouts.
 */
static boot_status_t compute_tmr_mac(const boot_platform_t *platform,
                                     const uint8_t key[WAL_CHAIN_TAG_BYTES],
                                     const wal_tmr_payload_t *tmr, uint32_t efuse_epoch,
                                     uint8_t out_tag[WAL_CHAIN_TAG_BYTES]) {
  wal_tmr_payload_t clean __attribute__((aligned(8)));
  memcpy(&clean, tmr, sizeof(clean));
  boot_secure_zeroize(clean.chain_tag, sizeof(clean.chain_tag));

  static const uint8_t domain_tmr[4] = {'K', '4', 'T', 'M'};
  hash_seg_t seg[] = {{domain_tmr, sizeof(domain_tmr)},
                      {key, WAL_CHAIN_TAG_BYTES},
                      {(const uint8_t *)&clean, sizeof(clean)},
                      {(const uint8_t *)&efuse_epoch, sizeof(efuse_epoch)}};
  boot_status_t s = hash_chain_compute(platform, seg, 4, out_tag);
  boot_secure_zeroize(&clean, sizeof(clean));
  return s;
}

/**
 * @brief K4: Device- & position-bound MAC for security-bearing WAL entries
 * (TXN_COMMIT, CONFIRM_COMMIT, DEVICE_LOCKED), stored in transfer_bitmap[4..7].
 */
static boot_status_t compute_entry_mac(const boot_platform_t *platform,
                                       const uint8_t key[WAL_CHAIN_TAG_BYTES],
                                       const wal_entry_payload_t *entry, uint32_t seq_id,
                                       uint32_t entry_offset,
                                       uint8_t out_tag[WAL_CHAIN_TAG_BYTES]) {
  wal_entry_payload_t clean __attribute__((aligned(8)));
  memcpy(&clean, entry, sizeof(clean));
  boot_secure_zeroize(&clean.transfer_bitmap[4], WAL_CHAIN_TAG_BYTES);
  clean.crc32_trailer = 0;

  static const uint8_t domain_ent[4] = {'K', '4', 'E', 'N'};
  hash_seg_t seg[] = {{domain_ent, sizeof(domain_ent)},
                      {key, WAL_CHAIN_TAG_BYTES},
                      {(const uint8_t *)&seq_id, sizeof(seq_id)},
                      {(const uint8_t *)&entry_offset, sizeof(entry_offset)},
                      {(const uint8_t *)&clean, offsetof(wal_entry_payload_t, crc32_trailer)}};
  boot_status_t s = hash_chain_compute(platform, seg, 5, out_tag);
  boot_secure_zeroize(&clean, sizeof(clean));
  return s;
}

static int tmr_majority_vote_idx(const wal_tmr_payload_t *c, int n) {
  size_t sz = sizeof(wal_tmr_payload_t);
  if (n >= 2 && constant_time_memcmp_glitch_safe((const uint8_t *)&c[0], (const uint8_t *)&c[1],
                                                 sz) == BOOT_OK) {
    return 0;
  }
  if (n == 3) {
    if (constant_time_memcmp_glitch_safe((const uint8_t *)&c[0], (const uint8_t *)&c[2], sz) ==
        BOOT_OK) {
      return 0;
    }
    if (constant_time_memcmp_glitch_safe((const uint8_t *)&c[1], (const uint8_t *)&c[2], sz) ==
        BOOT_OK) {
      return 1;
    }
  }
  return 0;
}

static bool verify_header_crc_glitch_safe(const wal_sector_header_aligned_t *aligned_header) {
  uint32_t magic = aligned_header->data.sector_magic;
  if (magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
    const wal_sector_header_v1_t *legacy_hdr =
        (const wal_sector_header_v1_t *)&aligned_header->data;
    uint32_t calc_crc = compute_boot_crc32((const uint8_t *)legacy_hdr,
                                           offsetof(wal_sector_header_v1_t, header_crc32));
    bool crc_ok = (calc_crc == legacy_hdr->header_crc32);
    BOOT_SECURE_REQUIRE(crc_ok, { return false; });
    return true;
  } else if (magic == WAL_ABI_VERSION_MAGIC_CURRENT) {
    uint32_t calc_crc = sector_hdr_crc(&aligned_header->data);
    bool crc_ok = (calc_crc == aligned_header->data.header_crc32);
    BOOT_SECURE_REQUIRE(crc_ok, { return false; });
    return true;
  }
  return false;
}

static bool read_header(const boot_platform_t *p, uint32_t idx,
                        wal_sector_header_aligned_t *out_hdr) {
  boot_secure_zeroize(out_hdr, sizeof(*out_hdr));
  if (p->flash->read(wal_sector_addrs[idx], (uint8_t *)out_hdr, sizeof(*out_hdr)) != BOOT_OK) {
    return false;
  }
  return verify_header_crc_glitch_safe(out_hdr);
}

static int32_t find_sector_by_seq(const boot_platform_t *p, uint32_t seq) {
  wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    if (read_header(p, i, &hdr) && hdr.data.sequence_id == seq) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return (int32_t)i;
    }
  }
  boot_secure_zeroize(&hdr, sizeof(hdr));
  return -1;
}

static boot_status_t smart_erase_sector(const boot_platform_t *platform, uint32_t sector_idx) {
  uint32_t addr = wal_sector_addrs[sector_idx];
  size_t sec_size = wal_sector_sizes[sector_idx];

  if (boot_flash_range_hits_immutable_boot(addr, sec_size)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  bool is_erased = false;
  if (boot_flash_is_erased(platform, addr, sec_size, &is_erased) == BOOT_OK && is_erased) {
    return BOOT_OK;
  }

  if (sec_size >= CHIP_FLASH_MAX_SECTOR_SIZE && platform->wdt &&
      platform->wdt->suspend_for_critical_section) {
    platform->wdt->suspend_for_critical_section();
  } else if (platform->wdt && platform->wdt->kick) {
    platform->wdt->kick();
  }

  boot_status_t status = boot_flash_erase_sector_guarded(platform->flash, addr);

  if (sec_size >= CHIP_FLASH_MAX_SECTOR_SIZE && platform->wdt && platform->wdt->resume) {
    platform->wdt->resume();
  } else if (platform->wdt && platform->wdt->kick) {
    platform->wdt->kick();
  }

  return status;
}

static boot_status_t rotate_to_sector(const boot_platform_t *p, uint32_t idx, uint32_t seq,
                                      const wal_tmr_payload_t *tmr, uint32_t *out_erase) {
  uint32_t prev = 0;
  {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    if (read_header(p, idx, &hdr)) {
      prev = hdr.data.erase_count;
    }
    boot_secure_zeroize(&hdr, sizeof(hdr));
  }

  boot_status_t s = smart_erase_sector(p, idx);
  if (s != BOOT_OK) {
    return s;
  }

  uint32_t next_erase = (prev < UINT32_MAX) ? (prev + 1U) : UINT32_MAX;
  wal_sector_header_aligned_t wh __attribute__((aligned(8)));
  memset(&wh, p->flash->erased_value, sizeof(wh));
  wh.data.sector_magic = WAL_ABI_VERSION_MAGIC;
  wh.data.sequence_id = seq;
  wh.data.erase_count = next_erase;
  wh.data.tmr_data = *tmr;
  if (journal_key_valid && wh.data.tmr_data.chain_entry_count > 0u) {
    uint32_t efuse_epoch = 0;
    (void)boot_read_monotonic_counter_safe(p, &efuse_epoch);
    (void)compute_tmr_mac(p, journal_key, &wh.data.tmr_data, efuse_epoch,
                          wh.data.tmr_data.chain_tag);
  }
  wh.data.header_crc32 = sector_hdr_crc(&wh.data);

  if (p->wdt && p->wdt->kick) {
    p->wdt->kick();
  }
  s = boot_flash_write_guarded(p->flash, wal_sector_addrs[idx], (const uint8_t *)&wh, sizeof(wh));
  boot_secure_zeroize(&wh, sizeof(wh));

  if (s == BOOT_OK && out_erase) {
    *out_erase = next_erase;
  }
  return s;
}

/**
 * @brief Findet den am wenigsten abgenutzten physischen Sektor (Wear-Leveling)
 * und respektiert exclude_indices strikt auch bei TOOB_WAL_SECTORS == 4.
 */
static uint32_t get_best_wear_leveling_sector(const boot_platform_t *platform, uint32_t highest_seq,
                                              const uint32_t *exclude_indices,
                                              uint8_t exclude_count) {
  uint32_t best_idx = 0xFFFFFFFFu;
  uint32_t min_erase = 0xFFFFFFFFu;
  uint32_t fallback_idx = 0xFFFFFFFFu;
  uint32_t fallback_age = 0u;
  uint32_t fallback_erase = 0xFFFFFFFFu;
  const uint32_t protect_win = (TOOB_WAL_SECTORS > 4u) ? WAL_PROTECT_WINDOW : 2u;

  wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    bool excluded = false;
    for (uint8_t j = 0; j < exclude_count; j++) {
      if (i == exclude_indices[j]) {
        excluded = true;
        break;
      }
    }
    if (excluded) {
      continue;
    }

    if (read_header(platform, i, &hdr)) {
      if (is_newer_sequence(hdr.data.sequence_id, highest_seq)) {
        continue;
      }
      uint32_t age = (highest_seq >= hdr.data.sequence_id)
                         ? (highest_seq - hdr.data.sequence_id)
                         : ((UINT32_MAX - hdr.data.sequence_id) + highest_seq + 1U);
      if (fallback_idx == 0xFFFFFFFFu || age > fallback_age ||
          (age == fallback_age && hdr.data.erase_count < fallback_erase)) {
        fallback_idx = i;
        fallback_age = age;
        fallback_erase = hdr.data.erase_count;
      }

      if (age < protect_win) {
        continue;
      }

      if (hdr.data.erase_count < min_erase) {
        min_erase = hdr.data.erase_count;
        best_idx = i;
      }
    } else {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return i;
    }
  }
  boot_secure_zeroize(&hdr, sizeof(hdr));
  if (best_idx != 0xFFFFFFFFu) {
    return best_idx;
  }
  return (fallback_idx != 0xFFFFFFFFu) ? fallback_idx : 0u;
}

static uint32_t scan_for_frontier_linear(const boot_platform_t *platform, uint32_t sector_addr,
                                         size_t sec_size, uint8_t erased_val) {
  uint32_t offset = sizeof(wal_sector_header_aligned_t);
  uint32_t frontier = offset;

  while (offset + sizeof(wal_entry_aligned_t) <= sec_size) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }

    wal_entry_aligned_t entry __attribute__((aligned(8)));

    if (platform->flash->read(sector_addr + offset, (uint8_t *)&entry, sizeof(entry)) != BOOT_OK) {
      break;
    }

    wal_entry_state_t es = classify_entry(&entry, erased_val);
    boot_secure_zeroize(&entry, sizeof(entry));
    if (es == WAL_E_ERASED) {
      return offset;
    }

    /* Advance past both valid and torn 64B-aligned slots to locate the first
     * virgin erased slot without forcing premature 4KB sector rotations. */
    offset += sizeof(wal_entry_aligned_t);
    frontier = offset;
  }
  return frontier;
}

/* ==============================================================================
 * PUBLIC WAL API
 * ==============================================================================
 */

boot_status_t boot_journal_init(const boot_platform_t *platform) {
  if (!platform || !platform->flash || !platform->wdt) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (TOOB_WAL_SECTORS < 4 || TOOB_WAL_SECTORS > MAX_WAL_SECTORS) {
    return BOOT_ERR_INVALID_ARG;
  }

  tmr_defer_enabled = false;
  tmr_dirty = false;

  /* 1. Layout Sanity Check */
  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    if (wal_sector_sizes[i] < sizeof(wal_sector_header_aligned_t) + sizeof(wal_entry_aligned_t)) {
      return BOOT_ERR_FLASH_HW;
    }
  }

  /* 1b. K4: Derive device-bound journal key BEFORE TMR verification */
  journal_key_valid = false;
  boot_secure_zeroize(journal_key, sizeof(journal_key));
  if (boot_derive_journal_key(platform, journal_key) == BOOT_OK) {
    journal_key_valid = true;
  }

  /* 2. Scan all sectors for highest sequence */
  uint32_t highest_seq = 0;
  int32_t highest_idx = -1;
  bool migration_required = false;
  wal_sector_header_aligned_t cached_winner __attribute__((aligned(8)));
  {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
      if (read_header(platform, i, &hdr)) {
        if (highest_idx == -1 || is_newer_sequence(hdr.data.sequence_id, highest_seq)) {
          highest_seq = hdr.data.sequence_id;
          highest_idx = (int32_t)i;
          cached_winner = hdr;
        }
      }
    }
    boot_secure_zeroize(&hdr, sizeof(hdr));
  }

  /* 3. Factory Blank Initialization or Majority Vote Recovery */
  if (highest_idx == -1) {
    active_wal_index = 0;
    boot_secure_zeroize(&current_active_header, sizeof(current_active_header));
    current_active_header.sector_magic = WAL_ABI_VERSION_MAGIC;
    current_active_header.sequence_id = 1;
    current_active_header.erase_count = 1;
    current_active_header.tmr_data.struct_version = WAL_TMR_VERSION_CURRENT;
    current_active_header.tmr_data.populated_size = WAL_TMR_POPULATED_SIZE;

    if (journal_key_valid) {
      uint32_t efuse_epoch = 0;
      (void)boot_read_monotonic_counter_safe(platform, &efuse_epoch);
      current_active_header.tmr_data.chain_entry_count = 1u;
      (void)compute_tmr_mac(platform, journal_key, &current_active_header.tmr_data, efuse_epoch,
                            current_active_header.tmr_data.chain_tag);
    }

    boot_status_t er_stat = smart_erase_sector(platform, 0);
    if (er_stat != BOOT_OK) {
      return er_stat;
    }

    current_active_header.header_crc32 = sector_hdr_crc(&current_active_header);

    wal_sector_header_aligned_t write_hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&write_hdr, sizeof(write_hdr));
    memset(&write_hdr, platform->flash->erased_value, sizeof(write_hdr));
    memcpy(&write_hdr.data, &current_active_header, sizeof(wal_sector_header_t));

    if (boot_flash_write_guarded(platform->flash, wal_sector_addrs[0], (const uint8_t *)&write_hdr,
                                 sizeof(write_hdr)) != BOOT_OK) {
      boot_secure_zeroize(&write_hdr, sizeof(write_hdr));
      return BOOT_ERR_FLASH;
    }
    boot_secure_zeroize(&write_hdr, sizeof(write_hdr));
  } else {
    active_wal_index = (uint32_t)highest_idx;

    bool legacy_migration = false;
    migration_required = false;
    if (cached_winner.data.sector_magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
      const wal_sector_header_v1_t *legacy_hdr =
          (const wal_sector_header_v1_t *)&cached_winner.data;

      current_active_header.sector_magic = WAL_ABI_VERSION_MAGIC_CURRENT;
      current_active_header.sequence_id = legacy_hdr->sequence_id;
      current_active_header.erase_count = legacy_hdr->erase_count;
      migrate_v1_tmr(&current_active_header.tmr_data, &legacy_hdr->tmr_data);
      upgrade_tmr_payload(&current_active_header.tmr_data);

      current_active_header.header_crc32 = sector_hdr_crc(&current_active_header);
      legacy_migration = true;
      migration_required = true;
    } else {
      current_active_header = cached_winner.data;
    }
    boot_secure_zeroize(&cached_winner, sizeof(cached_winner));

    if (current_active_header.tmr_data.struct_version > WAL_TMR_VERSION_CURRENT) {
      boot_terminal_halt(platform, BOOT_ERR_ABI_MISMATCH, SITE_TMR_FUTURE);
    }

    wal_tmr_payload_t tmr_candidates[3];
    boot_secure_zeroize(tmr_candidates, sizeof(tmr_candidates));
    tmr_candidates[0] = current_active_header.tmr_data;
    int num_candidates = 1;

    {
      wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
      for (uint32_t step = 1; step <= 2; step++) {
        if (highest_seq <= step && current_active_header.erase_count <= TOOB_WAL_SECTORS) {
          break;
        }

        uint32_t target_seq = highest_seq - step;
        bool found_contiguous = false;

        for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
          if (read_header(platform, i, &hdr) && hdr.data.sequence_id == target_seq) {
            if (hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
              const wal_sector_header_v1_t *legacy_shdr = (const wal_sector_header_v1_t *)&hdr.data;
              wal_tmr_payload_t converted_tmr;
              migrate_v1_tmr(&converted_tmr, &legacy_shdr->tmr_data);
              tmr_candidates[num_candidates++] = converted_tmr;
            } else {
              tmr_candidates[num_candidates++] = hdr.data.tmr_data;
            }
            found_contiguous = true;
            break;
          }
        }
        if (!found_contiguous) {
          break;
        }
      }
      boot_secure_zeroize(&hdr, sizeof(hdr));
    }

    if (num_candidates >= 2) {
      current_active_header.tmr_data =
          tmr_candidates[tmr_majority_vote_idx(tmr_candidates, num_candidates)];
    }
    boot_secure_zeroize(tmr_candidates, sizeof(tmr_candidates));

    /* K4: Authenticate persisted TMR BEFORE any struct_version upgrade so an
     * offline SPI attacker cannot downgrade struct_version to skip K4 MAC! */
    if (!legacy_migration && journal_key_valid &&
        current_active_header.tmr_data.chain_entry_count > 0u) {
      uint32_t efuse_epoch = 0;
      (void)boot_read_monotonic_counter_safe(platform, &efuse_epoch);
      uint8_t exp_tag[WAL_CHAIN_TAG_BYTES];
      boot_status_t mac_st = compute_tmr_mac(platform, journal_key, &current_active_header.tmr_data,
                                             efuse_epoch, exp_tag);
      bool tag_ok = (mac_st == BOOT_OK && constant_time_memcmp_glitch_safe(
                                              exp_tag, current_active_header.tmr_data.chain_tag,
                                              WAL_CHAIN_TAG_BYTES) == BOOT_OK);
      if (!tag_ok && efuse_epoch > 0u) {
        /* Brownout tolerance right after a +1 OTP monotonic advance */
        uint8_t prev_tag[WAL_CHAIN_TAG_BYTES];
        if (compute_tmr_mac(platform, journal_key, &current_active_header.tmr_data,
                            efuse_epoch - 1u, prev_tag) == BOOT_OK &&
            constant_time_memcmp_glitch_safe(prev_tag, current_active_header.tmr_data.chain_tag,
                                             WAL_CHAIN_TAG_BYTES) == BOOT_OK) {
          tag_ok = true;
          migration_required = true;
        }
        boot_secure_zeroize(prev_tag, sizeof(prev_tag));
      }
      boot_secure_zeroize(exp_tag, sizeof(exp_tag));
      BOOT_SECURE_REQUIRE(tag_ok, { return BOOT_ERR_VERIFY; });
    }

    if (!legacy_migration &&
        current_active_header.tmr_data.struct_version < WAL_TMR_VERSION_CURRENT) {
      upgrade_tmr_payload(&current_active_header.tmr_data);
      migration_required = true;
    }
  }

  /* 4. ECC-Safe Frontier Scan */
  cached_write_offset =
      scan_for_frontier_linear(platform, wal_sector_addrs[active_wal_index],
                               wal_sector_sizes[active_wal_index], platform->flash->erased_value);

  wal_initialized = true;

  if (migration_required) {
    boot_status_t mig_stat = boot_journal_update_tmr(platform, &current_active_header.tmr_data);
    if (mig_stat != BOOT_OK) {
      return mig_stat;
    }
  }

  persisted_tmr_data = current_active_header.tmr_data;
  return BOOT_OK;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform, wal_tmr_payload_t *out_tmr) {
  if (!platform || !out_tmr) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!wal_initialized) {
    return BOOT_ERR_STATE;
  }

  *out_tmr = current_active_header.tmr_data;
  return BOOT_OK;
}

boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform,
                                           wal_entry_payload_t *out_state, uint32_t *out_net_accum,
                                           uint32_t *out_resume_offset) {
  if (!platform || !platform->flash || !out_state) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!wal_initialized) {
    return BOOT_ERR_STATE;
  }

  memset(out_state, 0, sizeof(wal_entry_payload_t));
  if (out_net_accum) {
    *out_net_accum = 0;
  }
  if (out_resume_offset) {
    *out_resume_offset = 0;
  }

  bool found_main_intent = false;
  bool found_accum = false;
  bool found_resume = false;

  uint32_t search_seq = current_active_header.sequence_id;

  for (uint32_t step = 0; step < TOOB_WAL_SECTORS; step++) {
    int32_t sec_idx = find_sector_by_seq(platform, search_seq);

    if (sec_idx == -1) {
      if (search_seq <= 1 && current_active_header.erase_count <= TOOB_WAL_SECTORS) {
        break;
      }
      search_seq--;
      continue;
    }

    size_t sec_size = wal_sector_sizes[sec_idx];
    uint32_t current_offset;

    if (step == 0) {
      current_offset = cached_write_offset;
    } else {
      current_offset = scan_for_frontier_linear(platform, wal_sector_addrs[sec_idx], sec_size,
                                                platform->flash->erased_value);
    }

    while (current_offset >= (sizeof(wal_sector_header_aligned_t) + sizeof(wal_entry_aligned_t))) {
      current_offset -= (uint32_t)sizeof(wal_entry_aligned_t);

      wal_entry_aligned_t entry __attribute__((aligned(8)));

      if (platform->wdt && platform->wdt->kick) {
        platform->wdt->kick();
      }
      if (platform->flash->read(wal_sector_addrs[sec_idx] + current_offset, (uint8_t *)&entry,
                                sizeof(entry)) != BOOT_OK) {
        continue;
      }

      bool entry_valid = true;
      BOOT_SECURE_REQUIRE(classify_entry(&entry, platform->flash->erased_value) == WAL_E_VALID,
                          { entry_valid = false; });
      if (!entry_valid) {
        boot_secure_zeroize(&entry, sizeof(entry));
        continue;
      }

      uint32_t intent = entry.data.intent;

      /* K4: Authenticate security-bearing intents against offline SPI forgery/replay */
      if (journal_key_valid && current_active_header.tmr_data.chain_entry_count > 0u &&
          wal_intent_is_security_bearing(intent)) {
        uint8_t exp_mac[WAL_CHAIN_TAG_BYTES];
        boot_status_t mac_st = compute_entry_mac(platform, journal_key, &entry.data, search_seq,
                                                 current_offset, exp_mac);
        boot_status_t mac_ok =
            (mac_st == BOOT_OK)
                ? constant_time_memcmp_glitch_safe(
                      exp_mac, (const uint8_t *)&entry.data.transfer_bitmap[4], WAL_CHAIN_TAG_BYTES)
                : BOOT_ERR_VERIFY;
        boot_secure_zeroize(exp_mac, sizeof(exp_mac));
        if (mac_ok != BOOT_OK) {
          boot_secure_zeroize(&entry, sizeof(entry));
          return BOOT_ERR_VERIFY;
        }
      }

      if (intent == WAL_INTENT_NET_SEARCH_ACCUM) {
        if (!found_accum && out_net_accum) {
          *out_net_accum = entry.data.offset;
          found_accum = true;
        }
      } else if (intent == WAL_INTENT_DOWNLOAD_CHECKPOINT) {
        if (!found_resume && out_resume_offset) {
          *out_resume_offset = entry.data.delta_chunk_id;
          found_resume = true;
        }
      } else if (intent == WAL_INTENT_SLEEP_BACKOFF || intent == WAL_INTENT_DEPRECATED_NONCE) {
        /* Side-band intents do not alter the active transaction state.
         * NOTE: WAL_INTENT_TXN_ROLLBACK_PENDING IS a main transaction intent
         * and must be reconstructed so torn rollbacks resume after brownout! */
      } else {
        if (!found_main_intent) {
          memcpy(out_state, &entry.data, sizeof(wal_entry_payload_t));
          found_main_intent = true;
        }
      }

      boot_secure_zeroize(&entry, sizeof(entry));

      bool accum_ok = (found_accum || out_net_accum == NULL);
      bool resume_ok = (found_resume || out_resume_offset == NULL);
      if (found_main_intent && accum_ok && resume_ok) {
        break;
      }
    }

    bool accum_ok = (found_accum || out_net_accum == NULL);
    bool resume_ok = (found_resume || out_resume_offset == NULL);
    if (found_main_intent && accum_ok && resume_ok) {
      break;
    }

    if (search_seq <= 1 && current_active_header.erase_count <= TOOB_WAL_SECTORS) {
      break;
    }
    search_seq--;
  }

  if (found_main_intent) {
    return BOOT_OK;
  } else {
    return BOOT_ERR_STATE;
  }
}

/* ==============================================================================
 * ATOMIC APPEND & ROTATION ENGINE
 * ==============================================================================
 */

boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry) {
  if (!platform || !platform->flash || !new_entry) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!wal_initialized) {
    return BOOT_ERR_STATE;
  }

  size_t sec_size = wal_sector_sizes[active_wal_index];
  uint32_t target_offset = cached_write_offset;
  bool needs_rotation = false;

  if (target_offset + sizeof(wal_entry_aligned_t) <= sec_size) {
    uint8_t check_buf[sizeof(wal_entry_aligned_t)] __attribute__((aligned(8)));

    if (platform->flash->read(wal_sector_addrs[active_wal_index] + target_offset, check_buf,
                              sizeof(check_buf)) == BOOT_OK) {
      if (!is_fully_erased_constant_time(check_buf, sizeof(check_buf),
                                         platform->flash->erased_value)) {
        target_offset = 0;
        needs_rotation = true;
      }
    } else {
      target_offset = 0;
      needs_rotation = true;
    }
    boot_secure_zeroize(check_buf, sizeof(check_buf));
  } else {
    needs_rotation = true;
  }

  if (needs_rotation || target_offset == 0) {
    uint32_t exclude_list[1] = {active_wal_index};
    uint32_t new_idx =
        get_best_wear_leveling_sector(platform, current_active_header.sequence_id, exclude_list, 1);

    if (platform->flash->max_erase_cycles > 0 &&
        current_active_header.erase_count >= platform->flash->max_erase_cycles) {
      return BOOT_ERR_COUNTER_EXHAUSTED;
    }

    uint32_t new_erase = 0;
    boot_status_t status =
        rotate_to_sector(platform, new_idx, current_active_header.sequence_id + 1,
                         &current_active_header.tmr_data, &new_erase);
    if (status != BOOT_OK) {
      return status;
    }

    active_wal_index = new_idx;
    current_active_header.sequence_id++;
    current_active_header.erase_count = new_erase;
    target_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
    cached_write_offset = target_offset;
  }

  wal_entry_aligned_t entry __attribute__((aligned(8)));
  memset(&entry, platform->flash->erased_value, sizeof(entry));
  memcpy(&entry.data, new_entry, sizeof(wal_entry_payload_t));

  entry.data.magic = WAL_ENTRY_MAGIC;
  if (journal_key_valid && wal_intent_is_security_bearing(entry.data.intent)) {
    uint8_t mac_tag[WAL_CHAIN_TAG_BYTES];
    if (compute_entry_mac(platform, journal_key, &entry.data, current_active_header.sequence_id,
                          target_offset, mac_tag) == BOOT_OK) {
      memcpy(&entry.data.transfer_bitmap[4], mac_tag, WAL_CHAIN_TAG_BYTES);
    }
    boot_secure_zeroize(mac_tag, sizeof(mac_tag));
  }
  entry.data.crc32_trailer = entry_crc(&entry.data);

  if (platform->wdt && platform->wdt->kick) {
    platform->wdt->kick();
  }
  boot_status_t entry_status =
      boot_flash_write_guarded(platform->flash, wal_sector_addrs[active_wal_index] + target_offset,
                               (const uint8_t *)&entry, sizeof(entry));
  if (entry_status != BOOT_OK) {
    boot_secure_zeroize(&entry, sizeof(entry));
    return entry_status;
  }

  wal_entry_aligned_t verify_entry __attribute__((aligned(8)));
  boot_secure_zeroize(&verify_entry, sizeof(verify_entry));

  if (platform->flash->read(wal_sector_addrs[active_wal_index] + target_offset,
                            (uint8_t *)&verify_entry, sizeof(verify_entry)) != BOOT_OK ||
      constant_time_memcmp_glitch_safe((const uint8_t *)&entry, (const uint8_t *)&verify_entry,
                                       sizeof(entry)) != BOOT_OK) {
    cached_write_offset = (uint32_t)sec_size;
    boot_secure_zeroize(&entry, sizeof(entry));
    boot_secure_zeroize(&verify_entry, sizeof(verify_entry));
    return BOOT_ERR_FLASH_HW;
  }

  boot_secure_zeroize(&entry, sizeof(entry));
  boot_secure_zeroize(&verify_entry, sizeof(verify_entry));

  cached_write_offset = target_offset + (uint32_t)sizeof(wal_entry_aligned_t);
  return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
  if (!platform || !platform->flash || !platform->wdt || !new_tmr) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!wal_initialized) {
    return BOOT_ERR_STATE;
  }

  bool magic_legacy = false;
  {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    if (read_header(platform, active_wal_index, &hdr)) {
      if (hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
        magic_legacy = true;
      }
    }
    boot_secure_zeroize(&hdr, sizeof(hdr));
  }

  if (!magic_legacy && constant_time_memcmp_glitch_safe(
                           (const uint8_t *)&current_active_header.tmr_data,
                           (const uint8_t *)new_tmr, sizeof(wal_tmr_payload_t)) == BOOT_OK) {
    return BOOT_OK;
  }

  if (tmr_defer_enabled && !magic_legacy) {
    current_active_header.tmr_data = *new_tmr;
    current_active_header.tmr_data.struct_version = WAL_TMR_VERSION_CURRENT;
    current_active_header.tmr_data.populated_size = WAL_TMR_POPULATED_SIZE;
    tmr_dirty = (constant_time_memcmp_glitch_safe((const uint8_t *)&persisted_tmr_data,
                                                  (const uint8_t *)&current_active_header.tmr_data,
                                                  sizeof(wal_tmr_payload_t)) != BOOT_OK);
    return BOOT_OK;
  }

  if (platform->flash->max_erase_cycles > 0U &&
      (platform->flash->max_erase_cycles <= 3U ||
       current_active_header.erase_count >= platform->flash->max_erase_cycles - 3U)) {
    return BOOT_ERR_COUNTER_EXHAUSTED;
  }

  wal_tmr_payload_t tmr_to_write = *new_tmr;
  tmr_to_write.struct_version = WAL_TMR_VERSION_CURRENT;
  tmr_to_write.populated_size = WAL_TMR_POPULATED_SIZE;

  if (journal_key_valid) {
    uint32_t efuse_epoch = 0;
    (void)boot_read_monotonic_counter_safe(platform, &efuse_epoch);
    tmr_to_write.chain_entry_count =
        (tmr_to_write.chain_entry_count == 0u) ? 1u : (tmr_to_write.chain_entry_count + 1u);
    (void)compute_tmr_mac(platform, journal_key, &tmr_to_write, efuse_epoch,
                          tmr_to_write.chain_tag);
  }

  wal_entry_payload_t carry_txn __attribute__((aligned(8)));
  boot_secure_zeroize(&carry_txn, sizeof(carry_txn));
  bool has_carry_txn = (boot_journal_reconstruct_txn(platform, &carry_txn, NULL, NULL) == BOOT_OK &&
                        carry_txn.intent != (uint32_t)WAL_INTENT_NONE);

  uint32_t active_seq = current_active_header.sequence_id;
  uint32_t new_idx = active_wal_index;

  uint32_t exclude_list[4];
  exclude_list[0] = active_wal_index;
  uint8_t exclude_count = 1;
  uint32_t final_erase_count = current_active_header.erase_count;

  for (uint32_t step = 1; step <= 3; step++) {
    new_idx = get_best_wear_leveling_sector(platform, active_seq, exclude_list, exclude_count);
    exclude_list[exclude_count++] = new_idx;
    active_seq++;

    uint32_t new_erase = 0;
    boot_status_t status =
        rotate_to_sector(platform, new_idx, active_seq, &tmr_to_write, &new_erase);
    if (status != BOOT_OK) {
      boot_secure_zeroize(&carry_txn, sizeof(carry_txn));
      return status;
    }

    /* Anchor live non-NONE transaction in TMR backup sectors (steps 1..2) so a
     * 3-sector TMR rotation in a 4-sector WAL ring never orphans active state
     * across nested power-cuts, while keeping head sector (step 3) at +128B. */
    if (has_carry_txn && step < 3u) {
      wal_entry_aligned_t carry_entry __attribute__((aligned(8)));
      memset(&carry_entry, platform->flash->erased_value, sizeof(carry_entry));
      memcpy(&carry_entry.data, &carry_txn, sizeof(wal_entry_payload_t));
      carry_entry.data.magic = WAL_ENTRY_MAGIC;
      const uint32_t carry_off = (uint32_t)sizeof(wal_sector_header_aligned_t);
      if (journal_key_valid && wal_intent_is_security_bearing(carry_entry.data.intent)) {
        uint8_t mac_tag[WAL_CHAIN_TAG_BYTES];
        if (compute_entry_mac(platform, journal_key, &carry_entry.data, active_seq, carry_off,
                              mac_tag) == BOOT_OK) {
          memcpy(&carry_entry.data.transfer_bitmap[4], mac_tag, WAL_CHAIN_TAG_BYTES);
        }
        boot_secure_zeroize(mac_tag, sizeof(mac_tag));
      }
      carry_entry.data.crc32_trailer = entry_crc(&carry_entry.data);
      status = boot_flash_write_guarded(platform->flash, wal_sector_addrs[new_idx] + carry_off,
                                        (const uint8_t *)&carry_entry, sizeof(carry_entry));
      boot_secure_zeroize(&carry_entry, sizeof(carry_entry));
      if (status != BOOT_OK) {
        boot_secure_zeroize(&carry_txn, sizeof(carry_txn));
        return status;
      }
    }

    active_wal_index = new_idx;
    final_erase_count = new_erase;
  }
  boot_secure_zeroize(&carry_txn, sizeof(carry_txn));

  cached_write_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
  current_active_header.sequence_id = active_seq;
  current_active_header.erase_count = final_erase_count;
  current_active_header.tmr_data = tmr_to_write;
  current_active_header.header_crc32 = sector_hdr_crc(&current_active_header);
  persisted_tmr_data = tmr_to_write;
  tmr_dirty = false;

  return BOOT_OK;
}

void boot_journal_set_tmr_defer(bool defer) {
  tmr_defer_enabled = defer;
}

boot_status_t boot_journal_flush_tmr(const boot_platform_t *platform) {
  if (!platform || !platform->flash || !platform->wdt) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!wal_initialized) {
    return BOOT_ERR_STATE;
  }
  if (!tmr_dirty) {
    return BOOT_OK;
  }

  bool saved_defer = tmr_defer_enabled;
  wal_tmr_payload_t staged = current_active_header.tmr_data;
  current_active_header.tmr_data = persisted_tmr_data;
  tmr_defer_enabled = false;

  boot_status_t status = boot_journal_update_tmr(platform, &staged);
  tmr_defer_enabled = saved_defer;

  if (status != BOOT_OK) {
    current_active_header.tmr_data = staged;
    tmr_dirty = true;
  }
  return status;
}

boot_status_t boot_journal_reconstruct_aux_heal(const boot_platform_t *platform,
                                                wal_entry_payload_t *out_heal, bool *out_found) {
  if (!platform || !platform->flash || !out_heal || !out_found) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!wal_initialized) {
    return BOOT_ERR_STATE;
  }

  boot_secure_zeroize(out_heal, sizeof(*out_heal));
  *out_found = false;

  uint32_t search_seq = current_active_header.sequence_id;

  for (uint32_t step = 0U; step < TOOB_WAL_SECTORS; step++) {
    int32_t sec_idx = find_sector_by_seq(platform, search_seq);
    if (sec_idx == -1) {
      if (search_seq <= 1U && current_active_header.erase_count <= TOOB_WAL_SECTORS) {
        break;
      }
      search_seq--;
      continue;
    }

    size_t sec_size = wal_sector_sizes[sec_idx];
    uint32_t current_offset =
        (step == 0U) ? cached_write_offset
                     : scan_for_frontier_linear(platform, wal_sector_addrs[sec_idx], sec_size,
                                                platform->flash->erased_value);

    while (current_offset >= (sizeof(wal_sector_header_aligned_t) + sizeof(wal_entry_aligned_t))) {
      current_offset -= (uint32_t)sizeof(wal_entry_aligned_t);

      wal_entry_aligned_t entry __attribute__((aligned(8)));
      if (platform->wdt && platform->wdt->kick) {
        platform->wdt->kick();
      }
      if (platform->flash->read(wal_sector_addrs[sec_idx] + current_offset, (uint8_t *)&entry,
                                sizeof(entry)) != BOOT_OK) {
        continue;
      }

      if (classify_entry(&entry, platform->flash->erased_value) != WAL_E_VALID) {
        boot_secure_zeroize(&entry, sizeof(entry));
        continue;
      }

      uint32_t intent = entry.data.intent;

      if (journal_key_valid && current_active_header.tmr_data.chain_entry_count > 0U &&
          wal_intent_is_security_bearing(intent)) {
        uint8_t exp_mac[WAL_CHAIN_TAG_BYTES];
        boot_status_t mac_st = compute_entry_mac(platform, journal_key, &entry.data, search_seq,
                                                 current_offset, exp_mac);
        boot_status_t mac_ok =
            (mac_st == BOOT_OK)
                ? constant_time_memcmp_glitch_safe(
                      exp_mac, (const uint8_t *)&entry.data.transfer_bitmap[4], WAL_CHAIN_TAG_BYTES)
                : BOOT_ERR_VERIFY;
        boot_secure_zeroize(exp_mac, sizeof(exp_mac));
        if (mac_ok != BOOT_OK) {
          boot_secure_zeroize(&entry, sizeof(entry));
          return BOOT_ERR_VERIFY;
        }
      }

      if (intent == WAL_INTENT_NET_SEARCH_ACCUM || intent == WAL_INTENT_DOWNLOAD_CHECKPOINT ||
          intent == WAL_INTENT_SLEEP_BACKOFF || intent == WAL_INTENT_DEPRECATED_NONCE ||
          intent == WAL_INTENT_UPDATE_PENDING || intent == WAL_INTENT_TXN_BEGIN ||
          intent == WAL_INTENT_CLOUD_CMD) {
        boot_secure_zeroize(&entry, sizeof(entry));
        continue;
      }

      if (intent == WAL_INTENT_CONFIRM_COMMIT || intent == WAL_INTENT_RECOVERY_RESOLVED) {
        memcpy(out_heal, &entry.data, sizeof(*out_heal));
        *out_found = true;
        boot_secure_zeroize(&entry, sizeof(entry));
        return BOOT_OK;
      }

      /* Terminal epoch boundary reached (NONE, TXN_COMMIT, TXN_ROLLBACK, DEVICE_LOCKED) */
      boot_secure_zeroize(&entry, sizeof(entry));
      return BOOT_OK;
    }

    if (search_seq <= 1U && current_active_header.erase_count <= TOOB_WAL_SECTORS) {
      break;
    }
    search_seq--;
  }

  return BOOT_OK;
}
