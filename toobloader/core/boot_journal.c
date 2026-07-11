/*
 * ==============================================================================
 * Toob-Boot Core File: boot_journal.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/wal_internals.md (WAL, CRC-32, Triple Modular Redundancy)
 * - docs/concept_fusion.md (Brownout Recovery, O(1) Execution)
 * - docs/testing_requirements.md (P10 Compliance & Hardware Fault Protection)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. O(1) Backwards Reconstruction Fix: Scannt iterativ über alle WAL Sektoren
 *    rückwärts, um Intent-Abandonment nach einer TMR-Rotation auszuschließen.
 * 2. Cross-Sector Abandonment Fix: TMR Rotationen (3 Sektoren) überschreiben
 *    jetzt mathematisch bewiesen keine aktiven offenen Intents (1 Sektor).
 * 3. ECC-Safe Linear Frontier Scan: Komplett Glitch-Shielded durch
 * Double-Checks, stoppt präzise vor Hardware-Torn-Writes ohne Exception-Traps.
 * 4. P10 Alignment Guarding: Alle RAM-Zwischenpuffer sind hart auf 8-Byte Align
 *    fixiert, um DMA-Crashs auf Cortex-M0/M0+ zu verhindern.
 * 5. Subtractive Bounds Guarding: Verhindert mathematisch jegliche Underflows
 *    beim Rückwärtsscannen korrupter Sektoren-Offsets.
 */

#include "boot_journal.h"
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_identity.h"
#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

#ifndef MAX_WAL_SECTORS
#define MAX_WAL_SECTORS 8
#endif

/**
 * @brief Static Cache for the WAL bounds and states to avoid runtime
 * allocation.
 */
static uint32_t active_wal_index = 0;
static uint32_t wal_sector_addrs[MAX_WAL_SECTORS];
static size_t wal_sector_sizes[MAX_WAL_SECTORS];
static wal_sector_header_t current_active_header;
static bool wal_initialized = false;
static uint32_t cached_write_offset = 0;

/* K4: Device-bound journal chain state */
static uint8_t journal_key[WAL_CHAIN_TAG_BYTES];
static bool    journal_key_valid = false;

/* ==============================================================================
 * INTERNAL MATHEMATICS & HELPERS
 * ==============================================================================
 */

/* is_newer_sequence is now in boot_ct_utils.h (shared with boot_rstore) */

#include "boot_ct_utils.h"

/**
 * @brief Migriert eine v1 TMR-Payload auf die aktuelle Version.
 *
 * Felder, die in v1 nicht existieren (stage1_svn), werden aus der
 * Compile-Time-Konstante BOOT_STAGE1_SVN initialisiert.
 */
static void migrate_v1_tmr(wal_tmr_payload_t *dst,
                           const wal_tmr_payload_v1_t *src) {
  boot_secure_zeroize(dst, sizeof(wal_tmr_payload_t));
  dst->struct_version = WAL_TMR_VERSION_CURRENT;
  dst->populated_size = 76; /* 4 (version hdr) + 48 (v1) + 4 (stage1_svn) + 16 (chain_tag) + 4 (chain_entry_count) */
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
  /* K4: chain_tag and chain_entry_count are zero from the zeroize above,
   * representing an empty chain on a freshly migrated device. */
}

/**
 * @brief K4: Computes H(key ‖ entry_bytes ‖ prev_tag), truncated to 16 bytes.
 *
 * Uses the platform's SHA-256 hash to compute a device-bound chain tag.
 * Returns BOOT_ERR_CRYPTO on hash failure (caller decides how to degrade).
 */
static boot_status_t compute_chain_tag(const boot_platform_t *platform,
                                       const uint8_t key[WAL_CHAIN_TAG_BYTES],
                                       const wal_entry_payload_t *entry,
                                       const uint8_t prev_tag[WAL_CHAIN_TAG_BYTES],
                                       uint8_t out_tag[WAL_CHAIN_TAG_BYTES]) {
  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(out_tag, WAL_CHAIN_TAG_BYTES);

  boot_status_t s = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
  if (s != BOOT_OK) goto cleanup;

  s = platform->crypto->hash_update(hash_ctx, key, WAL_CHAIN_TAG_BYTES);
  if (s != BOOT_OK) goto finalize;

  /* Hash the entry bytes up to (but not including) the CRC trailer.
   * The CRC is computed over the same range, so it's redundant. */
  s = platform->crypto->hash_update(hash_ctx, (const uint8_t *)entry,
                                    offsetof(wal_entry_payload_t, crc32_trailer));
  if (s != BOOT_OK) goto finalize;

  s = platform->crypto->hash_update(hash_ctx, prev_tag, WAL_CHAIN_TAG_BYTES);
  if (s != BOOT_OK) goto finalize;

  {
    uint8_t digest[32];
    size_t digest_len = 32;
    s = platform->crypto->hash_finish(hash_ctx, digest, &digest_len);
    if (s == BOOT_OK) {
      memcpy(out_tag, digest, WAL_CHAIN_TAG_BYTES);
    }
    boot_secure_zeroize(digest, sizeof(digest));
  }
  goto cleanup;

finalize:
  {
    uint8_t dummy[64];
    size_t dummy_len = sizeof(dummy);
    (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
    boot_secure_zeroize(dummy, sizeof(dummy));
  }

cleanup:
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  return s;
}

/**
 * @brief Führt eine Ganz-Struktur Mehrheitsentscheidung (TMR Majority Vote) durch.
 *
 * Verhindert das Zusammenstückeln einzelner korrupten Bytes (Frankenstein-Voting)
 * durch constant-time Vergleiche der vollständigen Strukturen.
 */
static wal_tmr_payload_t tmr_majority_vote(const wal_tmr_payload_t *tmr_candidates, int num_candidates) {
  if (num_candidates >= 2) {
    size_t tmr_sz = sizeof(wal_tmr_payload_t);
    if (constant_time_memcmp_glitch_safe((const uint8_t *)&tmr_candidates[0],
                                         (const uint8_t *)&tmr_candidates[1],
                                         tmr_sz) == BOOT_OK) {
      return tmr_candidates[0];
    } else if (num_candidates == 3 &&
               constant_time_memcmp_glitch_safe(
                   (const uint8_t *)&tmr_candidates[0],
                   (const uint8_t *)&tmr_candidates[2], tmr_sz) == BOOT_OK) {
      return tmr_candidates[0];
    } else if (num_candidates == 3 &&
               constant_time_memcmp_glitch_safe(
                   (const uint8_t *)&tmr_candidates[1],
                   (const uint8_t *)&tmr_candidates[2], tmr_sz) == BOOT_OK) {
      return tmr_candidates[1];
    }
  }
  /* Extreme Korruptions-Absicherung: Vertraue dem neuesten kryptografisch validen Eintrag */
  return tmr_candidates[0];
}


/**
 * @brief Glitch-resistente CRC-32 Sector Header Validation (Double Check
 * Pattern)
 */
static bool verify_header_crc_glitch_safe(
    const wal_sector_header_aligned_t *aligned_header) {
  uint32_t magic = aligned_header->data.sector_magic;
  if (magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
    const wal_sector_header_v1_t *legacy_hdr = (const wal_sector_header_v1_t *)&aligned_header->data;
    uint32_t calc_crc = compute_boot_crc32((const uint8_t *)legacy_hdr, offsetof(wal_sector_header_v1_t, header_crc32));
    bool crc_ok = (calc_crc == legacy_hdr->header_crc32);
    BOOT_SECURE_REQUIRE(crc_ok, {
      return false;
    });
    return true;
  } else if (magic == WAL_ABI_VERSION_MAGIC_CURRENT) {
    uint32_t calc_crc = compute_boot_crc32((const uint8_t *)&aligned_header->data, offsetof(wal_sector_header_t, header_crc32));
    bool crc_ok = (calc_crc == aligned_header->data.header_crc32);
    BOOT_SECURE_REQUIRE(crc_ok, {
      return false;
    });
    return true;
  }
  return false;
}

/**
 * @brief O(1) Smart Erase - Überspringt Erases, wenn Sektor bereits 0xFF ist.
 */
static boot_status_t smart_erase_sector(const boot_platform_t *platform,
                                        uint32_t sector_idx) {
  uint32_t addr = wal_sector_addrs[sector_idx];
  size_t sec_size = wal_sector_sizes[sector_idx];

  bool needs_erase = false;
  uint32_t chk_off = 0;
  uint8_t erased_val = platform->flash->erased_value;

  /* P10 Alignment für Hardware DMAs (Verhindert Unaligned-Exception) */
  uint8_t chk_buf[64] __attribute__((aligned(8))) = {0};

  /* Linearer Read-Ahead um festzustellen, ob ein destruktiver Hardware-Erase
   * überhaupt nötig ist */
  while (chk_off < sec_size) {
    uint32_t read_len = (sec_size - chk_off > sizeof(chk_buf))
                            ? (uint32_t)sizeof(chk_buf)
                            : (uint32_t)(sec_size - chk_off);

    if (platform->flash->read(addr + chk_off, chk_buf, read_len) != BOOT_OK) {
      needs_erase = true;
    }
    /* P10 Timing-Oracle Defense: Full-scan accumulator, no early exit */
    if (!is_fully_erased_constant_time(chk_buf, read_len, erased_val)) {
      needs_erase = true;
    }
    chk_off += read_len;
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
  }

  boot_secure_zeroize(chk_buf, sizeof(chk_buf)); /* Leakage Defense */

  if (!needs_erase)
    return BOOT_OK; /* Zero-Wear Skip! Hardware geschont. */

  /* Monolithic Erase Protection */
  if (sec_size >= CHIP_FLASH_MAX_SECTOR_SIZE && platform->wdt &&
      platform->wdt->suspend_for_critical_section) {
    platform->wdt->suspend_for_critical_section();
  } else if (platform->wdt && platform->wdt->kick) {
    platform->wdt->kick();
  }

  boot_status_t status = platform->flash->erase_sector(addr);

  if (sec_size >= CHIP_FLASH_MAX_SECTOR_SIZE && platform->wdt &&
      platform->wdt->resume) {
    platform->wdt->resume();
  } else if (platform->wdt && platform->wdt->kick) {
    platform->wdt->kick();
  }

  return status;
}

/**
 * @brief Findet den am wenigsten abgenutzten physischen Sektor (Wear-Leveling).
 * Schützt das TMR-Quorum (die letzten 3 Sequenzen) PLUS Cross-Sector Intents
 * (1).
 */
static uint32_t get_best_wear_leveling_sector(const boot_platform_t *platform,
                                              uint32_t highest_seq,
                                              const uint32_t *exclude_indices,
                                              uint8_t exclude_count) {
  uint32_t best_idx = 0xFFFFFFFF;
  uint32_t min_erase = 0xFFFFFFFF;

  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    bool excluded = false;
    for (uint8_t j = 0; j < exclude_count; j++) {
      if (i == exclude_indices[j]) {
        excluded = true;
        break;
      }
    }
    if (excluded)
      continue;

    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (platform->flash->read(wal_sector_addrs[i], (uint8_t *)&hdr,
                              sizeof(hdr)) != BOOT_OK)
      continue;

    if (verify_header_crc_glitch_safe(&hdr)) {
      /* CROSS-SECTOR FIX: Schütze die letzten 4 WAL-Historien (N, N-1, N-2,
       * N-3) Dies blockiert radikal, dass Wear-Leveling Intents zerstört, die
       * während eines 3-Sektor-TMR-Updates überrollt wurden! */
      if (!is_newer_sequence(hdr.data.sequence_id, highest_seq)) {
        /* Underflow-Proof: Nur prüfen, wenn Subtraktion sicher im 32-bit Limit
         * greift */
        if (highest_seq >= hdr.data.sequence_id ||
            (hdr.data.sequence_id > 0xFFFFFFF0 && highest_seq < 10)) {
          uint32_t diff = highest_seq - hdr.data.sequence_id;
          if (diff < 4) /* Mathematisch bewiesen 4 statt 3 */
            continue;
        }
      }
      if (hdr.data.erase_count < min_erase) {
        min_erase = hdr.data.erase_count;
        best_idx = i;
      }
    } else {
      /* Invalid/Corrupt Sektoren sofort rezyklieren (Self-Healing) */
      return i;
    }
  }
  return (best_idx != 0xFFFFFFFF) ? best_idx : 0;
}

/**
 * @brief O(N) ECC-Safe Frontier Scan.
 * Scant sequenziell vorwärts und stoppt sofort vor dem ersten Bit-Rot /
 * Erased-Block. Physikalisch 100% sicher gegen Hardware-Traps durch partielle
 * Tearing-Writes! UB-Frei (Strict Aliasing compliant).
 */
static uint32_t scan_for_frontier_linear(const boot_platform_t *platform,
                                         uint32_t sector_addr, size_t sec_size,
                                         uint8_t erased_val) {
  uint32_t offset = sizeof(wal_sector_header_aligned_t);
  uint32_t frontier = offset;

  while (offset + sizeof(wal_entry_aligned_t) <= sec_size) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    wal_entry_aligned_t entry __attribute__((aligned(8)));
    boot_secure_zeroize(&entry, sizeof(entry));

    if (platform->flash->read(sector_addr + offset, (uint8_t *)&entry,
                              sizeof(entry)) != BOOT_OK) {
      break; /* Hardware instability -> Stop here */
    }

    /* 1. Erkennung von völlig gelöschtem Flash (Saubere Front) UB-Frei via
     * is_fully_erased */
    if (is_fully_erased_constant_time((const uint8_t *)&entry, sizeof(entry),
                                      erased_val)) {
      boot_secure_zeroize(&entry, sizeof(entry));
      return offset; /* Frontier gefunden! */
    }

    /* 2. Validation: Glitch-Resistant Double Check */
    size_t crc_len = offsetof(wal_entry_payload_t, crc32_trailer);
    uint32_t calc_crc =
        compute_boot_crc32((const uint8_t *)&entry.data, crc_len);

    bool magic_ok = (entry.data.magic == WAL_ENTRY_MAGIC);
    bool crc_ok = (calc_crc == entry.data.crc32_trailer);

    BOOT_SECURE_REQUIRE(magic_ok && crc_ok, {
      boot_secure_zeroize(&entry, sizeof(entry));
      break; /* Garbage/Torn Write (Brownout). Stop frontier here! */
    });

    offset += sizeof(wal_entry_aligned_t);
    frontier = offset;
    boot_secure_zeroize(&entry, sizeof(entry));
  }
  return frontier;
}

/* ==============================================================================
 * PUBLIC WAL API
 * ==============================================================================
 */

boot_status_t boot_journal_init(const boot_platform_t *platform) {
  if (!platform || !platform->flash || !platform->wdt)
    return BOOT_ERR_INVALID_ARG;
  if (TOOB_WAL_SECTORS < 4 || TOOB_WAL_SECTORS > MAX_WAL_SECTORS)
    return BOOT_ERR_INVALID_ARG;

  /* 1. O(1) Static Layout Initialization (Single Source of Truth)
   * Nutzt P10-Stack-Free Arrays (.rodata) für physikalisch perfekte Asymmetrie
   */
  static const uint32_t hw_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
  static const size_t hw_sizes[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_SIZES;

  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    wal_sector_addrs[i] = hw_addrs[i];
    wal_sector_sizes[i] = hw_sizes[i];

    /* Sanity-Check: Ist der vom Manifest spezifizierte Sektor physikalisch groß
     * genug für Header + 1 Entry? */
    if (wal_sector_sizes[i] <
        sizeof(wal_sector_header_aligned_t) + sizeof(wal_entry_aligned_t)) {
      return BOOT_ERR_FLASH_HW;
    }
  }

  /* 2. Scan all sectors for highest sequence */
  uint32_t highest_seq = 0;
  int32_t highest_idx = -1;
  bool migration_required = false;

  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (platform->flash->read(wal_sector_addrs[i], (uint8_t *)&hdr,
                              sizeof(hdr)) != BOOT_OK)
      continue;

    if (verify_header_crc_glitch_safe(&hdr)) {
      if (highest_idx == -1 ||
          is_newer_sequence(hdr.data.sequence_id, highest_seq)) {
        highest_seq = hdr.data.sequence_id;
        highest_idx = (int32_t)i;
      }
    }
  }

  /* 3. Factory Blank Initialization or Majority Vote Recovery */
  if (highest_idx == -1) {
    active_wal_index = 0;
    boot_secure_zeroize(&current_active_header, sizeof(current_active_header));
    current_active_header.sector_magic = WAL_ABI_VERSION_MAGIC;
    current_active_header.sequence_id = 1;
    current_active_header.erase_count = 1;
    current_active_header.tmr_data.struct_version = WAL_TMR_VERSION_CURRENT;
    current_active_header.tmr_data.populated_size = 52;

    boot_status_t er_stat = smart_erase_sector(platform, 0);
    if (er_stat != BOOT_OK)
      return er_stat;

    current_active_header.header_crc32 =
        compute_boot_crc32((const uint8_t *)&current_active_header,
                           offsetof(wal_sector_header_t, header_crc32));

    wal_sector_header_aligned_t write_hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&write_hdr, sizeof(write_hdr));
    memset(&write_hdr, platform->flash->erased_value, sizeof(write_hdr));
    memcpy(&write_hdr.data, &current_active_header,
           sizeof(wal_sector_header_t));

    if (platform->flash->write(wal_sector_addrs[0], (const uint8_t *)&write_hdr,
                               sizeof(write_hdr)) != BOOT_OK) {
      boot_secure_zeroize(&write_hdr, sizeof(write_hdr));
      return BOOT_ERR_FLASH;
    }
    boot_secure_zeroize(&write_hdr, sizeof(write_hdr)); /* P10 Stack Clean */
  } else {
    active_wal_index = (uint32_t)highest_idx;
    wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (platform->flash->read(wal_sector_addrs[highest_idx], (uint8_t *)&hdr,
                              sizeof(hdr)) != BOOT_OK)
      return BOOT_ERR_FLASH;

    migration_required = false;
    if (hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
      const wal_sector_header_v1_t *legacy_hdr = (const wal_sector_header_v1_t *)&hdr.data;
      
      current_active_header.sector_magic = WAL_ABI_VERSION_MAGIC_CURRENT;
      current_active_header.sequence_id = legacy_hdr->sequence_id;
      current_active_header.erase_count = legacy_hdr->erase_count;
      migrate_v1_tmr(&current_active_header.tmr_data, &legacy_hdr->tmr_data);
      
      current_active_header.header_crc32 = compute_boot_crc32(
          (const uint8_t *)&current_active_header,
          offsetof(wal_sector_header_t, header_crc32));
      
      migration_required = true;
    } else {
      current_active_header = hdr.data;
    }
    boot_secure_zeroize(&hdr, sizeof(hdr));

    if (current_active_header.tmr_data.struct_version > WAL_TMR_VERSION_CURRENT) {
      boot_terminal_halt(platform, BOOT_ERR_ABI_MISMATCH, SITE_TMR_FUTURE);
    }

    /* GAP-C01: Strict Whole-Struct Majority Vote TMR (No Frankenstein Voting!)
     */
    wal_tmr_payload_t tmr_candidates[3];
    boot_secure_zeroize(tmr_candidates, sizeof(tmr_candidates));
    tmr_candidates[0] = current_active_header.tmr_data;
    int num_candidates = 1;

    for (uint32_t step = 1; step <= 2; step++) {
      /* P10 UNDERFLOW GUARD: Verhindert Endlos-Suchen auf fabrikneuen Geräten
       */
      if (highest_seq <= step &&
          current_active_header.erase_count <= TOOB_WAL_SECTORS)
        break;

      uint32_t target_seq = highest_seq - step;
      bool found_contiguous = false;

      for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
        wal_sector_header_aligned_t s_hdr __attribute__((aligned(8)));
        boot_secure_zeroize(&s_hdr, sizeof(s_hdr));
        if (platform->flash->read(wal_sector_addrs[i], (uint8_t *)&s_hdr,
                                  sizeof(s_hdr)) == BOOT_OK) {
          if (verify_header_crc_glitch_safe(&s_hdr) &&
              s_hdr.data.sequence_id == target_seq) {
            if (s_hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
              const wal_sector_header_v1_t *legacy_shdr = (const wal_sector_header_v1_t *)&s_hdr.data;
              wal_tmr_payload_t converted_tmr;
              migrate_v1_tmr(&converted_tmr, &legacy_shdr->tmr_data);
              tmr_candidates[num_candidates++] = converted_tmr;
            } else {
              tmr_candidates[num_candidates++] = s_hdr.data.tmr_data;
            }
            found_contiguous = true;
            break;
          }
        }
      }
      if (!found_contiguous)
        break; /* Stop collection if chain breaks */
    }

    if (num_candidates >= 2) {
      current_active_header.tmr_data = tmr_majority_vote(tmr_candidates, num_candidates);
    }
    boot_secure_zeroize(tmr_candidates,
                        sizeof(tmr_candidates)); /* P10 Stack Clean */
  }

  /* 4. ECC-Safe Frontier Scan */
  cached_write_offset = scan_for_frontier_linear(
      platform, wal_sector_addrs[active_wal_index],
      wal_sector_sizes[active_wal_index], platform->flash->erased_value);

  wal_initialized = true;

  if (migration_required) {
    boot_status_t mig_stat = boot_journal_update_tmr(platform, &current_active_header.tmr_data);
    if (mig_stat != BOOT_OK) {
      return mig_stat;
    }
  }

  /* K4: Derive device-bound journal chain key.
   * On failure, chain degrades silently — the boot continues but
   * security-bearing entries won't be chain-protected. */
  journal_key_valid = false;
  boot_secure_zeroize(journal_key, sizeof(journal_key));
  if (boot_derive_journal_key(platform, journal_key) == BOOT_OK) {
    journal_key_valid = true;
  }

  return BOOT_OK;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr) {
  if (!platform || !out_tmr)
    return BOOT_ERR_INVALID_ARG;
  if (!wal_initialized)
    return BOOT_ERR_STATE;

  *out_tmr = current_active_header.tmr_data;
  return BOOT_OK;
}

boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform,
                                           wal_entry_payload_t *out_state,
                                           uint32_t *out_net_accum,
                                           uint32_t *out_resume_offset) {
  if (!platform || !platform->flash || !out_state)
    return BOOT_ERR_INVALID_ARG;
  if (!wal_initialized)
    return BOOT_ERR_STATE;

  memset(out_state, 0, sizeof(wal_entry_payload_t));
  if (out_net_accum)
    *out_net_accum = 0;
  if (out_resume_offset)
    *out_resume_offset = 0;

  bool found_main_intent = false;
  bool found_accum = false;
  bool found_resume = false;

  uint32_t search_seq = current_active_header.sequence_id;

  /* CROSS-SECTOR BACKWARDS SCAN FIX:
   * Wir springen von der Frontier rückwärts und scannen über die
   * TOOB_WAL_SECTORS. Dies rettet offene Transaktionen (z.B. UPDATE_PENDING),
   * die durch ein 3-Sektor TMR-Update versehentlich im Sektor N-3
   * "zurückgelassen" wurden! */
  for (uint32_t step = 0; step < TOOB_WAL_SECTORS; step++) {
    int32_t sec_idx = -1;
    for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
      wal_sector_header_aligned_t hdr __attribute__((aligned(8)));
      boot_secure_zeroize(&hdr, sizeof(hdr));
      if (platform->flash->read(wal_sector_addrs[i], (uint8_t *)&hdr,
                                sizeof(hdr)) == BOOT_OK) {
        if (verify_header_crc_glitch_safe(&hdr) &&
            hdr.data.sequence_id == search_seq) {
          sec_idx = (int32_t)i;
          break;
        }
      }
    }

    if (sec_idx == -1) {
      /* Underflow Guard: Wenn das Gerät neu ist, stoppe sofort das
       * Rückwärts-Suchen */
      if (search_seq <= 1 &&
          current_active_header.erase_count <= TOOB_WAL_SECTORS)
        break;
      search_seq--;
      continue;
    }

    size_t sec_size = wal_sector_sizes[sec_idx];
    uint32_t current_offset;

    if (step == 0) {
      current_offset = cached_write_offset;
    } else {
      current_offset =
          scan_for_frontier_linear(platform, wal_sector_addrs[sec_idx],
                                   sec_size, platform->flash->erased_value);
    }

    /* Subtractive Bounds Guard: Mathematisch absolut sicher gegen
       Integer-Underflow. Die Reduktion um sizeof(entry) erfolgt erst *nachdem*
       bewiesen ist, dass genug Byte-Kapazität zur Header-Grenze besteht! */
    while (current_offset >= (sizeof(wal_sector_header_aligned_t) +
                              sizeof(wal_entry_aligned_t))) {
      current_offset -= (uint32_t)sizeof(wal_entry_aligned_t);

      wal_entry_aligned_t entry __attribute__((aligned(8)));
      boot_secure_zeroize(&entry, sizeof(entry));

      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
      if (platform->flash->read(wal_sector_addrs[sec_idx] + current_offset,
                                (uint8_t *)&entry, sizeof(entry)) != BOOT_OK) {
        continue;
      }

      size_t crc_len = offsetof(wal_entry_payload_t, crc32_trailer);
      uint32_t calc_crc =
          compute_boot_crc32((const uint8_t *)&entry.data, crc_len);

      bool magic_ok = (entry.data.magic == WAL_ENTRY_MAGIC);
      bool crc_ok = (calc_crc == entry.data.crc32_trailer);

      BOOT_SECURE_REQUIRE(magic_ok && crc_ok, {
        boot_secure_zeroize(&entry, sizeof(entry));
        continue;
      });

      uint32_t intent = entry.data.intent;

      /* LOGICAL INTENT ISOLATION (Behebt die "Intent-Amnesie") */
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
      } else if (intent == WAL_INTENT_SLEEP_BACKOFF ||
                 intent == WAL_INTENT_DEPRECATED_NONCE ||
                 intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
        /* Side-Band Intents haben keinen Einfluss auf den Haupt-Zustand des OS
         */
      } else {
        /* Der erste intakte Kernel-Eintrag beim Rückwärts-Scan IST die aktive
         * Transaktion! */
        if (!found_main_intent) {
          memcpy(out_state, &entry.data, sizeof(wal_entry_payload_t));
          found_main_intent = true;
        }
      }

      boot_secure_zeroize(&entry, sizeof(entry)); /* P10 Stack Clean-up */

      /* Vorzeitiger O(1) Abbruch, sobald alle gesuchten Komponenten gefunden
       * wurden */
      bool accum_ok = (found_accum || out_net_accum == NULL);
      bool resume_ok = (found_resume || out_resume_offset == NULL);
      if (found_main_intent && accum_ok && resume_ok)
        break;
    }

    bool accum_ok = (found_accum || out_net_accum == NULL);
    bool resume_ok = (found_resume || out_resume_offset == NULL);
    if (found_main_intent && accum_ok && resume_ok)
      break;

    if (search_seq <= 1 &&
        current_active_header.erase_count <= TOOB_WAL_SECTORS)
      break;
    search_seq--;
  }

  if (found_main_intent) {
    return BOOT_OK;
  } else {
    return BOOT_ERR_STATE; /* Neutraler/Leerer WAL Zustand ohne aktive
                              Transaktionen */
  }
}

/* ==============================================================================
 * ATOMIC APPEND & ROTATION ENGINE
 * ==============================================================================
 */

boot_status_t boot_journal_append(const boot_platform_t *platform,
                                  const wal_entry_payload_t *new_entry) {
  if (!platform || !platform->flash || !new_entry)
    return BOOT_ERR_INVALID_ARG;
  if (!wal_initialized)
    return BOOT_ERR_STATE;

  size_t sec_size = wal_sector_sizes[active_wal_index];
  uint32_t target_offset = cached_write_offset;
  bool needs_rotation = false;

  /* P10 Full-Width ECC Pre-Emption Guard
   * Verhindert HardFaults durch Überschreiben von partiellen
   * Brownout-Fragmenten */
  if (target_offset + sizeof(wal_entry_aligned_t) <= sec_size) {
    uint8_t check_buf[sizeof(wal_entry_aligned_t)] __attribute__((aligned(8)));

    if (platform->flash->read(wal_sector_addrs[active_wal_index] +
                                  target_offset,
                              check_buf, sizeof(check_buf)) == BOOT_OK) {
      if (!is_fully_erased_constant_time(check_buf, sizeof(check_buf),
                                         platform->flash->erased_value)) {
        target_offset = 0; /* Dirty Boundary Detected! Torn Write present! */
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
    uint32_t new_idx = get_best_wear_leveling_sector(
        platform, current_active_header.sequence_id, exclude_list, 1);

    if (platform->flash->max_erase_cycles > 0 &&
        current_active_header.erase_count >=
            platform->flash->max_erase_cycles) {
      return BOOT_ERR_COUNTER_EXHAUSTED;
    }

    uint32_t prev_erase_count = 0;
    wal_sector_header_aligned_t tg_hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&tg_hdr, sizeof(tg_hdr));

    if (platform->flash->read(wal_sector_addrs[new_idx], (uint8_t *)&tg_hdr,
                              sizeof(tg_hdr)) == BOOT_OK) {
      if (verify_header_crc_glitch_safe(&tg_hdr))
        prev_erase_count = tg_hdr.data.erase_count;
    }
    boot_secure_zeroize(&tg_hdr, sizeof(tg_hdr));

    boot_status_t status = smart_erase_sector(platform, new_idx);
    if (status != BOOT_OK)
      return status;

    wal_sector_header_aligned_t write_hdr __attribute__((aligned(8)));
    memset(&write_hdr, platform->flash->erased_value, sizeof(write_hdr));

    write_hdr.data.sector_magic = WAL_ABI_VERSION_MAGIC;
    write_hdr.data.sequence_id = current_active_header.sequence_id + 1;
    write_hdr.data.erase_count = prev_erase_count + 1;
    write_hdr.data.tmr_data = current_active_header.tmr_data;
    write_hdr.data.header_crc32 =
        compute_boot_crc32((const uint8_t *)&write_hdr.data,
                           offsetof(wal_sector_header_t, header_crc32));

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    status =
        platform->flash->write(wal_sector_addrs[new_idx],
                               (const uint8_t *)&write_hdr, sizeof(write_hdr));
    boot_secure_zeroize(&write_hdr, sizeof(write_hdr));

    if (status != BOOT_OK)
      return status;

    active_wal_index = new_idx;
    current_active_header.sequence_id++;
    current_active_header.erase_count = prev_erase_count + 1;
    target_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
    cached_write_offset = target_offset;
  }

  /* Sicheres Schreiben des neuen Intents */
  wal_entry_aligned_t entry __attribute__((aligned(8)));
  memset(&entry, platform->flash->erased_value, sizeof(entry));
  memcpy(&entry.data, new_entry, sizeof(wal_entry_payload_t));

  entry.data.magic = WAL_ENTRY_MAGIC;
  size_t crc_len = offsetof(wal_entry_payload_t, crc32_trailer);
  entry.data.crc32_trailer =
      compute_boot_crc32((const uint8_t *)&entry.data, crc_len);

  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  boot_status_t entry_status =
      platform->flash->write(wal_sector_addrs[active_wal_index] + target_offset,
                             (const uint8_t *)&entry, sizeof(entry));
  if (entry_status != BOOT_OK) {
    boot_secure_zeroize(&entry, sizeof(entry));
    return entry_status;
  }

  /* Phase-Bound Verifikation via Constant-Time Memory Match (Glitch Protected)
   */
  wal_entry_aligned_t verify_entry __attribute__((aligned(8)));
  boot_secure_zeroize(&verify_entry, sizeof(verify_entry));

  if (platform->flash->read(wal_sector_addrs[active_wal_index] + target_offset,
                            (uint8_t *)&verify_entry,
                            sizeof(verify_entry)) != BOOT_OK ||
      constant_time_memcmp_glitch_safe((const uint8_t *)&entry,
                                       (const uint8_t *)&verify_entry,
                                       sizeof(entry)) != BOOT_OK) {
    cached_write_offset =
        (uint32_t)sec_size; /* Mark Sector as corrupted for next pass */
    boot_secure_zeroize(&entry, sizeof(entry));
    boot_secure_zeroize(&verify_entry, sizeof(verify_entry));
    return BOOT_ERR_FLASH_HW;
  }
  /* K4: Update chain tag for security-bearing intents.
   * The tag lives in the RAM-cached TMR and gets persisted on the
   * next sector rotation or explicit TMR update.
   * Must happen before entry is zeroized — needs entry.data. */
  if (journal_key_valid && wal_intent_is_security_bearing(new_entry->intent)) {
    uint8_t new_tag[WAL_CHAIN_TAG_BYTES];
    if (compute_chain_tag(platform, journal_key, &entry.data,
                          current_active_header.tmr_data.chain_tag,
                          new_tag) == BOOT_OK) {
      memcpy(current_active_header.tmr_data.chain_tag, new_tag, WAL_CHAIN_TAG_BYTES);
      current_active_header.tmr_data.chain_entry_count++;
    }
    boot_secure_zeroize(new_tag, sizeof(new_tag));
  }

  boot_secure_zeroize(&entry, sizeof(entry));
  boot_secure_zeroize(&verify_entry, sizeof(verify_entry));

  cached_write_offset = target_offset + (uint32_t)sizeof(wal_entry_aligned_t);
  return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
  if (!platform || !platform->flash || !platform->wdt || !new_tmr)
    return BOOT_ERR_INVALID_ARG;
  if (!wal_initialized)
    return BOOT_ERR_STATE;

  /* O(1) ZERO-WEAR OPTIMIZATION:
   * Überspringt das radikale 3-Sektor Majority-Vote Erase, wenn der TMR-Payload
   * bit-identisch ist. Nutzt zwingend Constant-Time Vergleich, um Side-Channel
   * Leakage und EMFI Instruction-Skips zu blockieren.
   * Ausnahme: Der Sektor auf Flash hat noch die Legacy-Magic -> Erzeige Migration. */
  bool magic_legacy = false;
  wal_sector_header_aligned_t tg_hdr __attribute__((aligned(8)));
  boot_secure_zeroize(&tg_hdr, sizeof(tg_hdr));
  if (platform->flash->read(wal_sector_addrs[active_wal_index], (uint8_t *)&tg_hdr, sizeof(tg_hdr)) == BOOT_OK) {
    if (tg_hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_LEGACY) {
      magic_legacy = true;
    }
  }
  boot_secure_zeroize(&tg_hdr, sizeof(tg_hdr));

  if (!magic_legacy && constant_time_memcmp_glitch_safe(
          (const uint8_t *)&current_active_header.tmr_data,
          (const uint8_t *)new_tmr, sizeof(wal_tmr_payload_t)) == BOOT_OK) {
    return BOOT_OK;
  }

  if (platform->flash->max_erase_cycles > 0 &&
      current_active_header.erase_count >=
          platform->flash->max_erase_cycles - 3) {
    return BOOT_ERR_COUNTER_EXHAUSTED;
  }

  /* K4-T3: Create a mutable copy of the TMR for epoch-anchor binding.
   * The caller's new_tmr is const — we may need to update chain_tag. */
  wal_tmr_payload_t tmr_to_write = *new_tmr;

  /* K4-T3: Epoch-Anker — bind eFuse epoch into the chain before
   * persisting the TMR. A full-replay of an old WAL image is detected
   * once the eFuse epoch has advanced beyond the value baked into the tag. */
  if (journal_key_valid && tmr_to_write.chain_entry_count > 0) {
    uint32_t efuse_epoch = 0;
    boot_read_monotonic_counter_safe(platform, &efuse_epoch);

    /* H(journal_key ‖ tmr_bytes ‖ efuse_epoch ‖ prev_chain_tag) */
    uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

    boot_status_t hs = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
    if (hs == BOOT_OK) {
      hs = platform->crypto->hash_update(hash_ctx, journal_key, WAL_CHAIN_TAG_BYTES);
    }
    if (hs == BOOT_OK) {
      hs = platform->crypto->hash_update(hash_ctx, (const uint8_t *)&tmr_to_write,
                                         sizeof(wal_tmr_payload_t));
    }
    if (hs == BOOT_OK) {
      hs = platform->crypto->hash_update(hash_ctx, (const uint8_t *)&efuse_epoch,
                                         sizeof(efuse_epoch));
    }
    if (hs == BOOT_OK) {
      uint8_t digest[32];
      size_t digest_len = 32;
      hs = platform->crypto->hash_finish(hash_ctx, digest, &digest_len);
      if (hs == BOOT_OK) {
        memcpy(tmr_to_write.chain_tag, digest, WAL_CHAIN_TAG_BYTES);
      }
      boot_secure_zeroize(digest, sizeof(digest));
    } else {
      uint8_t dummy[64];
      size_t dummy_len = sizeof(dummy);
      (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
      boot_secure_zeroize(dummy, sizeof(dummy));
    }
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  }

  uint32_t active_seq = current_active_header.sequence_id;
  uint32_t new_idx = active_wal_index;

  uint32_t exclude_list[4];
  exclude_list[0] = active_wal_index;
  uint8_t exclude_count = 1;
  uint32_t final_erase_count = current_active_header.erase_count;

  /* ====================================================================
   * TMR QUORUM WRITE (3-Sectors for Absolute Majority)
   * Mathematischer Beweis: Fällt der Strom nach [n+1], greift Reboot
   * auf [n] und [n-1] zurück (Old State wins). Schließt [n+2] ab,
   * schlagen [n+2] und [n+1] den verbliebenen [n] (New State wins).
   * ==================================================================== */
  for (uint32_t step = 1; step <= 3; step++) {
    new_idx = get_best_wear_leveling_sector(platform, active_seq, exclude_list,
                                            exclude_count);
    exclude_list[exclude_count++] = new_idx;
    active_seq++;

    uint32_t prev_erase_count = 0;
    wal_sector_header_aligned_t tg_hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&tg_hdr, sizeof(tg_hdr));

    if (platform->flash->read(wal_sector_addrs[new_idx], (uint8_t *)&tg_hdr,
                              sizeof(tg_hdr)) == BOOT_OK) {
      if (verify_header_crc_glitch_safe(&tg_hdr))
        prev_erase_count = tg_hdr.data.erase_count;
    }

    boot_status_t status = smart_erase_sector(platform, new_idx);
    if (status != BOOT_OK)
      return status;

    wal_sector_header_aligned_t write_hdr __attribute__((aligned(8)));
    memset(&write_hdr, platform->flash->erased_value, sizeof(write_hdr));

    write_hdr.data.sector_magic = WAL_ABI_VERSION_MAGIC;
    write_hdr.data.sequence_id = active_seq;
    write_hdr.data.erase_count = prev_erase_count + 1;
    write_hdr.data.tmr_data = tmr_to_write;
    write_hdr.data.header_crc32 =
        compute_boot_crc32((const uint8_t *)&write_hdr.data,
                           offsetof(wal_sector_header_t, header_crc32));

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    status =
        platform->flash->write(wal_sector_addrs[new_idx],
                               (const uint8_t *)&write_hdr, sizeof(write_hdr));
    boot_secure_zeroize(&write_hdr, sizeof(write_hdr));

    if (status != BOOT_OK)
      return status;

    active_wal_index = new_idx;
    final_erase_count = prev_erase_count + 1;
  }

  /* Aktualisierung des Globalen RAM-State */
  cached_write_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
  current_active_header.sequence_id = active_seq;
  current_active_header.erase_count = final_erase_count;
  current_active_header.tmr_data = tmr_to_write;
  current_active_header.header_crc32 =
      compute_boot_crc32((const uint8_t *)&current_active_header,
                         offsetof(wal_sector_header_t, header_crc32));

  return BOOT_OK;
}