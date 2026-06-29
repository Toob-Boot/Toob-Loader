/**
 * @file boot_rstore.c
 * @brief Generic Quorum-Protected Redundant Store (Phase 4 Implementation)
 *
 * Implements the reusable quorum-vote, self-healing, and smart-erase
 * machinery extracted from boot_journal.c's TMR logic.
 *
 * REFERENCED SPECIFICATIONS:
 * - plan.md Phase 4 (Redundanz-Konvergenz: KDM → Quorum)
 * - docs/wal_internals.md (Original TMR mechanics)
 *
 * ARCHITECTURAL INVARIANTS:
 * 1. Whole-Struct Vote: Records are compared as complete units, never
 *    mixed byte-by-byte across slots (no Frankenstein records).
 * 2. Bounded Healing: At most 1 sector erase + 1 record write per read,
 *    under wdt->suspend_for_critical_section(). O(1) WDT profile.
 * 3. Underflow-Safe Sequencing: RFC 1982 arithmetic prevents wrap-around
 *    bugs in sequence comparison.
 * 4. Smart-Erase: Skips hardware erase if the target sector is already
 *    fully erased (0xFF), saving flash wear.
 */

#include "boot_rstore.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_fih.h"
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include <string.h>

#define RSTORE_MAX_SLOTS 8
#define RSTORE_MAX_RECORD_BYTES 256

_Static_assert(sizeof(boot_rstore_slot_header_t) == 16,
               "Slot header size assumption violated");

/* ============================================================================
 * INTERNAL: Smart Erase (Zero-Wear Skip)
 * ============================================================================ */

/**
 * @brief Erases a sector only if it contains non-erased data.
 */
static boot_status_t rstore_smart_erase(const boot_platform_t *platform,
                                        uint32_t addr, size_t sec_size) {
  bool needs_erase = false;
  uint32_t chk_off = 0;
  uint8_t erased_val = platform->flash->erased_value;
  uint8_t chk_buf[64] __attribute__((aligned(8))) = {0};

  /* P10 R2: Loop bounded by sec_size / sizeof(chk_buf).
   * Max iterations: CHIP_FLASH_MAX_SECTOR_SIZE / 64 = typically 64. */
  uint32_t max_iterations = (uint32_t)(sec_size / sizeof(chk_buf)) + 1;
  uint32_t iteration = 0;
  while (chk_off < sec_size && iteration < max_iterations) {
    uint32_t read_len = (sec_size - chk_off > sizeof(chk_buf))
                            ? (uint32_t)sizeof(chk_buf)
                            : (uint32_t)(sec_size - chk_off);

    if (platform->flash->read(addr + chk_off, chk_buf, read_len) != BOOT_OK) {
      needs_erase = true;
    }
    if (!is_fully_erased_constant_time(chk_buf, read_len, erased_val)) {
      needs_erase = true;
    }
    chk_off += read_len;
    iteration++;
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
  }

  boot_secure_zeroize(chk_buf, sizeof(chk_buf));

  if (!needs_erase)
    return BOOT_OK;

  /* Caller is responsible for WDT suspend/resume if needed */
  return platform->flash->erase_sector(addr);
}

/* ============================================================================
 * INTERNAL: Slot I/O
 * ============================================================================ */

/**
 * @brief Reads and validates a single slot's header + record.
 *
 * @param out_hdr    Filled with the slot header on success
 * @param out_record Filled with the record data on success
 * @return true if the slot contains a valid, CRC-verified record
 */
static bool rstore_read_slot(const boot_platform_t *platform,
                             const boot_rstore_desc_t *desc,
                             uint8_t slot_idx,
                             boot_rstore_slot_header_t *out_hdr,
                             uint8_t *out_record) {
  uint32_t addr = desc->slot_addrs[slot_idx];
  uint8_t read_buf[sizeof(boot_rstore_slot_header_t) + RSTORE_MAX_RECORD_BYTES]
      __attribute__((aligned(8)));

  uint32_t total_read = (uint32_t)(sizeof(boot_rstore_slot_header_t) +
                                   desc->record_size);
  if (total_read > sizeof(read_buf))
    return false;

  boot_secure_zeroize(read_buf, sizeof(read_buf));

  if (platform->flash->read(addr, read_buf, total_read) != BOOT_OK) {
    boot_secure_zeroize(read_buf, sizeof(read_buf));
    return false;
  }

  /* Extract header */
  memcpy(out_hdr, read_buf, sizeof(boot_rstore_slot_header_t));

  /* Magic check */
  if (out_hdr->magic != desc->magic) {
    boot_secure_zeroize(read_buf, sizeof(read_buf));
    return false;
  }

  /* CRC-32 over full header (with CRC field zeroed) + record.
   * The header_crc32 is at offset 12, so we zero it in the buffer
   * for verification, then compare against the stored value. */
  uint32_t stored_crc = out_hdr->header_crc32;
  uint32_t zero = 0;
  memcpy(read_buf + offsetof(boot_rstore_slot_header_t, header_crc32),
         &zero, sizeof(uint32_t));

  uint32_t calc_crc = compute_boot_crc32(read_buf, total_read);

  bool crc_ok = (calc_crc == stored_crc);
  BOOT_SECURE_REQUIRE(crc_ok, {
    boot_secure_zeroize(read_buf, sizeof(read_buf));
    return false;
  });

  /* Extract record */
  memcpy(out_record, read_buf + sizeof(boot_rstore_slot_header_t),
         desc->record_size);

  boot_secure_zeroize(read_buf, sizeof(read_buf));
  return true;
}

/**
 * @brief Writes a header + record to a single slot.
 */
static boot_status_t rstore_write_slot(const boot_platform_t *platform,
                                       const boot_rstore_desc_t *desc,
                                       uint8_t slot_idx,
                                       uint32_t sequence_id,
                                       uint32_t erase_count,
                                       const uint8_t *record) {
  uint32_t addr = desc->slot_addrs[slot_idx];
  uint8_t write_buf[sizeof(boot_rstore_slot_header_t) + RSTORE_MAX_RECORD_BYTES]
      __attribute__((aligned(8)));
  uint32_t total_write = (uint32_t)(sizeof(boot_rstore_slot_header_t) +
                                    desc->record_size);
  if (total_write > sizeof(write_buf))
    return BOOT_ERR_INVALID_ARG;

  memset(write_buf, platform->flash->erased_value, sizeof(write_buf));

  /* Build header */
  boot_rstore_slot_header_t hdr;
  hdr.magic = desc->magic;
  hdr.sequence_id = sequence_id;
  hdr.erase_count = erase_count;
  hdr.header_crc32 = 0; /* Placeholder for CRC computation */

  memcpy(write_buf, &hdr, sizeof(boot_rstore_slot_header_t));
  memcpy(write_buf + sizeof(boot_rstore_slot_header_t), record,
         desc->record_size);

  /* CRC-32 over full header (with CRC field zeroed) + record */
  uint32_t calc_crc = compute_boot_crc32(write_buf, total_write);

  /* Patch CRC into the write buffer at the header_crc32 offset */
  memcpy(write_buf + offsetof(boot_rstore_slot_header_t, header_crc32),
         &calc_crc, sizeof(uint32_t));

  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  boot_status_t status = platform->flash->write(addr, write_buf, total_write);

  boot_secure_zeroize(write_buf, sizeof(write_buf));
  return status;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

boot_status_t boot_rstore_read(const boot_platform_t *platform,
                               const boot_rstore_desc_t *desc,
                               void *out_record) {
  if (!platform || !platform->flash || !platform->wdt || !desc || !out_record)
    return BOOT_ERR_INVALID_ARG;
  if (desc->slot_count < 3 || desc->slot_count > RSTORE_MAX_SLOTS)
    return BOOT_ERR_INVALID_ARG;
  if (desc->record_size == 0 || desc->record_size > RSTORE_MAX_RECORD_BYTES)
    return BOOT_ERR_INVALID_ARG;

  /* Read all slots */
  boot_rstore_slot_header_t headers[RSTORE_MAX_SLOTS];
  uint8_t records[RSTORE_MAX_SLOTS][RSTORE_MAX_RECORD_BYTES];
  bool valid[RSTORE_MAX_SLOTS];
  uint8_t valid_count = 0;

  boot_secure_zeroize(headers, sizeof(headers));
  boot_secure_zeroize(records, sizeof(records));
  boot_secure_zeroize(valid, sizeof(valid));

  for (uint8_t i = 0; i < desc->slot_count; i++) {
    valid[i] = rstore_read_slot(platform, desc, i, &headers[i], records[i]);
    if (valid[i])
      valid_count++;
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
  }

  if (valid_count == 0) {
    boot_secure_zeroize(headers, sizeof(headers));
    boot_secure_zeroize(records, sizeof(records));
    return BOOT_ERR_NOT_FOUND;
  }

  /* Find the record with the highest valid sequence */
  uint8_t newest_idx = 0xFF;
  uint32_t newest_seq = 0;
  for (uint8_t i = 0; i < desc->slot_count; i++) {
    if (!valid[i])
      continue;
    if (newest_idx == 0xFF ||
        is_newer_sequence(headers[i].sequence_id, newest_seq)) {
      newest_seq = headers[i].sequence_id;
      newest_idx = i;
    }
  }

  /* Whole-Struct Majority Vote among valid slots */
  uint8_t majority_record[RSTORE_MAX_RECORD_BYTES];
  boot_secure_zeroize(majority_record, sizeof(majority_record));
  bool majority_found = false;
  uint8_t majority_idx = newest_idx;

  if (valid_count >= 2) {
    /* Count agreements with the newest record */
    uint8_t agree_count = 1; /* The newest slot agrees with itself */
    for (uint8_t i = 0; i < desc->slot_count; i++) {
      if (!valid[i] || i == newest_idx)
        continue;
      if (constant_time_memcmp_glitch_safe(
              records[newest_idx], records[i], desc->record_size) == BOOT_OK) {
        agree_count++;
      }
    }

    if (agree_count >= 2) {
      /* Newest record has majority agreement */
      memcpy(majority_record, records[newest_idx], desc->record_size);
      majority_found = true;
    } else {
      /* Newest record is the odd one out — check other pairs */
      for (uint8_t i = 0; i < desc->slot_count && !majority_found; i++) {
        if (!valid[i] || i == newest_idx)
          continue;
        uint8_t pair_agree = 1;
        for (uint8_t j = i + 1; j < desc->slot_count; j++) {
          if (!valid[j] || j == newest_idx)
            continue;
          if (constant_time_memcmp_glitch_safe(
                  records[i], records[j], desc->record_size) == BOOT_OK) {
            pair_agree++;
          }
        }
        if (pair_agree >= 2) {
          memcpy(majority_record, records[i], desc->record_size);
          majority_idx = i;
          majority_found = true;
        }
      }
    }
  }

  if (!majority_found) {
    /* No majority — trust the newest valid record as best-effort */
    memcpy(majority_record, records[newest_idx], desc->record_size);
    majority_found = true;
  }

  /* Output the resolved record */
  memcpy(out_record, majority_record, desc->record_size);

  /* Bounded Opportunistic Healing:
   * If any slot is invalid or disagrees with majority, repair exactly one
   * under WDT suspension. O(1) profile: 1 erase + 1 write. */
  for (uint8_t i = 0; i < desc->slot_count; i++) {
    bool needs_heal = false;

    if (!valid[i]) {
      needs_heal = true;
    } else if (constant_time_memcmp_glitch_safe(
                   records[i], majority_record, desc->record_size) != BOOT_OK) {
      needs_heal = true;
    }

    if (needs_heal) {
      /* Heal exactly one slot, then stop (bounded) */
      uint32_t heal_erase_count = valid[i] ? headers[i].erase_count : 0;
      uint32_t heal_seq = newest_seq + 1;

      if (platform->wdt && platform->wdt->suspend_for_critical_section)
        platform->wdt->suspend_for_critical_section();

      boot_status_t erase_stat =
          rstore_smart_erase(platform, desc->slot_addrs[i], desc->slot_sizes[i]);
      if (erase_stat == BOOT_OK) {
        (void)rstore_write_slot(platform, desc, i, heal_seq,
                                heal_erase_count + 1, majority_record);
      }

      if (platform->wdt && platform->wdt->resume)
        platform->wdt->resume();

      break; /* Bounded: heal at most one slot per read */
    }
  }

  boot_secure_zeroize(headers, sizeof(headers));
  boot_secure_zeroize(records, sizeof(records));
  boot_secure_zeroize(majority_record, sizeof(majority_record));

  return BOOT_OK;
}

boot_status_t boot_rstore_write(const boot_platform_t *platform,
                                const boot_rstore_desc_t *desc,
                                const void *record) {
  if (!platform || !platform->flash || !platform->wdt || !desc || !record)
    return BOOT_ERR_INVALID_ARG;
  if (desc->slot_count < 3 || desc->slot_count > RSTORE_MAX_SLOTS)
    return BOOT_ERR_INVALID_ARG;
  if (desc->record_size == 0 || desc->record_size > RSTORE_MAX_RECORD_BYTES)
    return BOOT_ERR_INVALID_ARG;

  /* Determine the current highest sequence across all slots */
  uint32_t highest_seq = 0;
  bool found_any = false;

  for (uint8_t i = 0; i < desc->slot_count; i++) {
    boot_rstore_slot_header_t hdr;
    uint8_t dummy_rec[RSTORE_MAX_RECORD_BYTES];
    boot_secure_zeroize(&hdr, sizeof(hdr));
    boot_secure_zeroize(dummy_rec, sizeof(dummy_rec));

    if (rstore_read_slot(platform, desc, i, &hdr, dummy_rec)) {
      if (!found_any || is_newer_sequence(hdr.sequence_id, highest_seq)) {
        highest_seq = hdr.sequence_id;
        found_any = true;
      }
    }
    boot_secure_zeroize(dummy_rec, sizeof(dummy_rec));
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
  }

  /* Write to all slots with incrementing sequences.
   * Brownout safety: If power fails after writing k < slot_count slots,
   * the next read will find k new-state copies vs (slot_count - k)
   * old-state copies. For k >= 2, new state wins by majority.
   * For k == 1, old state wins — safe, we retry on next boot. */
  uint32_t write_seq = highest_seq;

  for (uint8_t i = 0; i < desc->slot_count; i++) {
    write_seq++;

    /* Read existing erase count for wear tracking */
    uint32_t prev_erase_count = 0;
    {
      boot_rstore_slot_header_t existing_hdr;
      uint8_t existing_rec[RSTORE_MAX_RECORD_BYTES];
      boot_secure_zeroize(&existing_hdr, sizeof(existing_hdr));
      boot_secure_zeroize(existing_rec, sizeof(existing_rec));

      if (rstore_read_slot(platform, desc, i, &existing_hdr, existing_rec)) {
        prev_erase_count = existing_hdr.erase_count;
      }
      boot_secure_zeroize(existing_rec, sizeof(existing_rec));
    }

    boot_status_t erase_stat =
        rstore_smart_erase(platform, desc->slot_addrs[i], desc->slot_sizes[i]);
    if (erase_stat != BOOT_OK)
      return erase_stat;

    boot_status_t write_stat = rstore_write_slot(
        platform, desc, i, write_seq, prev_erase_count + 1, record);
    if (write_stat != BOOT_OK)
      return write_stat;

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
  }

  return BOOT_OK;
}
