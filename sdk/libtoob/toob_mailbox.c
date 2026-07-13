/**
 * @file toob_mailbox.c
 * @brief OS-side Mailbox writer (two-sector A/B, torn-write safe).
 *
 * Replaces the previous erase-both-then-write-slot-0 design, which defeated
 * double-buffering: a torn write wiped the only surviving record and reset the
 * sequence, causing the Core to silently ignore updates (seq <= last_consumed).
 *
 * This implementation writes only the STALE slot and erases only that slot's
 * sector, so:
 *   - at every instant at least one slot holds a valid, complete record, and
 *   - `seq` is strictly monotonic across brownouts (it is derived from the
 *     surviving good slot, which a torn write never touches).
 *
 * The Core reader mirrors the slot scan below: read all slots, take the valid
 * one with the highest `seq`.
 */

#include "toob_mailbox.h"
#include "libtoob.h"
#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif

#include "toob_internal.h"
#include <stddef.h>

#ifndef CHIP_FLASH_WRITE_ALIGNMENT
#define CHIP_FLASH_WRITE_ALIGNMENT CHIP_FLASH_WRITE_ALIGN
#endif

/* Geometry sanity: the writer erases exactly one slot sector at a time, so the
 * mailbox region must be TOOB_MAILBOX_SLOTS distinct erase sectors. */
_Static_assert(CHIP_MAILBOX_SIZE == TOOB_MAILBOX_SLOTS * CHIP_MAILBOX_SLOT_SIZE,
               "mailbox region must be exactly TOOB_MAILBOX_SLOTS slot sectors");
_Static_assert(sizeof(toob_mailbox_t) <= CHIP_MAILBOX_SLOT_SIZE,
               "mailbox record must fit in one slot sector");
_Static_assert(sizeof(toob_mailbox_t) % CHIP_FLASH_WRITE_ALIGNMENT == 0,
               "mailbox record must be a multiple of the flash write alignment");

static inline uint32_t slot_addr(uint32_t i) {
  return CHIP_MAILBOX_ABS_ADDR + i * CHIP_MAILBOX_SLOT_SIZE;
}

/**
 * @brief Read one slot and validate magic + CRC.
 * @return true and fills *out if the slot holds a complete valid record.
 */
static bool slot_read_valid(uint32_t i, toob_mailbox_t *out) {
  toob_secure_zeroize(out, sizeof(*out));

  if (toob_os_flash_read(slot_addr(i), (uint8_t *)out, sizeof(*out)) != TOOB_OK) {
    return false;
  }
  if (out->magic != TOOB_MAILBOX_MAGIC) {
    return false;
  }
  uint32_t expect = toob_lib_crc32((const uint8_t *)out, TOOB_MAILBOX_CRC_LEN);
  return expect == out->crc32;
}

/**
 * @brief Write a request into the stale slot with seq = best_seq + 1.
 *
 * Sequence: scan slots -> pick target (oldest / invalid) and best_seq ->
 * build record -> erase target sector -> write -> glitch-safe read-back verify.
 */
static toob_status_t mailbox_put(toob_req_t req, uint32_t tbm1_addr, uint64_t nonce) {
  toob_mailbox_t rec;
  uint32_t best_seq = 0;
  uint32_t target = 0;
  uint32_t target_seq = 0xFFFFFFFFu; /* pick the slot with the LOWEST seq (invalid = 0) */

  for (uint32_t i = 0; i < TOOB_MAILBOX_SLOTS; i++) {
    bool ok = slot_read_valid(i, &rec);
    uint32_t seq = ok ? rec.seq : 0u; /* an invalid slot is treated as the oldest */

    if (ok && rec.seq > best_seq) {
      best_seq = rec.seq;
    }
    if (seq < target_seq) {
      target_seq = seq;
      target = i;
    }
    toob_secure_zeroize(&rec, sizeof(rec)); /* slot may carry a CONFIRM nonce */
  }
  /* target is now the slot NOT holding the freshest record; best_seq is preserved
   * there and is never erased below. NOTE: seq is uint32 and single-writer; a wrap
   * needs 2^32 successful writes (unreachable in device lifetime). */

  /* Build the new record (zeroize first: sets _reserved and any pad to 0). */
  toob_mailbox_t m;
  toob_secure_zeroize(&m, sizeof(m));
  m.magic     = TOOB_MAILBOX_MAGIC;
  m.version   = TOOB_MAILBOX_VERSION;
  m.request   = (uint16_t)req;
  m.seq       = best_seq + 1u;
  m.tbm1_addr = tbm1_addr;
  m.nonce     = nonce;
  m.crc32     = toob_lib_crc32((const uint8_t *)&m, TOOB_MAILBOX_CRC_LEN);

  /* Erase ONLY the target slot's sector. The freshest good slot stays intact. */
  toob_status_t status = toob_os_flash_erase(slot_addr(target), CHIP_MAILBOX_SLOT_SIZE);
  if (status != TOOB_OK) {
    toob_secure_zeroize(&m, sizeof(m));
    return status;
  }

  status = toob_os_flash_write(slot_addr(target), (const uint8_t *)&m, sizeof(m));
  if (status != TOOB_OK) {
    toob_secure_zeroize(&m, sizeof(m));
    return status;
  }

  /* Phase-bound read-back verify (glitch-safe, ghost-match-proof). */
  toob_mailbox_t verify;
  toob_secure_zeroize(&verify, sizeof(verify));
  status = toob_os_flash_read(slot_addr(target), (uint8_t *)&verify, sizeof(verify));

  if (status != TOOB_OK ||
      toob_ct_memcmp_glitch_safe((const uint8_t *)&m,
                                 (const uint8_t *)&verify,
                                 sizeof(m)) != TOOB_OK) {
    /* Torn/failed write. The other slot still holds the previous good record,
     * so the Core keeps working; the caller retries and seq will not regress. */
    status = TOOB_ERR_FLASH_HW;
  } else {
    status = TOOB_OK;
  }

  toob_secure_zeroize(&m, sizeof(m));
  toob_secure_zeroize(&verify, sizeof(verify));
  return status;
}

/* ===== Public API (called from toob_update.c / toob_confirm.c) ===== */

toob_status_t toob_mailbox_set_update(uint32_t manifest_flash_addr) {
  return mailbox_put(TOOB_REQ_UPDATE_PENDING, manifest_flash_addr, 0);
}

toob_status_t toob_mailbox_set_confirm(uint64_t nonce) {
  return mailbox_put(TOOB_REQ_CONFIRM, 0, nonce);
}

toob_status_t toob_mailbox_set_recovery_resolved(void) {
  return mailbox_put(TOOB_REQ_RECOVERY_RESOLVED, 0, 0);
}