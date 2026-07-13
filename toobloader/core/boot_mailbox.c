/**
 * @file boot_mailbox.c
 * @brief Core-side mailbox reader + WAL fold-in (C17).
 *
 * Mirrors the OS writer's slot scan: read both A/B slots, take the valid one
 * with the highest seq. If seq is newer than the TMR watermark, translate the
 * request into a WAL intent and advance the watermark.
 *
 * Crash model: APPLY (append) happens before the watermark bump, giving
 * at-least-once semantics. The mailbox intents (UPDATE_PENDING, CONFIRM_COMMIT,
 * RECOVERY_RESOLVED) are idempotent, so a power loss between the two only risks
 * re-applying on the next boot, never losing the request. A WAL sector rotation
 * inside boot_journal_update_tmr does not strand the just-appended entry: the
 * journal's backward cross-sector scan recovers it (see boot_journal.c).
 */

#include "boot_mailbox.h"
#include "boot_journal.h"
#include "boot_crc32.h"
#include "boot_fih.h"            /* BOOT_SECURE_REQUIRE, TOOB glitch delay */
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h" /* CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SLOT_SIZE */
#include <stddef.h>
#include <stdbool.h>

/* Geometry: the two slots must live in distinct erase sectors (see wire header). */
_Static_assert(CHIP_MAILBOX_SIZE == TOOB_MAILBOX_SLOTS * CHIP_MAILBOX_SLOT_SIZE,
               "mailbox region must be exactly TOOB_MAILBOX_SLOTS slot sectors");
_Static_assert(sizeof(toob_mailbox_t) <= CHIP_MAILBOX_SLOT_SIZE,
               "mailbox record must fit in one slot sector");

static uint32_t mbx_slot_addr(uint32_t i) {
  return CHIP_MAILBOX_ABS_ADDR + i * CHIP_MAILBOX_SLOT_SIZE;
}

/* Read one slot; return true and fill *out only if magic + CRC validate. */
static bool mbx_read_valid(const boot_platform_t *platform, uint32_t i,
                           toob_mailbox_t *out) {
  boot_secure_zeroize(out, sizeof(*out));

  if (platform->flash->read(mbx_slot_addr(i), (uint8_t *)out, sizeof(*out)) != BOOT_OK) {
    return false;
  }
  if (out->magic != TOOB_MAILBOX_MAGIC) {
    return false;
  }
  uint32_t expect = compute_boot_crc32((const uint8_t *)out, TOOB_MAILBOX_CRC_LEN);
  return expect == out->crc32;
}

/* Take the valid slot with the highest seq. Returns true and fills *best if any. */
static bool mbx_read_best(const boot_platform_t *platform, toob_mailbox_t *best) {
  bool have = false;
  toob_mailbox_t s;

  for (uint32_t i = 0; i < TOOB_MAILBOX_SLOTS; i++) {
    if (mbx_read_valid(platform, i, &s)) {
      if (!have || s.seq > best->seq) {
        *best = s;
        have = true;
      }
    }
  }
  boot_secure_zeroize(&s, sizeof(s));
  return have;
}

/* Translate one request into a WAL intent. The Core seals CRC + chain tag
 * inside boot_journal_append (it holds the device key; the OS cannot). */
static boot_status_t mbx_apply(const boot_platform_t *platform,
                               const toob_mailbox_t *rec,
                               const wal_tmr_payload_t *tmr) {
  wal_entry_payload_t entry;
  boot_secure_zeroize(&entry, sizeof(entry));
  entry.magic = WAL_ENTRY_MAGIC;

  switch ((toob_req_t)rec->request) {
    case TOOB_REQ_UPDATE_PENDING:
      entry.intent = WAL_INTENT_UPDATE_PENDING;
      entry.offset = rec->tbm1_addr;
      return boot_journal_append(platform, &entry);

    case TOOB_REQ_CONFIRM: {
      /* Stale-confirm defense: commit only when the confirmed nonce matches the
       * currently booted (tentative) update's nonce. A replayed old CONFIRM with
       * a different nonce is consumed but never commits. */
      uint64_t active = ((uint64_t)tmr->active_nonce_hi << 32) | tmr->active_nonce_lo;
      bool match = (rec->nonce == active);
      BOOT_SECURE_REQUIRE(match == (rec->nonce == active),
                          { return BOOT_ERR_INVALID_STATE; });
      if (!match) {
        return BOOT_OK; /* consume, do not commit */
      }
      entry.intent = WAL_INTENT_CONFIRM_COMMIT;
      return boot_journal_append(platform, &entry);
    }

    case TOOB_REQ_RECOVERY_RESOLVED:
      entry.intent = WAL_INTENT_RECOVERY_RESOLVED;
      return boot_journal_append(platform, &entry);

    case TOOB_REQ_NONE:
    default:
      return BOOT_OK; /* unknown/none: consume and ignore */
  }
}

boot_status_t boot_mailbox_consume(const boot_platform_t *platform) {
  if (!platform || !platform->flash || !platform->flash->read) {
    return BOOT_ERR_INVALID_ARG;
  }

  toob_mailbox_t rec;
  wal_tmr_payload_t tmr;
  boot_status_t status = BOOT_OK;

  boot_secure_zeroize(&rec, sizeof(rec));
  boot_secure_zeroize(&tmr, sizeof(tmr));

  /* Empty mailbox: nothing to do (no flash writes, safe every boot). */
  if (!mbx_read_best(platform, &rec)) {
    goto cleanup;
  }

  status = boot_journal_get_tmr(platform, &tmr);
  if (status != BOOT_OK) {
    goto cleanup;
  }

  /* Idempotency gate: apply only strictly-newer records (double-checked). */
  bool is_new = (rec.seq > tmr.last_mbx_request_id);
  BOOT_SECURE_REQUIRE(is_new == (rec.seq > tmr.last_mbx_request_id),
                      { status = BOOT_ERR_INVALID_STATE; goto cleanup; });
  if (!is_new) {
    goto cleanup; /* already consumed */
  }

  /* APPLY first, then advance the watermark (at-least-once; idempotent intents). */
  status = mbx_apply(platform, &rec, &tmr);
  if (status != BOOT_OK) {
    goto cleanup;
  }

  tmr.last_mbx_request_id = rec.seq;
  status = boot_journal_update_tmr(platform, &tmr);

cleanup:
  boot_secure_zeroize(&rec, sizeof(rec));
  boot_secure_zeroize(&tmr, sizeof(tmr));
  return status;
}