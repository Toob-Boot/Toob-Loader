/**
 * @file toob_mailbox.c
 * @brief OS-side Mailbox writer (two-sector A/B, torn-write safe, cumulative v2).
 *
 * Writes only the STALE slot and erases only that slot's sector, so:
 *   - at every instant at least one slot holds a valid, complete record,
 *   - `seq` is strictly monotonic across brownouts and never reset on I/O errors,
 *   - orthogonal request bitflags emitted within the same boot session are
 *     merged cumulatively rather than overwriting unconsumed intents (CRIT-24).
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

/* Geometry sanity: the writer erases exactly one slot sector at a time, so the
 * mailbox region must be TOOB_MAILBOX_SLOTS distinct erase sectors. */
_Static_assert(CHIP_MAILBOX_SIZE == TOOB_MAILBOX_SLOTS * CHIP_MAILBOX_SLOT_SIZE,
               "mailbox region must be exactly TOOB_MAILBOX_SLOTS slot sectors");
_Static_assert(CHIP_MAILBOX_SLOT_SIZE > 0U &&
                   (CHIP_MAILBOX_SLOT_SIZE & (CHIP_MAILBOX_SLOT_SIZE - 1U)) == 0U,
               "CHIP_MAILBOX_SLOT_SIZE must be a non-zero power-of-two erase sector");
_Static_assert(sizeof(toob_mailbox_t) <= CHIP_MAILBOX_SLOT_SIZE,
               "mailbox record must fit in one slot sector");
_Static_assert(sizeof(toob_mailbox_t) % CHIP_FLASH_WRITE_ALIGNMENT == 0,
               "mailbox record must be a multiple of the flash write alignment");

typedef enum {
  MBX_SLOT_VALID   = 0,
  MBX_SLOT_INVALID = 1,
  MBX_SLOT_IO_ERR  = 2
} mbx_slot_state_t;

/* Per-boot-session cumulative intent accumulator (protected by toob_os_lock). */
static bool     s_session_init = false;
static bool     s_session_has_handoff = false;
static uint64_t s_session_boot_nonce = 0ULL;
static uint16_t s_session_flags = 0U;
static uint32_t s_session_tbm1_addr = 0U;
static uint64_t s_session_confirm_nonce = 0ULL;

void toob_mailbox_session_reset_for_test(void);
void toob_mailbox_session_reset_for_test(void) {
  toob_os_lock();
  s_session_init = false;
  s_session_has_handoff = false;
  s_session_boot_nonce = 0ULL;
  s_session_flags = 0U;
  s_session_tbm1_addr = 0U;
  s_session_confirm_nonce = 0ULL;
  toob_os_unlock();
}

static inline uint32_t slot_addr(uint32_t i) {
  return CHIP_MAILBOX_ABS_ADDR + i * CHIP_MAILBOX_SLOT_SIZE;
}

static inline bool mbx_seq_is_newer(uint32_t cand, uint32_t cur) {
  if (cand == 0U) {
    return false;
  }
  if (cur == 0U) {
    return true;
  }
  uint32_t diff = (cand >= cur) ? (cand - cur) : ((UINT32_MAX - cur) + 1U + cand);
  return (diff != 0U) && (diff < 0x80000000U);
}

/**
 * @brief Read one slot and distinguish valid record vs invalid data vs flash I/O error.
 */
static mbx_slot_state_t slot_read_valid(uint32_t i, toob_mailbox_t *out,
                                        toob_status_t *out_io_err) {
  toob_secure_zeroize(out, sizeof(*out));

  toob_status_t rd = toob_os_flash_read(slot_addr(i), (uint8_t *)out, sizeof(*out));
  if (rd != TOOB_OK) {
    if (out_io_err != NULL) {
      *out_io_err = rd;
    }
    toob_secure_zeroize(out, sizeof(*out));
    return MBX_SLOT_IO_ERR;
  }

  if (out->magic != TOOB_MAILBOX_MAGIC || out->seq == 0U) {
    toob_secure_zeroize(out, sizeof(*out));
    return MBX_SLOT_INVALID;
  }

  uint32_t expect = toob_lib_crc32((const uint8_t *)out, TOOB_MAILBOX_CRC_LEN);
  if (expect != out->crc32) {
    toob_secure_zeroize(out, sizeof(*out));
    return MBX_SLOT_INVALID;
  }

  return MBX_SLOT_VALID;
}

/**
 * @brief Merge request into per-boot session state and write to the stale slot.
 */
static toob_status_t mailbox_put(toob_req_t req, uint32_t tbm1_addr, uint64_t nonce) {
  if (req == TOOB_REQ_NONE || (req & (toob_req_t)(~TOOB_REQ_ALL_MASK)) != 0U) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_handoff_t handoff __attribute__((aligned(8)));
  bool handoff_ok = (toob_get_handoff(&handoff) == TOOB_OK);
  uint64_t cur_boot_nonce = handoff_ok ? handoff.boot_nonce : 0ULL;
  toob_secure_zeroize(&handoff, sizeof(handoff));

  toob_os_lock();

  /* Reset accumulator automatically on first use or new boot session nonce. */
  if (!s_session_init ||
      (handoff_ok != s_session_has_handoff) ||
      (handoff_ok && cur_boot_nonce != s_session_boot_nonce)) {
    s_session_init = true;
    s_session_has_handoff = handoff_ok;
    s_session_boot_nonce = cur_boot_nonce;
    s_session_flags = 0U;
    s_session_tbm1_addr = 0U;
    s_session_confirm_nonce = 0ULL;
  }

  toob_mailbox_t rec;
  uint32_t best_seq = 0U;
  bool have_best = false;
  uint32_t target = 0U;
  uint32_t target_seq = 0U;
  bool target_is_valid = false;
  bool target_set = false;

  for (uint32_t i = 0U; i < TOOB_MAILBOX_SLOTS; i++) {
    toob_status_t io_err = TOOB_ERR_FLASH;
    mbx_slot_state_t st = slot_read_valid(i, &rec, &io_err);
    if (st == MBX_SLOT_IO_ERR) {
      /* HIGH-23: Abort immediately on flash read failure without erasing or resetting seq! */
      toob_secure_zeroize(&rec, sizeof(rec));
      toob_os_unlock();
      return io_err;
    }

    if (st == MBX_SLOT_VALID) {
      if (!have_best || mbx_seq_is_newer(rec.seq, best_seq)) {
        best_seq = rec.seq;
        have_best = true;
      }
      if (!target_set || (target_is_valid && mbx_seq_is_newer(target_seq, rec.seq))) {
        target_set = true;
        target_is_valid = true;
        target_seq = rec.seq;
        target = i;
      }
    } else {
      if (!target_set || target_is_valid) {
        target_set = true;
        target_is_valid = false;
        target_seq = 0U;
        target = i;
      }
    }
    toob_secure_zeroize(&rec, sizeof(rec));
  }

  uint32_t next_seq = (best_seq == UINT32_MAX) ? 1U : (best_seq + 1U);

  /* Compute cumulative session payload before committing to flash. */
  uint16_t next_flags = (uint16_t)(s_session_flags | (uint16_t)req);
  uint32_t next_tbm1_addr = ((req & TOOB_REQ_UPDATE_PENDING) != 0U)
                                ? tbm1_addr
                                : s_session_tbm1_addr;
  uint64_t next_confirm_nonce = ((req & TOOB_REQ_CONFIRM) != 0U)
                                    ? nonce
                                    : s_session_confirm_nonce;

  toob_mailbox_t m;
  toob_secure_zeroize(&m, sizeof(m));
  m.magic     = TOOB_MAILBOX_MAGIC;
  m.version   = TOOB_MAILBOX_VERSION;
  m.request   = next_flags;
  m.seq       = next_seq;
  m.tbm1_addr = next_tbm1_addr;
  m.nonce     = next_confirm_nonce;
  m.crc32     = toob_lib_crc32((const uint8_t *)&m, TOOB_MAILBOX_CRC_LEN);

  /* Erase ONLY the target slot's sector. The freshest good slot stays intact. */
  uint32_t target_slot_addr = slot_addr(target);
  if (toob_flash_range_hits_immutable_boot(target_slot_addr, CHIP_MAILBOX_SLOT_SIZE)) {
    toob_secure_zeroize(&m, sizeof(m));
    toob_os_unlock();
    return TOOB_ERR_FLASH;
  }

  toob_status_t status = toob_os_flash_erase(target_slot_addr, CHIP_MAILBOX_SLOT_SIZE);
  if (status != TOOB_OK) {
    toob_secure_zeroize(&m, sizeof(m));
    toob_os_unlock();
    return status;
  }

  status = toob_os_flash_write(target_slot_addr, (const uint8_t *)&m, sizeof(m));
  if (status != TOOB_OK) {
    toob_secure_zeroize(&m, sizeof(m));
    toob_os_unlock();
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
    status = TOOB_ERR_FLASH_HW;
  } else {
    s_session_flags = next_flags;
    s_session_tbm1_addr = next_tbm1_addr;
    s_session_confirm_nonce = next_confirm_nonce;
    status = TOOB_OK;
  }

  toob_secure_zeroize(&m, sizeof(m));
  toob_secure_zeroize(&verify, sizeof(verify));
  toob_os_unlock();
  return status;
}

/* ===== Public API (called from toob_update.c / toob_confirm.c) ===== */

toob_status_t toob_mailbox_set_update(uint32_t manifest_flash_addr) {
  return mailbox_put(TOOB_REQ_UPDATE_PENDING, manifest_flash_addr, 0ULL);
}

toob_status_t toob_mailbox_set_confirm(uint64_t nonce) {
  return mailbox_put(TOOB_REQ_CONFIRM, 0U, nonce);
}

toob_status_t toob_mailbox_set_recovery_resolved(void) {
  return mailbox_put(TOOB_REQ_RECOVERY_RESOLVED, 0U, 0ULL);
}
