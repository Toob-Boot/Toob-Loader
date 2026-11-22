/**
 * ==============================================================================
 * Toob-Boot libtoob: OTA Daemon Implementation (toob_ota.c)
 * ==============================================================================
 *
 * ARCHITECTURAL PROPERTIES:
 * 1. Network-Agnostic Stream Writer: Buffers arbitrary-length chunks to
 *    TOOB_OTA_BUF_SIZE (multiple of CHIP_FLASH_WRITE_ALIGNMENT) before flushing.
 * 2. Fail-Closed Dual-Slot Resolution (CRIT-23): Under TOOB_TRANSPORT_POINTER,
 *    strictly resolves the inactive slot from validated handoff and locks the
 *    staging base address into ctx->write_cursor (zero TOCTOU).
 * 3. Incremental Erase-on-Demand (MED-19): Erases flash sectors lazily right
 *    before writing into each new sector, preventing BLE/HTTP timeouts in
 *    toob_ota_begin() and avoiding wear on untouched sectors.
 * 4. Torn-Write-Safe Resume Checkpoints (HIGH-21): Persists ONLY physically
 *    flushed byte offsets bound to target_addr, with blank-check & sector
 *    rollback on dirty brownout tails.
 * 5. Bounds Check Before Hash Update (MED-21): Rejects oversized chunks prior
 *    to mutating the streaming SHA-256 context.
 */

#include "libtoob.h"
#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif
#include "toob_internal.h"
#include <string.h>

/* SWEV-T3 Notifier Registration (protected by toob_os_lock) */
static toob_swap_notify_fn g_swap_notifier = NULL;

void toob_set_swap_notifier(toob_swap_notify_fn cb) {
#if TOOB_SWAP_EVENT_STATE
  toob_os_lock();
  g_swap_notifier = cb;
  toob_os_unlock();
#else
  (void)cb;
#endif
}

/* ==============================================================================
 * Internal State Machine Constants
 * ==============================================================================
 */

typedef enum {
  TOOB_OTA_STATE_IDLE = 0x00,
  TOOB_OTA_STATE_RECEIVING = 0x5A,
  TOOB_OTA_STATE_DONE = 0xA5,
  TOOB_OTA_STATE_ERROR = 0xFF
} toob_ota_state_t;

_Static_assert(
    TOOB_OTA_BUF_SIZE % CHIP_FLASH_WRITE_ALIGNMENT == 0,
    "OTA alignment buffer must be a multiple of CHIP_FLASH_WRITE_ALIGNMENT");
_Static_assert(TOOB_OTA_BUF_SIZE > 0 && TOOB_OTA_BUF_SIZE <= 4096,
               "OTA alignment buffer must be within sane bounds [1..4096]");

/* Named .noinit resume checkpoint (CRIT-26 / HIGH-21) */
TOOB_NOINIT_VAR(toob_ota_resume_state) toob_ota_resume_state_t g_toob_ota_resume_state;

/* ==============================================================================
 * INTERNAL HELPERS
 * ==============================================================================
 */

static toob_status_t _ota_resolve_slot_size(uint32_t target_addr, uint32_t *out_size) {
  if (!out_size) {
    return TOOB_ERR_INVALID_ARG;
  }
  uint32_t slot_size = 0U;
  if (target_addr == CHIP_STAGING_SLOT_ABS_ADDR) {
    slot_size = CHIP_STAGING_SLOT_SIZE;
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
  } else if (target_addr == CHIP_APP_SLOT_ABS_ADDR) {
    slot_size = CHIP_APP_SLOT_SIZE;
#endif
  } else {
    *out_size = 0U;
    return TOOB_ERR_FLASH;
  }
  if (slot_size == 0U || toob_flash_range_hits_immutable_boot(target_addr, slot_size)) {
    *out_size = 0U;
    return TOOB_ERR_FLASH;
  }
  *out_size = slot_size;
  return TOOB_OK;
}

static toob_status_t _ota_get_staging_target(uint32_t *out_addr, uint32_t *out_size) {
  if (!out_addr || !out_size) {
    return TOOB_ERR_INVALID_ARG;
  }
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
  toob_handoff_t handoff __attribute__((aligned(8)));
  toob_status_t st = toob_get_handoff(&handoff);
  uint8_t active_slot = handoff.active_slot;
  toob_secure_zeroize(&handoff, sizeof(handoff));

  /* CRIT-23: Fail closed on corrupted handoff or invalid active_slot —
   * NEVER fall back to CHIP_STAGING_SLOT_ABS_ADDR (Slot 1)! */
  if (st != TOOB_OK || active_slot > 1U) {
    *out_addr = 0U;
    *out_size = 0U;
    return (st != TOOB_OK) ? st : TOOB_ERR_VERIFY;
  }

  if (active_slot == 1U) {
    *out_addr = CHIP_APP_SLOT_ABS_ADDR;
    *out_size = CHIP_APP_SLOT_SIZE;
  } else {
    *out_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    *out_size = CHIP_STAGING_SLOT_SIZE;
  }
#else
  *out_addr = CHIP_STAGING_SLOT_ABS_ADDR;
  *out_size = CHIP_STAGING_SLOT_SIZE;
#endif
  if (*out_size == 0U || toob_flash_range_hits_immutable_boot(*out_addr, *out_size)) {
    *out_addr = 0U;
    *out_size = 0U;
    return TOOB_ERR_FLASH;
  }
  return TOOB_OK;
}

/* Resets session RAM context ONLY (does NOT clear .noinit resume checkpoint). */
static void _ctx_reset(toob_ota_ctx_t *ctx) {
  toob_secure_zeroize(ctx, sizeof(*ctx));
}

static void _volatile_snapshot_resume(toob_ota_resume_state_t *dst) {
  const volatile uint8_t *src =
      (const volatile uint8_t *)&g_toob_ota_resume_state;
  uint8_t *out = (uint8_t *)dst;
  for (size_t i = 0U; i < sizeof(toob_ota_resume_state_t); i++) {
    out[i] = src[i];
  }
}

/* MED-19: Lazily erase any sectors crossed by [ctx->write_cursor, ctx->write_cursor + write_len). */
static toob_status_t _ensure_sectors_erased(toob_ota_ctx_t *ctx,
                                            uint32_t target_addr,
                                            uint32_t target_size,
                                            uint32_t write_len) {
  if (ctx->write_cursor < target_addr || write_len > target_size ||
      (ctx->write_cursor - target_addr) > (target_size - write_len)) {
    return TOOB_ERR_FLASH;
  }
  uint32_t start_off = ctx->write_cursor - target_addr;
  uint32_t end_off = start_off + write_len;
  uint32_t needed_sectors =
      (end_off == 0U)
          ? 0U
          : (((end_off - 1U) / CHIP_FLASH_MAX_SECTOR_SIZE) + 1U);

  if (needed_sectors > 0xFFFFU) {
    return TOOB_ERR_INVALID_ARG;
  }

  while ((uint32_t)ctx->erased_sectors < needed_sectors) {
    uint32_t sec_off =
        (uint32_t)ctx->erased_sectors * CHIP_FLASH_MAX_SECTOR_SIZE;
    if (sec_off >= target_size) {
      return TOOB_ERR_FLASH;
    }
    uint32_t rem_slot = target_size - sec_off;
    uint32_t erase_span =
        (rem_slot < CHIP_FLASH_MAX_SECTOR_SIZE) ? rem_slot
                                                : CHIP_FLASH_MAX_SECTOR_SIZE;
    uint32_t sec_addr = target_addr + sec_off;
    if (toob_flash_range_hits_immutable_boot(sec_addr, erase_span)) {
      return TOOB_ERR_FLASH;
    }
    toob_status_t er = toob_os_flash_erase(sec_addr, erase_span);
    if (er != TOOB_OK) {
      return er;
    }
    ctx->erased_sectors++;
  }
  return TOOB_OK;
}

static toob_status_t _flush_buffer(toob_ota_ctx_t *ctx, uint32_t write_len) {
  if (write_len == 0U || write_len > TOOB_OTA_BUF_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  if (ctx->bytes_queued < ctx->buf_len) {
    return TOOB_ERR_STATE;
  }
  uint32_t flushed_so_far = ctx->bytes_queued - ctx->buf_len;
  if (ctx->write_cursor < flushed_so_far) {
    return TOOB_ERR_STATE;
  }
  uint32_t target_addr = ctx->write_cursor - flushed_so_far;
  uint32_t target_size = 0U;
  toob_status_t bnd_st = _ota_resolve_slot_size(target_addr, &target_size);
  if (bnd_st != TOOB_OK) {
    return bnd_st;
  }
  if (toob_flash_range_hits_immutable_boot(ctx->write_cursor, write_len) ||
      ctx->write_cursor < target_addr ||
      write_len > target_size ||
      (ctx->write_cursor - target_addr) > (target_size - write_len)) {
    return TOOB_ERR_FLASH;
  }

  toob_status_t erase_st =
      _ensure_sectors_erased(ctx, target_addr, target_size, write_len);
  if (erase_st != TOOB_OK) {
    return erase_st;
  }

  toob_status_t res =
      toob_os_flash_write(ctx->write_cursor, ctx->align_buf, write_len);

  /* Glitch-Resistant Double-Check on flash result */
  volatile uint32_t shield_1 = 0U, shield_2 = 0U;
  if (res == TOOB_OK) {
    shield_1 = TOOB_OK;
  }
  TOOB_GLITCH_DELAY();
  if (shield_1 == TOOB_OK && res == TOOB_OK) {
    shield_2 = TOOB_OK;
  }

  if (shield_1 != TOOB_OK || shield_2 != TOOB_OK || shield_1 != shield_2) {
    return (res != TOOB_OK) ? res : TOOB_ERR_FLASH;
  }

  /* Phase-Bound Chunked Read-Back Verify (64-byte stack chunk, ghost-match-proof). */
  {
    uint8_t rb_buf[64] __attribute__((aligned(8)));
    uint32_t pos = 0U;

    while (pos < write_len) {
      uint32_t remaining = write_len - pos;
      uint32_t chunk = (remaining > 64U) ? 64U : remaining;

      toob_secure_zeroize(rb_buf, sizeof(rb_buf));

      toob_status_t rd =
          toob_os_flash_read(ctx->write_cursor + pos, rb_buf, chunk);
      if (rd != TOOB_OK) {
        toob_secure_zeroize(rb_buf, sizeof(rb_buf));
        return TOOB_ERR_FLASH_HW;
      }

      if (toob_ct_memcmp_glitch_safe(&ctx->align_buf[pos], rb_buf, chunk) != TOOB_OK) {
        toob_secure_zeroize(rb_buf, sizeof(rb_buf));
        return TOOB_ERR_FLASH_HW;
      }

      pos += chunk;
    }

    toob_secure_zeroize(rb_buf, sizeof(rb_buf));
  }

  ctx->write_cursor += write_len;
  return TOOB_OK;
}

/* ==============================================================================
 * CHECKPOINT MANAGEMENT
 * ==============================================================================
 */

void toob_ota_checkpoint_clear(void) {
  toob_os_lock();
  toob_secure_zeroize(&g_toob_ota_resume_state, sizeof(g_toob_ota_resume_state));
  toob_os_unlock();
}

void toob_ota_checkpoint_save_bound_ex(uint32_t bytes_staged,
                                        uint32_t target_addr,
                                        const uint8_t sha256[32],
                                        const uint8_t assignment_id[16]) {
  toob_ota_resume_state_t local __attribute__((aligned(8)));
  toob_secure_zeroize(&local, sizeof(local));
  local.magic = TOOB_OTA_RESUME_MAGIC;
  local.bytes_staged = bytes_staged;
  if (sha256 != NULL) {
    memcpy(local.artifact_sha256, sha256, 32U);
  }
  local.target_addr = target_addr;

  toob_os_lock();
  if (assignment_id != NULL) {
    memcpy(local.assignment_id, assignment_id, 16U);
  } else {
    /* Preserve active assignment_id when internal chunk flushes update bytes_staged (TCI1-05). */
    toob_ota_resume_state_t prev __attribute__((aligned(8)));
    _volatile_snapshot_resume(&prev);
    size_t crc_len = offsetof(toob_ota_resume_state_t, crc32_trailer);
    if (prev.magic == TOOB_OTA_RESUME_MAGIC &&
        prev.target_addr == target_addr &&
        toob_lib_crc32((const uint8_t *)&prev, crc_len) == prev.crc32_trailer &&
        toob_ct_memcmp_glitch_safe(prev.artifact_sha256, local.artifact_sha256, 32U) == TOOB_OK) {
      memcpy(local.assignment_id, prev.assignment_id, 16U);
    }
    toob_secure_zeroize(&prev, sizeof(prev));
  }

  local.crc32_trailer = toob_lib_crc32(
      (const uint8_t *)&local, offsetof(toob_ota_resume_state_t, crc32_trailer));
  memcpy(&g_toob_ota_resume_state, &local, sizeof(local));
  toob_os_unlock();

  toob_secure_zeroize(&local, sizeof(local));
}

void toob_ota_checkpoint_save_bound(uint32_t bytes_staged,
                                    uint32_t target_addr,
                                    const uint8_t sha256[32]) {
  toob_ota_checkpoint_save_bound_ex(bytes_staged, target_addr, sha256, NULL);
}

void toob_ota_checkpoint_save(uint32_t bytes_staged, const uint8_t sha256[32]) {
  uint32_t target_addr = 0U, target_size = 0U;
  if (_ota_get_staging_target(&target_addr, &target_size) != TOOB_OK) {
    toob_ota_checkpoint_clear();
    return;
  }
  toob_ota_checkpoint_save_bound(bytes_staged, target_addr, sha256);
}

/* ==============================================================================
 * PUBLIC API
 * ==============================================================================
 */

toob_status_t toob_ota_ctx_init(toob_ota_ctx_t *ctx) {
  if (!ctx) {
    return TOOB_ERR_INVALID_ARG;
  }
  _ctx_reset(ctx);
  return TOOB_OK;
}

static toob_status_t _ota_begin_core(toob_ota_ctx_t *ctx, uint32_t total_size) {
  if (!ctx) {
    return TOOB_ERR_INVALID_ARG;
  }
  /* Reject re-entry while a transfer is active before touching checkpoint */
  if (ctx->state == TOOB_OTA_STATE_RECEIVING) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* HIGH-21: Always purge any stale checkpoint at the very start of begin. */
  toob_ota_checkpoint_clear();

  uint32_t target_addr = 0U, target_size = 0U;
  toob_status_t st = _ota_get_staging_target(&target_addr, &target_size);
  if (st != TOOB_OK) {
    return st;
  }

  if (total_size == 0U || total_size > target_size ||
      toob_flash_range_hits_immutable_boot(target_addr, total_size)) {
    return TOOB_ERR_INVALID_ARG;
  }

  _ctx_reset(ctx);
  ctx->erased_sectors = 0U; /* MED-19: Sectors erased lazily on demand */
  ctx->write_cursor = target_addr;
  ctx->total_size = total_size;
  ctx->state = TOOB_OTA_STATE_RECEIVING;

  return TOOB_OK;
}

toob_status_t toob_ota_begin(toob_ota_ctx_t *ctx, uint32_t total_size,
                             const uint8_t expected_sha256[32]) {
  toob_status_t res = _ota_begin_core(ctx, total_size);
  if (res != TOOB_OK) {
    return res;
  }

  if (expected_sha256 != NULL) {
    if (toob_os_sha256_init(&ctx->sha_ctx) != TOOB_OK) {
      _ctx_reset(ctx);
      return TOOB_ERR_NOT_SUPPORTED;
    }
    memcpy(ctx->expected_sha256, expected_sha256, 32U);
    ctx->is_verified = 1U;
  }
  return TOOB_OK;
}

toob_status_t toob_ota_begin_assigned(toob_ota_ctx_t *ctx,
                                       uint32_t total_size,
                                       const uint8_t expected_sha256[32],
                                       const uint8_t assignment_id[16]) {
  toob_status_t res = toob_ota_begin(ctx, total_size, expected_sha256);
  if (res != TOOB_OK) {
    return res;
  }
  if (assignment_id != NULL) {
    /* Seed assignment_id into CRC-protected .noinit state at bytes_staged=0 so subsequent
     * chunk flushes and fast-path resume verify the exact assignment binding (TCI1-05). */
    toob_ota_checkpoint_save_bound_ex(0U, ctx->write_cursor, expected_sha256, assignment_id);
  }
  return TOOB_OK;
}

toob_status_t toob_ota_pause(toob_ota_ctx_t *ctx) {
  if (!ctx) {
    return TOOB_ERR_INVALID_ARG;
  }
  _ctx_reset(ctx);
  return TOOB_OK;
}

toob_status_t toob_ota_abort(toob_ota_ctx_t *ctx) {
  if (!ctx) {
    return TOOB_ERR_INVALID_ARG;
  }
  _ctx_reset(ctx);
  toob_ota_checkpoint_clear();
  return TOOB_OK;
}

toob_status_t toob_ota_resume_assigned(toob_ota_ctx_t *ctx,
                                        uint32_t total_size,
                                        const uint8_t expected_sha256[32],
                                        const uint8_t expected_assignment_id[16],
                                        uint32_t *resume_offset) {
  if (!ctx || !resume_offset) {
    return TOOB_ERR_INVALID_ARG;
  }
  *resume_offset = 0U;

  uint32_t target_addr = 0U, target_size = 0U;
  toob_status_t tgt_st = _ota_get_staging_target(&target_addr, &target_size);
  if (tgt_st != TOOB_OK) {
    return tgt_st;
  }
  if (total_size == 0U || total_size > target_size ||
      toob_flash_range_hits_immutable_boot(target_addr, total_size)) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Fast-path: In-RAM active context (validate size, slot base, SHA-256, and assignment_id). */
  if (ctx->state == TOOB_OTA_STATE_RECEIVING) {
    uint32_t cur_flushed = ctx->bytes_queued - ctx->buf_len;
    if (ctx->total_size != total_size ||
        ctx->write_cursor < cur_flushed ||
        (ctx->write_cursor - cur_flushed) != target_addr) {
      return TOOB_ERR_INVALID_ARG;
    }
    if (expected_sha256 != NULL) {
      if (ctx->is_verified == 0U ||
          toob_ct_memcmp_glitch_safe(ctx->expected_sha256, expected_sha256, 32U) != TOOB_OK) {
        return TOOB_ERR_VERIFY;
      }
    } else if (ctx->is_verified != 0U) {
      return TOOB_ERR_INVALID_ARG;
    }
    if (expected_assignment_id != NULL) {
      toob_ota_resume_state_t cur_ckpt __attribute__((aligned(8)));
      toob_secure_zeroize(&cur_ckpt, sizeof(cur_ckpt));
      toob_os_lock();
      _volatile_snapshot_resume(&cur_ckpt);
      toob_os_unlock();
      size_t ckpt_crc_len = offsetof(toob_ota_resume_state_t, crc32_trailer);
      bool id_ok = (cur_ckpt.magic == TOOB_OTA_RESUME_MAGIC) &&
                   (toob_lib_crc32((const uint8_t *)&cur_ckpt, ckpt_crc_len) ==
                    cur_ckpt.crc32_trailer) &&
                   (toob_ct_memcmp_glitch_safe(cur_ckpt.assignment_id,
                                               expected_assignment_id, 16U) == TOOB_OK);
      toob_secure_zeroize(&cur_ckpt, sizeof(cur_ckpt));
      if (!id_ok) {
        toob_status_t abort_rc = toob_ota_abort(ctx);
        (void)abort_rc;
        return TOOB_ERR_NOT_FOUND;
      }
    }
    *resume_offset = ctx->bytes_queued;
    return TOOB_OK;
  }

  /* Slow-path: Snapshot and validate .noinit resume checkpoint. */
  toob_ota_resume_state_t saved __attribute__((aligned(8)));
  toob_secure_zeroize(&saved, sizeof(saved));
  toob_os_lock();
  _volatile_snapshot_resume(&saved);
  toob_os_unlock();

  size_t payload_len = offsetof(toob_ota_resume_state_t, crc32_trailer);
  uint32_t calc_crc = toob_lib_crc32((const uint8_t *)&saved, payload_len);

  bool valid_ckpt = (saved.magic == TOOB_OTA_RESUME_MAGIC) &&
                    (calc_crc == saved.crc32_trailer) &&
                    (saved.target_addr == target_addr) &&
                    (saved.bytes_staged > 0U) &&
                    (saved.bytes_staged < total_size) &&
                    ((saved.bytes_staged % TOOB_OTA_BUF_SIZE) == 0U);

  if (!valid_ckpt) {
    toob_secure_zeroize(&saved, sizeof(saved));
    toob_ota_checkpoint_clear();
    return TOOB_ERR_NOT_FOUND;
  }

  if (expected_sha256 != NULL) {
    if (toob_ct_memcmp_glitch_safe(saved.artifact_sha256, expected_sha256, 32U) != TOOB_OK) {
      toob_secure_zeroize(&saved, sizeof(saved));
      toob_ota_checkpoint_clear();
      return TOOB_ERR_NOT_FOUND;
    }
  } else {
    uint8_t zero_sha[32];
    memset(zero_sha, 0, sizeof(zero_sha));
    if (toob_ct_memcmp_glitch_safe(saved.artifact_sha256, zero_sha, 32U) != TOOB_OK) {
      toob_secure_zeroize(&saved, sizeof(saved));
      toob_ota_checkpoint_clear();
      return TOOB_ERR_NOT_FOUND;
    }
  }

  if (expected_assignment_id != NULL &&
      toob_ct_memcmp_glitch_safe(saved.assignment_id, expected_assignment_id, 16U) != TOOB_OK) {
    toob_secure_zeroize(&saved, sizeof(saved));
    toob_ota_checkpoint_clear();
    return TOOB_ERR_NOT_FOUND;
  }

  uint32_t staged = saved.bytes_staged;
  toob_secure_zeroize(&saved, sizeof(saved));

  _ctx_reset(ctx);

  /* MED-19: Blank-check remainder of partially written sector; on dirty brownout
   * tail, roll back staged offset to sector start and re-erase cleanly. */
  uint16_t resumed_erased_sectors =
      (uint16_t)(staged / CHIP_FLASH_MAX_SECTOR_SIZE);

  if ((staged % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U) {
    uint32_t sec_base_off =
        (staged / CHIP_FLASH_MAX_SECTOR_SIZE) * CHIP_FLASH_MAX_SECTOR_SIZE;
    uint32_t sec_end_off = sec_base_off + CHIP_FLASH_MAX_SECTOR_SIZE;
    if (sec_end_off > target_size) {
      sec_end_off = target_size;
    }

    bool dirty_tail = false;
    uint32_t chk = staged;
    while (chk < sec_end_off && !dirty_tail) {
      uint32_t rem = sec_end_off - chk;
      uint32_t c_len = (rem > TOOB_OTA_BUF_SIZE) ? TOOB_OTA_BUF_SIZE : rem;
      toob_status_t rd =
          toob_os_flash_read(target_addr + chk, ctx->align_buf, c_len);
      if (rd != TOOB_OK) {
        _ctx_reset(ctx);
        toob_ota_checkpoint_clear();
        return rd;
      }
      for (uint32_t i = 0U; i < c_len; i++) {
        if (ctx->align_buf[i] != 0xFFU) {
          dirty_tail = true;
          break;
        }
      }
      chk += c_len;
    }
    toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);

    if (dirty_tail) {
      uint32_t erase_span = sec_end_off - sec_base_off;
      if (toob_flash_range_hits_immutable_boot(target_addr + sec_base_off,
                                               erase_span)) {
        _ctx_reset(ctx);
        toob_ota_checkpoint_clear();
        return TOOB_ERR_FLASH;
      }
      toob_status_t er =
          toob_os_flash_erase(target_addr + sec_base_off, erase_span);
      if (er != TOOB_OK) {
        _ctx_reset(ctx);
        toob_ota_checkpoint_clear();
        return er;
      }
      staged = sec_base_off;
      resumed_erased_sectors =
          (uint16_t)((sec_base_off / CHIP_FLASH_MAX_SECTOR_SIZE) + 1U);
      if (staged > 0U) {
        toob_ota_checkpoint_save_bound_ex(staged, target_addr, expected_sha256, expected_assignment_id);
      } else if (expected_assignment_id != NULL) {
        toob_ota_checkpoint_save_bound_ex(0U, target_addr, expected_sha256, expected_assignment_id);
      } else {
        toob_ota_checkpoint_clear();
      }
    } else {
      resumed_erased_sectors =
          (uint16_t)((staged / CHIP_FLASH_MAX_SECTOR_SIZE) + 1U);
    }
  }

  ctx->erased_sectors = resumed_erased_sectors;
  ctx->write_cursor = target_addr + staged;
  ctx->bytes_queued = staged;
  ctx->buf_len = 0U;
  ctx->total_size = total_size;
  ctx->state = TOOB_OTA_STATE_RECEIVING;

  if (expected_sha256 != NULL) {
    if (toob_os_sha256_init(&ctx->sha_ctx) != TOOB_OK) {
      _ctx_reset(ctx);
      toob_ota_checkpoint_clear();
      return TOOB_ERR_NOT_SUPPORTED;
    }
    memcpy(ctx->expected_sha256, expected_sha256, 32U);
    ctx->is_verified = 1U;

    uint32_t rehashed = 0U;
    while (rehashed < staged) {
      uint32_t chunk_len = TOOB_OTA_BUF_SIZE;
      if ((staged - rehashed) < chunk_len) {
        chunk_len = staged - rehashed;
      }

      toob_status_t rd =
          toob_os_flash_read(target_addr + rehashed, ctx->align_buf, chunk_len);
      if (rd != TOOB_OK) {
        _ctx_reset(ctx);
        toob_ota_checkpoint_clear();
        return rd;
      }

      if (toob_os_sha256_update(&ctx->sha_ctx, ctx->align_buf, chunk_len) != TOOB_OK) {
        _ctx_reset(ctx);
        toob_ota_checkpoint_clear();
        return TOOB_ERR_NOT_SUPPORTED;
      }

      rehashed += chunk_len;
    }
    toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
  }

  *resume_offset = staged;
  return TOOB_OK;
}

toob_status_t toob_ota_resume(toob_ota_ctx_t *ctx, uint32_t total_size,
                              const uint8_t expected_sha256[32],
                              uint32_t *resume_offset) {
  return toob_ota_resume_assigned(ctx, total_size, expected_sha256, NULL, resume_offset);
}

toob_status_t toob_ota_trim_total_size(toob_ota_ctx_t *ctx, uint32_t exact_total_size) {
  if (!ctx) {
    return TOOB_ERR_INVALID_ARG;
  }
  toob_os_lock();
  if (ctx->state != TOOB_OTA_STATE_RECEIVING ||
      exact_total_size == 0U ||
      exact_total_size < ctx->bytes_queued ||
      exact_total_size > ctx->total_size) {
    toob_os_unlock();
    return TOOB_ERR_INVALID_ARG;
  }
  ctx->total_size = exact_total_size;
  if (ctx->bytes_queued == ctx->total_size) {
    ctx->state = TOOB_OTA_STATE_DONE;
  }
  toob_os_unlock();
  return TOOB_OK;
}

toob_status_t toob_ota_process_chunk(toob_ota_ctx_t *ctx, const uint8_t *chunk, uint32_t len) {
  if (!ctx || ctx->state != TOOB_OTA_STATE_RECEIVING || !chunk || len == 0U) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* MED-21: Reject out-of-bounds chunk BEFORE mutating streaming SHA-256 context! */
  if (len > (ctx->total_size - ctx->bytes_queued)) {
    return TOOB_ERR_INVALID_ARG;
  }

  if (ctx->is_verified != 0U) {
    if (toob_os_sha256_update(&ctx->sha_ctx, chunk, len) != TOOB_OK) {
      ctx->state = TOOB_OTA_STATE_ERROR;
      return TOOB_ERR_NOT_SUPPORTED;
    }
  }

  uint32_t chunk_pos = 0U;
  bool flushed_any = false;

  while (chunk_pos < len) {
    uint32_t space_left = TOOB_OTA_BUF_SIZE - ctx->buf_len;
    uint32_t remaining = len - chunk_pos;
    uint32_t to_copy = (remaining < space_left) ? remaining : space_left;

    memcpy(&ctx->align_buf[ctx->buf_len], &chunk[chunk_pos], to_copy);
    ctx->buf_len += to_copy;
    chunk_pos += to_copy;
    ctx->bytes_queued += to_copy;

    if (ctx->buf_len == TOOB_OTA_BUF_SIZE) {
      toob_status_t res = _flush_buffer(ctx, TOOB_OTA_BUF_SIZE);
      if (res != TOOB_OK) {
        ctx->state = TOOB_OTA_STATE_ERROR;
        toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
        return res;
      }
      ctx->buf_len = 0U;
      flushed_any = true;
      toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
    }
  }

  if (ctx->bytes_queued == ctx->total_size) {
    ctx->state = TOOB_OTA_STATE_DONE;
  }

  /* HIGH-21: Checkpoint ONLY physically flushed flash bytes, bound to target_addr. */
  if (flushed_any) {
    uint32_t flushed = ctx->bytes_queued - ctx->buf_len;
    uint32_t target_addr = ctx->write_cursor - flushed;
    toob_ota_checkpoint_save_bound(flushed, target_addr,
                                   (ctx->is_verified != 0U) ? ctx->expected_sha256 : NULL);
  }

  return TOOB_OK;
}

toob_status_t toob_ota_finalize(toob_ota_ctx_t *ctx) {
  if (!ctx) {
    return TOOB_ERR_INVALID_ARG;
  }
  if (ctx->state != TOOB_OTA_STATE_DONE &&
      !(ctx->state == TOOB_OTA_STATE_RECEIVING && ctx->is_verified == 0U &&
        ctx->bytes_queued > 0U && ctx->bytes_queued == ctx->total_size)) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* CRIT-23: Derive locked staging base directly from ctx (eliminates .noinit TOCTOU). */
  if (ctx->bytes_queued < ctx->buf_len) {
    return TOOB_ERR_STATE;
  }
  uint32_t flushed_before = ctx->bytes_queued - ctx->buf_len;
  if (ctx->write_cursor < flushed_before) {
    return TOOB_ERR_STATE;
  }
  uint32_t target_addr = ctx->write_cursor - flushed_before;
  uint32_t target_size = 0U;
  toob_status_t slot_st = _ota_resolve_slot_size(target_addr, &target_size);
  if (slot_st != TOOB_OK) {
    ctx->state = TOOB_OTA_STATE_ERROR;
    toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
    return slot_st;
  }
  if (ctx->total_size == 0U || ctx->total_size > target_size ||
      toob_flash_range_hits_immutable_boot(target_addr, ctx->total_size)) {
    ctx->state = TOOB_OTA_STATE_ERROR;
    toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
    return TOOB_ERR_FLASH;
  }

  /* Flush residual bytes (pad trailing alignment bytes with 0xFF). */
  if (ctx->buf_len > 0U) {
    uint32_t aligned_len = ctx->buf_len;
    uint32_t remainder = aligned_len % CHIP_FLASH_WRITE_ALIGNMENT;
    if (remainder != 0U) {
      aligned_len += (CHIP_FLASH_WRITE_ALIGNMENT - remainder);
    }

    if (aligned_len > TOOB_OTA_BUF_SIZE) {
      ctx->state = TOOB_OTA_STATE_ERROR;
      toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
      return TOOB_ERR_INVALID_ARG;
    }

    if (aligned_len > ctx->buf_len) {
      memset(&ctx->align_buf[ctx->buf_len], 0xFF, aligned_len - ctx->buf_len);
    }

    toob_status_t res = _flush_buffer(ctx, aligned_len);
    if (res != TOOB_OK) {
      ctx->state = TOOB_OTA_STATE_ERROR;
      toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
      return res;
    }
    ctx->buf_len = 0U;
  }

  toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);

  if (ctx->is_verified != 0U) {
    uint8_t final_hash[32];
    toob_secure_zeroize(final_hash, sizeof(final_hash));
    if (toob_os_sha256_finalize(&ctx->sha_ctx, final_hash) != TOOB_OK) {
      _ctx_reset(ctx);
      toob_ota_checkpoint_clear();
      return TOOB_ERR_VERIFY;
    }

    toob_status_t cmp_st =
        toob_ct_memcmp_glitch_safe(final_hash, ctx->expected_sha256, 32U);
    toob_secure_zeroize(final_hash, sizeof(final_hash));

    if (cmp_st != TOOB_OK) {
      _ctx_reset(ctx);
      toob_ota_checkpoint_clear();
      return TOOB_ERR_VERIFY;
    }
  }

  uint32_t manifest_addr = target_addr;
  uint32_t stream_len = ctx->total_size;

  if (stream_len >= (uint32_t)(576U + sizeof(toob_tbm1_trailer_locator_t))) {
    toob_tbm1_trailer_locator_t loc;
    toob_secure_zeroize(&loc, sizeof(loc));
    uint32_t loc_addr = target_addr + stream_len - (uint32_t)sizeof(loc);
    if (toob_os_flash_read(loc_addr, (uint8_t *)&loc, (uint32_t)sizeof(loc)) == TOOB_OK &&
        loc.magic == TOOB_TBM1_TRAILER_MAGIC) {
      uint32_t calc_crc = toob_lib_crc32(
          (const uint8_t *)&loc, offsetof(toob_tbm1_trailer_locator_t, crc32));
      uint32_t body_limit = stream_len - (uint32_t)sizeof(loc);
      if (calc_crc == loc.crc32 &&
          loc.tbm1_off <= body_limit &&
          loc.tbm1_len >= 576U &&
          loc.tbm1_len <= (body_limit - loc.tbm1_off)) {
        manifest_addr = target_addr + loc.tbm1_off;
      }
    }
    toob_secure_zeroize(&loc, sizeof(loc));
  }

  _ctx_reset(ctx);
  toob_ota_checkpoint_clear();

#if TOOB_SWAP_EVENT_STATE
  toob_os_lock();
  toob_swap_notify_fn notify_cb = g_swap_notifier;
  toob_os_unlock();
  if (notify_cb != NULL) {
    toob_swap_event_t ev = {
        .abi_version = TOOB_SWAP_EVENT_ABI_VERSION,
        .phase = TOOB_SWAP_PHASE_PREPARE,
        .sectors_done = 0U,
        .sectors_total = 0U,
        .flags = 0U,
    };
    notify_cb(&ev);
  }
#endif

  return toob_set_next_update(manifest_addr);
}
