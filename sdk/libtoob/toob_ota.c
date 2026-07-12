/**
 * ==============================================================================
 * Toob-Boot libtoob: OTA Daemon Implementation (toob_ota.c)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/lol.md (Case 1 & Case 2 Update Cycle logic)
 * - docs/libtoob_api.md (toob_set_next_update delegation)
 * - docs/testing_requirements.md (P10 compliance, zero dynamic allocation)
 * - docs/concept_fusion.md (WAL transaction architecture)
 *
 * ARCHITECTURAL PROPERTIES:
 * 1. Network-Agnostic Stream Writer: The RTOS pushes arbitrary-length
 *    chunks. This module internally buffers and aligns them to the
 *    CHIP_FLASH_WRITE_ALIGNMENT before flushing to the Staging Slot.
 * 2. Zero Dynamic Allocation: All buffers are statically sized and
 *    bounded by _Static_assert at compile time.
 * 3. Glitch-Resistant Flash Verification: Every flash write is
 *    double-checked via the established TOOB_GLITCH_DELAY shield pattern.
 * 4. Single-Exit Cleanup: Sensitive alignment buffers are zeroized
 *    before every return path (P10 Stack Leakage Defense).
 * 5. Context-Based Re-Entrancy: All session state lives in a caller-
 *    allocated toob_ota_ctx_t, enabling parallel OTA sessions.
 */

#include "libtoob.h"
#include "libtoob_config_sandbox.h"
#include "toob_internal.h"
#include <string.h>

#ifndef CHIP_STAGING_SLOT_ABS_ADDR
#define CHIP_STAGING_SLOT_ABS_ADDR 0x0
#endif
#ifndef CHIP_STAGING_SLOT_SIZE
#define CHIP_STAGING_SLOT_SIZE 0x0
#endif
#ifndef CHIP_FLASH_WRITE_ALIGNMENT
#define CHIP_FLASH_WRITE_ALIGNMENT CHIP_FLASH_WRITE_ALIGN
#endif



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

/* P10: Alignment buffer must be an exact multiple of flash write alignment */
_Static_assert(
    TOOB_OTA_BUF_SIZE % CHIP_FLASH_WRITE_ALIGNMENT == 0,
    "OTA alignment buffer must be a multiple of CHIP_FLASH_WRITE_ALIGNMENT");
_Static_assert(TOOB_OTA_BUF_SIZE > 0 && TOOB_OTA_BUF_SIZE <= 4096,
               "OTA alignment buffer must be within sane bounds [1..4096]");

/* ==============================================================================
 * INTERNAL HELPERS
 * ==============================================================================
 */

static void _ctx_reset(toob_ota_ctx_t *ctx) {
    toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
    toob_secure_zeroize(ctx->expected_sha256, sizeof(ctx->expected_sha256));
    toob_secure_zeroize(&ctx->sha_ctx, sizeof(ctx->sha_ctx));
    ctx->state = TOOB_OTA_STATE_IDLE;
    ctx->buf_len = 0;
    ctx->bytes_queued = 0;
    ctx->write_cursor = CHIP_STAGING_SLOT_ABS_ADDR;
    ctx->total_size = 0;
    ctx->is_verified = 0;
}

static toob_status_t _flush_buffer(toob_ota_ctx_t *ctx, uint32_t write_len) {
  if (write_len == 0 || write_len > TOOB_OTA_BUF_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_status_t res =
      toob_os_flash_write(ctx->write_cursor, ctx->align_buf, write_len);

  /* Glitch-Resistant Double-Check on flash result */
  volatile uint32_t shield_1 = 0, shield_2 = 0;
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

  /* Phase-Bound Chunked Read-Back Verify (Defense-in-Depth: SRAM→Flash).
   * Matches pattern from toob_submit_cloud_command — 64-byte stack chunk,
   * ghost-match-proof, glitch-safe comparison. */
  {
    uint8_t rb_buf[64] __attribute__((aligned(8)));
    uint32_t pos = 0;

    while (pos < write_len) {
      uint32_t remaining = write_len - pos;
      uint32_t chunk = (remaining > 64U) ? 64U : remaining;

      /* Ghost-Match-Proof: zero before read forces actual flash access */
      toob_secure_zeroize(rb_buf, sizeof(rb_buf));

      toob_status_t rd = toob_os_flash_read(
          ctx->write_cursor + pos, rb_buf, chunk);
      if (rd != TOOB_OK) {
        toob_secure_zeroize(rb_buf, sizeof(rb_buf));
        return TOOB_ERR_FLASH_HW;
      }

      if (toob_ct_memcmp_glitch_safe(
              &ctx->align_buf[pos], rb_buf, chunk) != TOOB_OK) {
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
 * PUBLIC API
 * ==============================================================================
 */

toob_status_t toob_ota_ctx_init(toob_ota_ctx_t *ctx) {
    if (!ctx) return TOOB_ERR_INVALID_ARG;
    toob_secure_zeroize(ctx, sizeof(toob_ota_ctx_t));
    ctx->write_cursor = CHIP_STAGING_SLOT_ABS_ADDR;
    return TOOB_OK;
}

static toob_status_t _ota_begin_core(toob_ota_ctx_t *ctx, uint32_t total_size) {

  if (!ctx) return TOOB_ERR_INVALID_ARG;
  if (total_size == 0 || total_size > CHIP_STAGING_SLOT_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Reject re-entry while a transfer is active */
  if (ctx->state == TOOB_OTA_STATE_RECEIVING) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Erase Flash before write (Erase-Before-Write Hardware Constraint) */
  /* P10 Fix: Align total size to flash erase sectors */
  uint32_t erase_size = total_size;
  uint32_t remainder = erase_size % CHIP_FLASH_MAX_SECTOR_SIZE;
  if (remainder != 0) {
    erase_size += (CHIP_FLASH_MAX_SECTOR_SIZE - remainder);
  }
  if (erase_size > CHIP_STAGING_SLOT_SIZE) {
      erase_size = CHIP_STAGING_SLOT_SIZE;
  }
  
  toob_status_t res = toob_os_flash_erase(CHIP_STAGING_SLOT_ABS_ADDR, erase_size);
  if (res != TOOB_OK) {
      return res;
  }

  _ctx_reset(ctx);

  ctx->write_cursor = CHIP_STAGING_SLOT_ABS_ADDR;
  ctx->total_size = total_size;
  ctx->state = TOOB_OTA_STATE_RECEIVING;

  return TOOB_OK;
}

toob_status_t toob_ota_begin(toob_ota_ctx_t *ctx, uint32_t total_size) {
    return _ota_begin_core(ctx, total_size);
}

toob_status_t toob_ota_begin_verified(toob_ota_ctx_t *ctx, uint32_t total_size, const uint8_t expected_sha256[32]) {
    toob_status_t res = _ota_begin_core(ctx, total_size);
    if (res != TOOB_OK) return res;

    if (toob_os_sha256_init(&ctx->sha_ctx) != TOOB_OK) {
        _ctx_reset(ctx);
        return TOOB_ERR_NOT_SUPPORTED;
    }

    memcpy(ctx->expected_sha256, expected_sha256, 32);
    ctx->is_verified = 1;
    return TOOB_OK;
}

toob_status_t toob_ota_abort(toob_ota_ctx_t *ctx) {
    if (!ctx) return TOOB_ERR_INVALID_ARG;
    _ctx_reset(ctx);
    return TOOB_OK;
}

toob_status_t toob_ota_resume(toob_ota_ctx_t *ctx, uint32_t total_size, uint32_t* resume_offset) {
    if (!ctx || !resume_offset) return TOOB_ERR_INVALID_ARG;
    if (total_size == 0 || total_size > CHIP_STAGING_SLOT_SIZE) return TOOB_ERR_INVALID_ARG;

    if (ctx->state == TOOB_OTA_STATE_RECEIVING) {
        *resume_offset = ctx->bytes_queued;
        return TOOB_OK;
    }

    /* GAP-02: Lese Checkpoint aus dem OS Handoff RAM */
    if (toob_validate_handoff() == TOOB_OK) {
        if (toob_handoff_state.resume_offset > 0 && toob_handoff_state.resume_offset <= CHIP_STAGING_SLOT_SIZE) {
            ctx->write_cursor = CHIP_STAGING_SLOT_ABS_ADDR + toob_handoff_state.resume_offset;
            ctx->bytes_queued = toob_handoff_state.resume_offset;
            ctx->total_size = total_size;
            ctx->state = TOOB_OTA_STATE_RECEIVING;
            *resume_offset = ctx->bytes_queued;
            return TOOB_OK;
        }
    }

    return TOOB_ERR_NOT_FOUND;
}

toob_status_t toob_ota_resume_verified(toob_ota_ctx_t *ctx, uint32_t total_size,
                                       const uint8_t expected_sha256[32],
                                       uint32_t *resume_offset) {
    if (!ctx || !resume_offset || !expected_sha256) return TOOB_ERR_INVALID_ARG;

    /* Delegate core resume logic (validates handoff, restores cursors & total_size) */
    toob_status_t stat = toob_ota_resume(ctx, total_size, resume_offset);
    if (stat != TOOB_OK) return stat;

    uint32_t prefix_len = *resume_offset;
    if (prefix_len == 0) return TOOB_OK; /* Nothing to re-hash */

    /* Initialize SHA-256 streaming context */
    if (toob_os_sha256_init(&ctx->sha_ctx) != TOOB_OK) {
        _ctx_reset(ctx);
        return TOOB_ERR_NOT_SUPPORTED;
    }

    /* Re-hash the already-staged prefix by reading it back from flash.
     * Reuses ctx->align_buf as temporary read buffer — zero additional allocation. */
    uint32_t rehashed = 0;
    while (rehashed < prefix_len) {
        uint32_t chunk_len = TOOB_OTA_BUF_SIZE;
        if (rehashed + chunk_len > prefix_len) {
            chunk_len = prefix_len - rehashed;
        }

        toob_status_t rd = toob_os_flash_read(
            CHIP_STAGING_SLOT_ABS_ADDR + rehashed,
            ctx->align_buf,
            chunk_len);
        if (rd != TOOB_OK) {
            _ctx_reset(ctx);
            return rd;
        }

        if (toob_os_sha256_update(&ctx->sha_ctx, ctx->align_buf, chunk_len) != TOOB_OK) {
            _ctx_reset(ctx);
            return TOOB_ERR_NOT_SUPPORTED;
        }

        rehashed += chunk_len;
    }

    toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);

    memcpy(ctx->expected_sha256, expected_sha256, 32);
    ctx->is_verified = 1;

    return TOOB_OK;
}

toob_status_t toob_ota_process_chunk(toob_ota_ctx_t *ctx, const uint8_t *chunk, uint32_t len) {
  if (!ctx) return TOOB_ERR_INVALID_ARG;
  if (ctx->state != TOOB_OTA_STATE_RECEIVING) {
    return TOOB_ERR_INVALID_ARG;
  }
  if (!chunk || len == 0) {
    return TOOB_ERR_INVALID_ARG;
  }

  if (ctx->is_verified) {
      if (toob_os_sha256_update(&ctx->sha_ctx, chunk, len) != TOOB_OK) {
          ctx->state = TOOB_OTA_STATE_ERROR;
          return TOOB_ERR_NOT_SUPPORTED;
      }
  }

  /* Overflow guard: total bytes received must not exceed declared size */
  if (ctx->bytes_queued + len < ctx->bytes_queued) { /* Arithmetic overflow check */
    ctx->state = TOOB_OTA_STATE_ERROR;
    return TOOB_ERR_INVALID_ARG;
  }
  if (ctx->bytes_queued + len > ctx->total_size) {
    ctx->state = TOOB_OTA_STATE_ERROR;
    return TOOB_ERR_INVALID_ARG;
  }

  uint32_t chunk_pos = 0;

  /* P10 Bounded Loop: chunk_pos strictly advances by at least 1 each iteration */
  while (chunk_pos < len) {
    uint32_t space_left = TOOB_OTA_BUF_SIZE - ctx->buf_len;
    uint32_t remaining = len - chunk_pos;
    uint32_t to_copy = (remaining < space_left) ? remaining : space_left;

    memcpy(&ctx->align_buf[ctx->buf_len], &chunk[chunk_pos], to_copy);
    ctx->buf_len += to_copy;
    chunk_pos += to_copy;
    ctx->bytes_queued += to_copy;

    /* Flush when buffer is exactly full (guaranteed aligned) */
    if (ctx->buf_len == TOOB_OTA_BUF_SIZE) {
      toob_status_t res = _flush_buffer(ctx, TOOB_OTA_BUF_SIZE);
      if (res != TOOB_OK) {
        ctx->state = TOOB_OTA_STATE_ERROR;
        toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
        return res;
      }
      ctx->buf_len = 0;
      toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);


    }
  }

  /* Transition to DONE when all declared bytes have been received */
  if (ctx->bytes_queued == ctx->total_size) {
    ctx->state = TOOB_OTA_STATE_DONE;
  }

  return TOOB_OK;
}

toob_status_t toob_ota_finalize(toob_ota_ctx_t *ctx) {
  if (!ctx) return TOOB_ERR_INVALID_ARG;
  if (ctx->state != TOOB_OTA_STATE_DONE) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Flush residual bytes (pad to CHIP_FLASH_WRITE_ALIGNMENT) */
  if (ctx->buf_len > 0) {
    uint32_t aligned_len = ctx->buf_len;
    uint32_t remainder = aligned_len % CHIP_FLASH_WRITE_ALIGNMENT;
    if (remainder != 0) {
      aligned_len += (CHIP_FLASH_WRITE_ALIGNMENT - remainder);
    }

    /* Safety: clamped write must never exceed buffer capacity */
    if (aligned_len > TOOB_OTA_BUF_SIZE) {
      ctx->state = TOOB_OTA_STATE_ERROR;
      toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
      return TOOB_ERR_INVALID_ARG;
    }

    toob_status_t res = _flush_buffer(ctx, aligned_len);
    if (res != TOOB_OK) {
      ctx->state = TOOB_OTA_STATE_ERROR;
      toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);
      return res;
    }
  }

  /* P10: Zeroize alignment buffer before WAL transaction */
  toob_secure_zeroize(ctx->align_buf, TOOB_OTA_BUF_SIZE);

  if (ctx->is_verified) {
      uint8_t final_hash[32];
      toob_secure_zeroize(final_hash, sizeof(final_hash));
      if (toob_os_sha256_finalize(&ctx->sha_ctx, final_hash) != TOOB_OK) {
          _ctx_reset(ctx);
          return TOOB_ERR_VERIFY;
      }
      
      /* GAP-20: Provably constant-time hash comparison via XOR accumulator */
      volatile uint8_t diff = 0;
      for (int i = 0; i < 32; i++) {
          diff |= final_hash[i] ^ ctx->expected_sha256[i];
      }
      
      toob_secure_zeroize(final_hash, sizeof(final_hash));
      
      if (diff != 0) {
          _ctx_reset(ctx);
          return TOOB_ERR_VERIFY;
      }
  }

  /* Reset state machine BEFORE WAL write (prevents re-entry on partial failure) */
  _ctx_reset(ctx);

  /* Atomically register the update intent in the WAL */
  return toob_set_next_update(CHIP_STAGING_SLOT_ABS_ADDR);
}
