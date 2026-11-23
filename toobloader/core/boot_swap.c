/*
 * ==============================================================================
 * Toob-Boot Core File: boot_swap.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/concept_fusion.md (Brownout Recovery, Zero-Allocation)
 * - docs/toobfuzzer_integration.md (Fuzzing parameters, Alignment limitations)
 */

#include "boot_swap.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_effect.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include "boot_slot_transport.h"
#include "boot_stream_writer.h"
#include "generated_boot_config.h"
#include <string.h>

#ifndef TOOB_TA1_STRICT_NO_CRC_SKIP
#define TOOB_TA1_STRICT_NO_CRC_SKIP 1
#endif
#if defined(TOOB_PROFILE_PRODUCTION) && !TOOB_TA1_STRICT_NO_CRC_SKIP
#error "TOOB_TA1_STRICT_NO_CRC_SKIP=0 forbidden in production!"
#endif

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 512,
               "Crypto Arena is too small for chunked flash operations!");
_Static_assert(BOOT_OK == 0x55AA55AA, "Glitch-Defense requires high-Hamming-distance BOOT_OK");

/* ==============================================================================
 * SHARED STREAMING FLASH WRITER (ARCH-T02, MED-08, MED-09)
 * ==============================================================================
 */

static boot_status_t stream_erase_ahead(boot_stream_writer_t *w, uint32_t write_end) {
  const boot_platform_t *p = w->platform;

  while (w->erased_end < write_end) {
    size_t sec = 0U;
    if (p->flash->get_sector_size(w->erased_end, &sec) != BOOT_OK || sec == 0U) {
      return BOOT_ERR_FLASH_HW;
    }

    if (boot_flash_range_hits_immutable_boot(w->erased_end, sec)) {
      return BOOT_ERR_FLASH_BOUNDS;
    }

    bool sec_erased = false;
    bool needs_erase =
        (boot_flash_is_erased(p, w->erased_end, sec, &sec_erased) != BOOT_OK) || !sec_erased;

    if (needs_erase) {
      const bool big = (sec >= CHIP_FLASH_MAX_SECTOR_SIZE);
      if (big && p->wdt != NULL && p->wdt->suspend_for_critical_section != NULL) {
        p->wdt->suspend_for_critical_section();
      } else if (p->wdt != NULL && p->wdt->kick != NULL) {
        p->wdt->kick();
      }

      boot_status_t er = boot_flash_erase_sector_guarded(p->flash, w->erased_end);

      if (big && p->wdt != NULL && p->wdt->resume != NULL) {
        p->wdt->resume();
      } else if (p->wdt != NULL && p->wdt->kick != NULL) {
        p->wdt->kick();
      }

      if (er != BOOT_OK) {
        return er;
      }
    }

    if (UINT32_MAX - w->erased_end < (uint32_t)sec) {
      return BOOT_ERR_FLASH_BOUNDS;
    }
    w->erased_end += (uint32_t)sec;
  }

  return BOOT_OK;
}

static boot_status_t stream_write_skip_erased(const flash_hal_t *flash, uint32_t dst,
                                              const uint8_t *buf, uint32_t len) {
  uint32_t align = (flash->write_align > 0U) ? flash->write_align : 1U;
  if ((dst % align) != 0U || (len % align) != 0U) {
    return boot_flash_write_guarded(flash, dst, buf, len);
  }

  uint8_t erased = flash->erased_value;
  uint32_t pos = 0U;
  while (pos < len) {
    while (pos < len && is_fully_erased_constant_time(buf + pos, align, erased)) {
      pos += align;
    }
    if (pos >= len) {
      break;
    }
    uint32_t run_start = pos;
    pos += align;
    while (pos < len && !is_fully_erased_constant_time(buf + pos, align, erased)) {
      pos += align;
    }
    boot_status_t st =
        boot_flash_write_guarded(flash, dst + run_start, buf + run_start, pos - run_start);
    if (st != BOOT_OK) {
      return st;
    }
  }
  return BOOT_OK;
}

static boot_status_t stream_verify_readback(const boot_platform_t *p, uint32_t addr,
                                            const uint8_t *expect, uint32_t len) {
  uint8_t rb[BOOT_STREAM_RB_WINDOW] __attribute__((aligned(8)));
  uint32_t off = 0U;
  while (off < len) {
    if (p->wdt != NULL && p->wdt->kick != NULL) {
      p->wdt->kick();
    }
    uint32_t step = ((len - off) > BOOT_STREAM_RB_WINDOW) ? BOOT_STREAM_RB_WINDOW : (len - off);
    boot_secure_zeroize(rb, step);
    if (p->flash->read(addr + off, rb, step) != BOOT_OK) {
      boot_secure_zeroize(rb, sizeof(rb));
      return BOOT_ERR_FLASH_HW;
    }
    BOOT_SECURE_REQUIRE(constant_time_memcmp_glitch_safe(rb, expect + off, step) == BOOT_OK, {
      boot_secure_zeroize(rb, sizeof(rb));
      return BOOT_ERR_FLASH_HW;
    });
    off += step;
  }
  boot_secure_zeroize(rb, sizeof(rb));
  return BOOT_OK;
}

boot_status_t boot_stream_writer_init(boot_stream_writer_t *w, const boot_platform_t *platform,
                                      uint32_t dest_addr, uint32_t expected_target_size,
                                      uint8_t *write_buf, uint32_t raw_write_cap,
                                      wal_entry_payload_t *open_txn) {
  if (w == NULL || platform == NULL || platform->flash == NULL || write_buf == NULL ||
      open_txn == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint32_t align =
      (platform->flash->write_align > 0U) ? (uint32_t)platform->flash->write_align : 1U;
  if (align > BOOT_STREAM_MAX_WRITE_ALIGN) {
    return BOOT_ERR_INVALID_ARG;
  }
  /* Coalesce sub-16B write_align up to 16B on 16B-aligned slots so XTS-AES
   * hardware flash encryption (e.g. ESP32-C6) never sees unaligned mid-stream
   * flushes even when unencrypted write_align is 4B. */
  if (align < 16U && (16U % align) == 0U && (dest_addr % 16U) == 0U && raw_write_cap >= 32U) {
    align = 16U;
  }
  if ((dest_addr % align) != 0U) {
    return BOOT_ERR_FLASH_ALIGN;
  }

  uint32_t buf_align = (align > 8U) ? align : 8U;
  uint32_t aligned_cap = (raw_write_cap / buf_align) * buf_align;
  if (aligned_cap < (buf_align * 2U)) {
    return BOOT_ERR_INVALID_STATE;
  }

  boot_secure_zeroize(w, sizeof(*w));
  w->platform = platform;
  w->dest_addr = dest_addr;
  w->expected_target_size = expected_target_size;
  w->write_align = align;
  w->write_buf = write_buf;
  w->write_cap = aligned_cap;
  w->erased_end = dest_addr;
  w->txn = open_txn;

  uint32_t checkpoint = 0U;
  if ((open_txn->intent == WAL_INTENT_UPDATE_PENDING ||
       open_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING) &&
      open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] == TOOB_PHASE_STREAM_WRITE) {
    checkpoint = open_txn->delta_chunk_id;
    if (checkpoint > expected_target_size) {
      checkpoint = expected_target_size;
    }
  }

  if (checkpoint > 0U) {
    if ((checkpoint % align) != 0U) {
      return BOOT_ERR_INVALID_STATE;
    }
    uint32_t curr = 0U;
    while (curr < checkpoint) {
      size_t sec = 0U;
      if (platform->flash->get_sector_size(dest_addr + curr, &sec) != BOOT_OK || sec == 0U) {
        return BOOT_ERR_FLASH_HW;
      }
      if (UINT32_MAX - curr < (uint32_t)sec) {
        return BOOT_ERR_FLASH_BOUNDS;
      }
      curr += (uint32_t)sec;
    }
    if (curr != checkpoint) {
      return BOOT_ERR_INVALID_STATE;
    }
    w->flushed_off = checkpoint;
    w->committed_off = checkpoint;
    w->checkpoint_off = checkpoint;
    w->erased_end = dest_addr + checkpoint;
  }

  return BOOT_OK;
}

boot_status_t boot_stream_writer_flush(boot_stream_writer_t *w, bool pad_final) {
  const boot_platform_t *p = w->platform;
  if (w->write_pos == 0U) {
    return BOOT_OK;
  }

  const uint32_t logical_start = w->target_off - w->write_pos;

  /* Entire buffer lies in the already-flushed (replayed) region -> discard. */
  if (logical_start + w->write_pos <= w->flushed_off) {
    w->write_pos = 0U;
    return BOOT_OK;
  }

  uint32_t valid_off = (logical_start < w->flushed_off) ? (w->flushed_off - logical_start) : 0U;
  uint32_t avail_len = w->write_pos - valid_off;
  uint32_t align = w->write_align;
  uint32_t write_len = 0U;
  uint32_t carry_len = 0U;

  if (!pad_final) {
    carry_len = avail_len % align;
    write_len = avail_len - carry_len;
    if (write_len == 0U) {
      if (valid_off > 0U && carry_len > 0U) {
        memmove(w->write_buf, w->write_buf + valid_off, carry_len);
      }
      w->write_pos = carry_len;
      return BOOT_OK;
    }
  } else {
    uint32_t rem = avail_len % align;
    write_len = avail_len;
    if (rem != 0U) {
      uint32_t pad = align - rem;
      if (valid_off > 0U && (valid_off + avail_len + pad) > w->write_cap) {
        memmove(w->write_buf, w->write_buf + valid_off, avail_len);
        valid_off = 0U;
      }
      if ((uint64_t)valid_off + avail_len + pad > w->write_cap) {
        return BOOT_ERR_FLASH_BOUNDS;
      }
      memset(w->write_buf + valid_off + avail_len, p->flash->erased_value, pad);
      write_len += pad;
    }
  }

  if (UINT32_MAX - w->dest_addr < w->flushed_off) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  const uint32_t dest = w->dest_addr + w->flushed_off;
  if (UINT32_MAX - dest < write_len) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  boot_status_t st = stream_erase_ahead(w, dest + write_len);
  if (st != BOOT_OK) {
    return st;
  }

  if (p->wdt != NULL && p->wdt->kick != NULL) {
    p->wdt->kick();
  }
  boot_status_t wr_st =
      stream_write_skip_erased(p->flash, dest, w->write_buf + valid_off, write_len);
  if (wr_st != BOOT_OK) {
    return (wr_st == BOOT_ERR_FLASH_BOUNDS) ? BOOT_ERR_FLASH_BOUNDS : BOOT_ERR_FLASH_HW;
  }

  st = stream_verify_readback(p, dest, w->write_buf + valid_off, write_len);
  if (st != BOOT_OK) {
    return st;
  }

  w->flushed_off += write_len;

  if (carry_len > 0U) {
    memmove(w->write_buf, w->write_buf + valid_off + write_len, carry_len);
    w->write_pos = carry_len;
  } else {
    w->write_pos = 0U;
  }

  /* Advance sector-aligned commit high-water over newly-complete sectors. */
  for (;;) {
    size_t sec = 0U;
    if (p->flash->get_sector_size(w->dest_addr + w->committed_off, &sec) != BOOT_OK || sec == 0U) {
      return BOOT_ERR_FLASH_HW;
    }
    if (w->committed_off + (uint32_t)sec > w->flushed_off) {
      break;
    }
    w->committed_off += (uint32_t)sec;
  }

  if (w->committed_off - w->checkpoint_off >= CHIP_FLASH_MAX_SECTOR_SIZE) {
    w->txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = TOOB_PHASE_STREAM_WRITE;
    w->txn->delta_chunk_id = w->committed_off;
    boot_status_t log = boot_journal_append(p, w->txn);
    if (log != BOOT_OK) {
      return log;
    }
    w->checkpoint_off = w->committed_off;
  }

  return BOOT_OK;
}

/* ==============================================================================
 * INTERNAL ZERO-ALLOCATION ERASE & TRANSPORT HELPERS
 * ==============================================================================
 */

/**
 * @brief Internal tracker for physical flash erases.
 * Smart-Erase scans sectors via boot_flash_is_erased to avoid unnecessary erases.
 */
static boot_status_t boot_swap_erase_tracked(const boot_platform_t *platform, uint32_t addr,
                                             size_t length, uint32_t *erases_out, uint8_t *arena,
                                             size_t arena_len) {
  (void)arena;
  (void)arena_len;

  if (!platform || !platform->flash || !platform->flash->erase_sector ||
      !platform->flash->get_sector_size) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (length == 0U) {
    return BOOT_OK;
  }
  if (UINT32_MAX - addr < length) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint32_t current_addr = addr;
  uint32_t end_addr = addr + (uint32_t)length;
  uint32_t loop_guard = 0U;
  const uint32_t MAX_ERASE_LOOPS = 100000U;

  while (current_addr < end_addr) {
    if (++loop_guard >= MAX_ERASE_LOOPS) {
      return BOOT_ERR_FLASH_HW;
    }

    size_t sec_size = 0U;
    boot_status_t status = platform->flash->get_sector_size(current_addr, &sec_size);
    if (status != BOOT_OK || sec_size == 0U) {
      return BOOT_ERR_FLASH_HW;
    }

    if (boot_flash_range_hits_immutable_boot(current_addr, sec_size)) {
      return BOOT_ERR_FLASH_BOUNDS;
    }

    bool sec_erased = false;
    bool needs_erase =
        (boot_flash_is_erased(platform, current_addr, sec_size, &sec_erased) != BOOT_OK) ||
        !sec_erased;

    if (needs_erase) {
      if (sec_size >= CHIP_FLASH_MAX_SECTOR_SIZE) {
        if (platform->wdt && platform->wdt->suspend_for_critical_section) {
          platform->wdt->suspend_for_critical_section();
        }

        status = boot_flash_erase_sector_guarded(platform->flash, current_addr);

        if (platform->wdt && platform->wdt->resume) {
          platform->wdt->resume();
        }
      } else {
        if (platform->wdt && platform->wdt->kick) {
          platform->wdt->kick();
        }
        status = boot_flash_erase_sector_guarded(platform->flash, current_addr);
        if (platform->wdt && platform->wdt->kick) {
          platform->wdt->kick();
        }
      }

      if (status != BOOT_OK) {
        return status;
      }
      if (erases_out) {
        (*erases_out)++;
      }
    }

    current_addr += (uint32_t)sec_size;
  }

  return BOOT_OK;
}

boot_status_t boot_swap_erase_safe(const boot_platform_t *platform, uint32_t addr, size_t len,
                                   uint8_t *arena, size_t arena_len) {
  return boot_swap_erase_tracked(platform, addr, len, NULL, arena, arena_len);
}

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH

typedef enum { SWAP_STATE_NORMAL = 0, SWAP_STATE_READ_ONLY = 1 } swap_state_t;
static swap_state_t current_swap_state = SWAP_STATE_NORMAL;

static boot_status_t boot_swap_check_eol_survival(const boot_platform_t *platform) {
  if (current_swap_state == SWAP_STATE_READ_ONLY) {
    return BOOT_ERR_COUNTER_EXHAUSTED;
  }
  if (!platform || !platform->flash) {
    return BOOT_ERR_INVALID_ARG;
  }

  wal_tmr_payload_t tmr;
  boot_status_t tmr_status = boot_journal_get_tmr(platform, &tmr);
  if (tmr_status != BOOT_OK) {
    return tmr_status;
  }

  if (platform->flash->max_erase_cycles > 0U) {
    if (tmr.app_slot_erase_counter >= platform->flash->max_erase_cycles) {
      current_swap_state = SWAP_STATE_READ_ONLY;
      return BOOT_ERR_COUNTER_EXHAUSTED;
    }
  }
  return BOOT_OK;
}

/* ==============================================================================
 * PUBLIC BOOT SWAP EXECUTION (Tier-4 Legacy Swap-Scratch Only — MED-09)
 * ==============================================================================
 */

TOOB_IRAM_ATTR boot_status_t boot_swap_apply(const boot_platform_t *platform, uint32_t src_base,
                                             uint32_t dest_base, uint32_t length,
                                             boot_dest_slot_t dest_slot,
                                             wal_entry_payload_t *open_txn, uint8_t *arena,
                                             size_t arena_len) {
  if (!arena || arena_len < 512U) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!platform || !platform->flash || !platform->flash->read || !platform->flash->write ||
      !platform->flash->get_sector_size) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (length > UINT32_MAX - src_base || length > UINT32_MAX - dest_base ||
      length > UINT32_MAX - CHIP_SCRATCH_SLOT_ABS_ADDR) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  if (length == 0U) {
    return BOOT_OK;
  }

  if (platform->flash->write_align > 0U) {
    if ((src_base % platform->flash->write_align != 0U) ||
        (dest_base % platform->flash->write_align != 0U) ||
        (length % platform->flash->write_align != 0U)) {
      return BOOT_ERR_FLASH_ALIGN;
    }
  }

  boot_status_t eol_status = boot_swap_check_eol_survival(platform);
  if (eol_status != BOOT_OK) {
    return eol_status;
  }

  uint32_t current_offset = 0U;

  /* Fast-Forward Recovery Logic via WAL Checkpoint */
  if (open_txn != NULL && (open_txn->intent == WAL_INTENT_UPDATE_PENDING ||
                           open_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING)) {
    current_offset = open_txn->delta_chunk_id;
    if (current_offset > length) {
      current_offset = length;
    }
  }

#if TOOB_SWAP_EVENT_STATE
  size_t standard_sec_size = 4096U;
  if (platform->flash->get_sector_size(dest_base, &standard_sec_size) != BOOT_OK ||
      standard_sec_size == 0U) {
    standard_sec_size = 4096U;
  }

  bool notify_disabled = false;
  const uint32_t NOTIFY_TIMEOUT_MS = 50U;

  if (platform->soc && platform->soc->swap_notify) {
#if TOOB_SWAP_EVENT_PHASE
    uint8_t initial_phase =
        (current_offset > 0U) ? TOOB_SWAP_PHASE_RESUMED : TOOB_SWAP_PHASE_SWAPPING;
#else
    uint8_t initial_phase = TOOB_SWAP_PHASE_SWAPPING;
#endif
    toob_swap_event_t ev = {.abi_version = TOOB_SWAP_EVENT_ABI_VERSION,
                            .phase = initial_phase,
                            .sectors_done = 0U,
                            .sectors_total = 0U,
                            .flags = (current_offset > 0U) ? 1U : 0U};

#if TOOB_SWAP_EVENT_PROGRESS
    ev.sectors_total = (uint32_t)((length + standard_sec_size - 1U) / standard_sec_size);
    ev.sectors_done = (uint32_t)(current_offset / standard_sec_size);
    if (ev.sectors_done > ev.sectors_total) {
      ev.sectors_done = ev.sectors_total;
    }
#endif

    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    uint32_t start_time = platform->clock->get_tick_ms();
    platform->soc->swap_notify(&ev);
    uint32_t duration = platform->clock->get_tick_ms() - start_time;
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    if (duration > NOTIFY_TIMEOUT_MS) {
      notify_disabled = true;
    }
  }
#endif

  const uint32_t MAX_ERASE_LOOPS = 100000U;
  uint32_t loop_guard = 0U;

  uint32_t physical_scratch_erases = 0U;
  uint32_t physical_dest_erases = 0U;
  uint32_t physical_src_erases = 0U;
  boot_status_t status = BOOT_OK;

  /* T3 Wear Leveling: Initialize scratch-ring seed from persistent erase counter */
  uint32_t scratch_seed = 0U;
  wal_tmr_payload_t init_tmr;
  boot_secure_zeroize(&init_tmr, sizeof(init_tmr));
  if (boot_journal_get_tmr(platform, &init_tmr) == BOOT_OK) {
    scratch_seed = init_tmr.swap_buffer_erase_counter;
  }
  boot_secure_zeroize(&init_tmr, sizeof(init_tmr));

  while (current_offset < length) {
    if (++loop_guard >= MAX_ERASE_LOOPS) {
      status = BOOT_ERR_FLASH_HW;
      goto swap_cleanup;
    }

    uint32_t current_src = src_base + current_offset;
    uint32_t current_dest = dest_base + current_offset;

    size_t dest_sec_size = 0U;
    size_t src_sec_size = 0U;
    size_t scratch_sec_size = 0U;

    if (platform->flash->get_sector_size(current_dest, &dest_sec_size) != BOOT_OK ||
        dest_sec_size == 0U || current_dest % dest_sec_size != 0U) {
      status = BOOT_ERR_FLASH_HW;
      goto swap_cleanup;
    }

    if (platform->flash->get_sector_size(current_src, &src_sec_size) != BOOT_OK ||
        src_sec_size == 0U || current_src % src_sec_size != 0U) {
      status = BOOT_ERR_FLASH_HW;
      goto swap_cleanup;
    }

    if (platform->flash->get_sector_size(CHIP_SCRATCH_SLOT_ABS_ADDR, &scratch_sec_size) !=
            BOOT_OK ||
        scratch_sec_size == 0U) {
      status = BOOT_ERR_FLASH_HW;
      goto swap_cleanup;
    }

    size_t block_size = dest_sec_size;
    if (src_sec_size > block_size) {
      block_size = src_sec_size;
    }
    if (scratch_sec_size > block_size) {
      block_size = scratch_sec_size;
    }

    const size_t ring_stride = (scratch_sec_size > block_size) ? scratch_sec_size : block_size;

    if (current_offset + block_size > length) {
      block_size = length - current_offset;
      if (platform->flash->write_align > 0U) {
        uint32_t align = platform->flash->write_align;
        uint32_t rem = (uint32_t)(block_size % align);
        if (rem != 0U) {
          block_size += (align - rem);
        }
      }
    }

    uint32_t scratch_base = CHIP_SCRATCH_SLOT_ABS_ADDR;
    uint32_t scratch_size = CHIP_SCRATCH_SLOT_SIZE;
    uint32_t max_scratch_blocks = (scratch_sec_size > 0U && scratch_size >= (uint32_t)ring_stride)
                                      ? (scratch_size / (uint32_t)ring_stride)
                                      : 1U;
    if (max_scratch_blocks == 0U) {
      max_scratch_blocks = 1U;
    }

    uint32_t chunk_idx = (ring_stride > 0U) ? (current_offset / (uint32_t)ring_stride) : 0U;
    uint32_t ring_idx = (scratch_seed + chunk_idx) % max_scratch_blocks;
    uint32_t current_scratch = scratch_base + (ring_idx * (uint32_t)ring_stride);

    bool is_resuming_this_chunk = (open_txn != NULL && open_txn->delta_chunk_id == current_offset &&
                                   open_txn->transfer_bitmap[2] == 0xAA55AA55U);

    if (is_resuming_this_chunk && open_txn != NULL &&
        open_txn->transfer_bitmap[3] >= scratch_base &&
        open_txn->transfer_bitmap[3] < scratch_base + scratch_size) {
      current_scratch = open_txn->transfer_bitmap[3];
    }

    uint32_t crc_src = 0U;
    uint32_t crc_dest = 0U;

    if (!is_resuming_this_chunk) {
      status =
          boot_crc32_flash_stream(platform, current_src, block_size, &crc_src, arena, arena_len);
      if (status != BOOT_OK) {
        goto swap_cleanup;
      }

      status =
          boot_crc32_flash_stream(platform, current_dest, block_size, &crc_dest, arena, arena_len);
      if (status != BOOT_OK) {
        goto swap_cleanup;
      }

#if !TOOB_TA1_STRICT_NO_CRC_SKIP
      if (crc_src == crc_dest) {
        bool is_identical = false;
        status = boot_swap_blocks_identical(platform, current_dest, current_src, block_size,
                                            &is_identical, arena, arena_len);
        if (status != BOOT_OK) {
          goto swap_cleanup;
        }
        if (is_identical) {
          current_offset += (uint32_t)block_size;
          continue;
        }
      }
#endif

      if (open_txn != NULL) {
        open_txn->delta_chunk_id = current_offset;
        open_txn->transfer_bitmap[0] = crc_src;
        open_txn->transfer_bitmap[1] = crc_dest;
        open_txn->transfer_bitmap[2] = 0xAA55AA55U;
        open_txn->transfer_bitmap[3] = current_scratch;
        boot_status_t log_stat = boot_journal_append(platform, open_txn);
        if (log_stat != BOOT_OK) {
          status = log_stat;
          goto swap_cleanup;
        }
      }
    } else {
      crc_src = open_txn->transfer_bitmap[0];
      crc_dest = open_txn->transfer_bitmap[1];
    }

    bool run_phase_a = true;
    bool run_phase_b = true;
    bool run_phase_c = true;

    if (is_resuming_this_chunk) {
      uint32_t phys_src = 0U;
      uint32_t phys_dest = 0U;
      uint32_t phys_scratch = 0U;

      status =
          boot_crc32_flash_stream(platform, current_src, block_size, &phys_src, arena, arena_len);
      if (status != BOOT_OK) {
        goto swap_cleanup;
      }

      status =
          boot_crc32_flash_stream(platform, current_dest, block_size, &phys_dest, arena, arena_len);
      if (status != BOOT_OK) {
        goto swap_cleanup;
      }

      status = boot_crc32_flash_stream(platform, current_scratch, block_size, &phys_scratch, arena,
                                       arena_len);
      if (status != BOOT_OK) {
        goto swap_cleanup;
      }

      bool dest_has_src = (phys_dest == crc_src);
      bool src_has_dest = (phys_src == crc_dest);
      bool scratch_has_dest = (phys_scratch == crc_dest);
      bool dest_has_dest = (phys_dest == crc_dest);
      bool src_has_src = (phys_src == crc_src);

      if (dest_has_src && src_has_dest) {
        current_offset += (uint32_t)block_size;
        continue;
      }

      if (dest_has_src && !src_has_dest) {
        if (!scratch_has_dest) {
          status = BOOT_ERR_FLASH_HW;
          goto swap_cleanup;
        }
        run_phase_a = false;
        run_phase_b = false;
        run_phase_c = true;
      } else if (!dest_has_src) {
        if (scratch_has_dest) {
          if (!src_has_src) {
            status = BOOT_ERR_FLASH_HW;
            goto swap_cleanup;
          }
          run_phase_a = false;
          run_phase_b = true;
          run_phase_c = true;
        } else {
          if (!dest_has_dest || !src_has_src) {
            status = BOOT_ERR_FLASH_HW;
            goto swap_cleanup;
          }
          run_phase_a = true;
          run_phase_b = true;
          run_phase_c = true;
        }
      } else {
        status = BOOT_ERR_INVALID_STATE;
        goto swap_cleanup;
      }
    }

    boot_allowed_region_t whitelist[3] = {{CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE},
                                          {CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE},
                                          {CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE}};

    flash_effect_t fx[6];
    size_t fx_cnt = 0U;
    const boot_swap_chunk_desc_t chunk_desc = {.current_src = current_src,
                                               .current_dest = current_dest,
                                               .scratch_addr = current_scratch,
                                               .block_size = (uint32_t)block_size,
                                               .crc_src = crc_src,
                                               .crc_dest = crc_dest,
                                               .run_phase_a = run_phase_a,
                                               .run_phase_b = run_phase_b,
                                               .run_phase_c = run_phase_c};

    status = boot_swap_plan_chunk_ring(platform, &chunk_desc, fx, 6U, &fx_cnt);
    if (status != BOOT_OK) {
      goto swap_cleanup;
    }

    status = boot_effect_execute(platform, fx, fx_cnt, whitelist, 3U, arena, arena_len);
    if (status != BOOT_OK) {
      goto swap_cleanup;
    }

    if (run_phase_a) {
      physical_scratch_erases +=
          (uint32_t)((block_size / scratch_sec_size > 0U) ? (block_size / scratch_sec_size) : 1U);
    }
    if (run_phase_b) {
      physical_dest_erases +=
          (uint32_t)((block_size / dest_sec_size > 0U) ? (block_size / dest_sec_size) : 1U);
    }
    if (run_phase_c) {
      physical_src_erases +=
          (uint32_t)((block_size / src_sec_size > 0U) ? (block_size / src_sec_size) : 1U);
    }

    current_offset += (uint32_t)block_size;

#if TOOB_SWAP_EVENT_STATE
    if (!notify_disabled && platform->soc && platform->soc->swap_notify) {
      toob_swap_event_t ev = {.abi_version = TOOB_SWAP_EVENT_ABI_VERSION,
                              .phase = TOOB_SWAP_PHASE_SWAPPING,
                              .sectors_done = 0U,
                              .sectors_total = 0U,
                              .flags = 0U};

#if TOOB_SWAP_EVENT_PROGRESS
      ev.sectors_total = (uint32_t)((length + standard_sec_size - 1U) / standard_sec_size);
      ev.sectors_done = (uint32_t)(current_offset / standard_sec_size);
      if (ev.sectors_done > ev.sectors_total) {
        ev.sectors_done = ev.sectors_total;
      }
#endif

      if (platform->wdt && platform->wdt->kick) {
        platform->wdt->kick();
      }
      uint32_t start_time = platform->clock->get_tick_ms();
      platform->soc->swap_notify(&ev);
      uint32_t duration = platform->clock->get_tick_ms() - start_time;
      if (platform->wdt && platform->wdt->kick) {
        platform->wdt->kick();
      }
      if (duration > NOTIFY_TIMEOUT_MS) {
        notify_disabled = true;
      }
    }
#endif
  }

  /* 4. ACCURATE TELEMETRY WRAP-UP */
  if (physical_dest_erases > 0U || physical_src_erases > 0U || physical_scratch_erases > 0U) {
    wal_tmr_payload_t tmr;
    if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
      if (dest_slot == BOOT_DEST_SLOT_APP) {
        tmr.app_slot_erase_counter += physical_dest_erases;
        tmr.staging_slot_erase_counter += physical_src_erases;
      } else {
        tmr.app_slot_erase_counter += physical_src_erases;
        tmr.staging_slot_erase_counter += physical_dest_erases;
      }
      tmr.swap_buffer_erase_counter += physical_scratch_erases;

      (void)boot_journal_update_tmr(platform, &tmr);
    }
  }

#if TOOB_SWAP_EVENT_STATE
  if (status == BOOT_OK && !notify_disabled && platform->soc && platform->soc->swap_notify) {
    toob_swap_event_t ev = {.abi_version = TOOB_SWAP_EVENT_ABI_VERSION,
                            .phase = TOOB_SWAP_PHASE_DONE,
                            .sectors_done = 0U,
                            .sectors_total = 0U,
                            .flags = 0U};

#if TOOB_SWAP_EVENT_PROGRESS
    ev.sectors_total = (uint32_t)((length + standard_sec_size - 1U) / standard_sec_size);
    ev.sectors_done = ev.sectors_total;
#endif

    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    platform->soc->swap_notify(&ev);
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
  }
#endif

swap_cleanup:
  boot_secure_zeroize(arena, arena_len);
  return status;
}

TOOB_IRAM_ATTR boot_status_t boot_swap_plan_chunk_ring(const boot_platform_t *platform,
                                                       const boot_swap_chunk_desc_t *desc,
                                                       flash_effect_t *out_fx, size_t cap,
                                                       size_t *n_out) {
  (void)platform;
  if (desc == NULL || out_fx == NULL || n_out == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  size_t count = 0U;

  if (desc->run_phase_a) {
    if (count + 2U > cap) {
      return BOOT_ERR_INVALID_ARG;
    }
    out_fx[count].op = EFF_ERASE;
    out_fx[count].src = 0U;
    out_fx[count].dst = desc->scratch_addr;
    out_fx[count].len = desc->block_size;
    out_fx[count].post_crc = boot_effect_compute_erased_crc(desc->block_size);
    count++;

    out_fx[count].op = EFF_COPY;
    out_fx[count].src = desc->current_dest;
    out_fx[count].dst = desc->scratch_addr;
    out_fx[count].len = desc->block_size;
    out_fx[count].post_crc = desc->crc_dest;
    count++;
  }

  if (desc->run_phase_b) {
    if (count + 2U > cap) {
      return BOOT_ERR_INVALID_ARG;
    }
    out_fx[count].op = EFF_ERASE;
    out_fx[count].src = 0U;
    out_fx[count].dst = desc->current_dest;
    out_fx[count].len = desc->block_size;
    out_fx[count].post_crc = boot_effect_compute_erased_crc(desc->block_size);
    count++;

    out_fx[count].op = EFF_COPY;
    out_fx[count].src = desc->current_src;
    out_fx[count].dst = desc->current_dest;
    out_fx[count].len = desc->block_size;
    out_fx[count].post_crc = desc->crc_src;
    count++;
  }

  if (desc->run_phase_c) {
    if (count + 2U > cap) {
      return BOOT_ERR_INVALID_ARG;
    }
    out_fx[count].op = EFF_ERASE;
    out_fx[count].src = 0U;
    out_fx[count].dst = desc->current_src;
    out_fx[count].len = desc->block_size;
    out_fx[count].post_crc = boot_effect_compute_erased_crc(desc->block_size);
    count++;

    out_fx[count].op = EFF_COPY;
    out_fx[count].src = desc->scratch_addr;
    out_fx[count].dst = desc->current_src;
    out_fx[count].len = desc->block_size;
    out_fx[count].post_crc = desc->crc_dest;
    count++;
  }

  *n_out = count;
  return BOOT_OK;
}

TOOB_IRAM_ATTR boot_status_t boot_swap_plan_chunk(const boot_platform_t *platform,
                                                  const boot_swap_chunk_desc_t *desc,
                                                  flash_effect_t *out_fx, size_t cap,
                                                  size_t *n_out) {
  if (desc == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  boot_swap_chunk_desc_t fixed_desc = *desc;
  fixed_desc.scratch_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
  return boot_swap_plan_chunk_ring(platform, &fixed_desc, out_fx, cap, n_out);
}

TOOB_IRAM_ATTR boot_status_t boot_copy_apply(const boot_platform_t *platform, uint32_t src_base,
                                             uint32_t dest_base, uint32_t length, uint32_t phase_id,
                                             wal_entry_payload_t *open_txn, uint8_t *arena,
                                             size_t arena_len) {
  if (!arena || arena_len < 512U) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!platform || !platform->flash || !platform->flash->read || !platform->flash->write ||
      !platform->flash->get_sector_size) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (length > UINT32_MAX - src_base || length > UINT32_MAX - dest_base) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  if (length == 0U) {
    return BOOT_OK;
  }

  if (platform->flash->write_align > 0U) {
    if ((src_base % platform->flash->write_align != 0U) ||
        (dest_base % platform->flash->write_align != 0U) ||
        (length % platform->flash->write_align != 0U)) {
      return BOOT_ERR_FLASH_ALIGN;
    }
  }

  boot_status_t eol_status = boot_swap_check_eol_survival(platform);
  if (eol_status != BOOT_OK) {
    return eol_status;
  }

  boot_allowed_region_t whitelist[3] = {{CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE},
                                        {CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE},
                                        {CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE}};

  uint32_t physical_erases = 0U;
  boot_status_t status =
      boot_swap_copy_region_resumable(platform, src_base, dest_base, length, phase_id, open_txn,
                                      whitelist, 3U, &physical_erases, arena, arena_len);

  if (status == BOOT_OK && physical_erases > 0U) {
    wal_tmr_payload_t tmr;
    if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
      if (dest_base == CHIP_APP_SLOT_ABS_ADDR) {
        tmr.app_slot_erase_counter += physical_erases;
      } else if (dest_base == CHIP_STAGING_SLOT_ABS_ADDR) {
        tmr.staging_slot_erase_counter += physical_erases;
      }
      (void)boot_journal_update_tmr(platform, &tmr);
    }
  }

  boot_secure_zeroize(arena, arena_len);
  return status;
}

#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH */

boot_status_t boot_splash_verify(const boot_platform_t *platform, uint32_t splash_addr,
                                 uint32_t max_size, uint8_t *arena, size_t arena_len) {
  if (!platform || !platform->flash || !platform->flash->read) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (max_size < sizeof(toob_splash_header_t)) {
    return BOOT_ERR_INVALID_ARG;
  }

  toob_splash_header_t header;
  boot_status_t status = platform->flash->read(splash_addr, &header, sizeof(toob_splash_header_t));
  if (status != BOOT_OK) {
    return status;
  }

  if (header.magic != 0x534C5053U) { /* 'SPLS' magic */
    return BOOT_ERR_NOT_FOUND;
  }

  if (header.data_size > max_size - sizeof(toob_splash_header_t)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  uint32_t computed_crc = 0U;
  status = boot_crc32_flash_stream(platform, splash_addr + 8U,
                                   (sizeof(toob_splash_header_t) - 8U) + header.data_size,
                                   &computed_crc, arena, arena_len);
  if (status != BOOT_OK) {
    return status;
  }

  if (computed_crc != header.crc32) {
    return BOOT_ERR_VERIFY;
  }

  return BOOT_OK;
}

#define SWAP_MAX_LOOPS 100000U

boot_status_t boot_swap_solve_block(const boot_platform_t *p, uint32_t src, uint32_t dst,
                                    uint32_t remaining, size_t *block_out) {
  size_t s_sec = 0U;
  size_t d_sec = 0U;
  if (!p || !p->flash || !p->flash->get_sector_size || !block_out) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (p->flash->get_sector_size(dst, &d_sec) != BOOT_OK || d_sec == 0U || dst % d_sec != 0U) {
    return BOOT_ERR_FLASH_HW;
  }
  if (p->flash->get_sector_size(src, &s_sec) != BOOT_OK || s_sec == 0U || src % s_sec != 0U) {
    return BOOT_ERR_FLASH_HW;
  }

  size_t block = (s_sec > d_sec) ? s_sec : d_sec;
  if (block > remaining) {
    block = remaining;
    if (p->flash->write_align > 0U) {
      uint32_t align = p->flash->write_align;
      uint32_t rem = (uint32_t)(block % align);
      if (rem != 0U) {
        block += (align - rem);
      }
    }
  }
  *block_out = block;
  return BOOT_OK;
}

boot_status_t boot_swap_blocks_identical(const boot_platform_t *p, uint32_t a, uint32_t b,
                                         size_t block, bool *out, uint8_t *arena,
                                         size_t arena_len) {
  if (!p || !p->flash || !p->flash->read || !out || !arena) {
    return BOOT_ERR_INVALID_ARG;
  }
  size_t half = (arena_len / 2U) & ~((size_t)7U);
  if (half == 0U) {
    return BOOT_ERR_INVALID_ARG;
  }

  *out = true;
  uint32_t off = 0U;
  while (off < block) {
    if (p->wdt && p->wdt->kick) {
      p->wdt->kick();
    }
    size_t step = (block - off > half) ? half : (block - off);
    if (p->flash->read(a + off, arena, step) != BOOT_OK ||
        p->flash->read(b + off, arena + half, step) != BOOT_OK) {
      *out = false;
      break;
    }
    if (constant_time_memcmp_glitch_safe(arena, arena + half, step) != BOOT_OK) {
      *out = false;
      break;
    }
    off += (uint32_t)step;
  }
  boot_secure_zeroize(arena, arena_len);
  return BOOT_OK;
}

boot_status_t boot_swap_copy_region_resumable(const boot_platform_t *p, uint32_t src_base,
                                              uint32_t dst_base, uint32_t length,
                                              uint32_t phase_magic, wal_entry_payload_t *txn,
                                              const boot_allowed_region_t *wl, uint32_t wl_n,
                                              uint32_t *erases_out, uint8_t *arena,
                                              size_t arena_len) {

  if (!p || !txn || !wl || wl_n == 0U || !arena) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint32_t offset = 0U;
  if (txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] == phase_magic) {
    offset = txn->delta_chunk_id;
    if (offset > length) {
      offset = length;
    }
  }

  uint32_t guard = 0U;
  while (offset < length) {
    if (++guard > SWAP_MAX_LOOPS) {
      return BOOT_ERR_FLASH_HW;
    }
    if (p->wdt && p->wdt->kick) {
      p->wdt->kick();
    }

    uint32_t src = src_base + offset;
    uint32_t dst = dst_base + offset;
    size_t block = 0U;
    boot_status_t status = boot_swap_solve_block(p, src, dst, length - offset, &block);
    if (status != BOOT_OK) {
      return status;
    }

    uint32_t crc_src = 0U;
    status = boot_crc32_flash_stream(p, src, block, &crc_src, arena, arena_len);
    if (status != BOOT_OK) {
      return status;
    }
#if !TOOB_TA1_STRICT_NO_CRC_SKIP
    uint32_t crc_dst = 0U;
    status = boot_crc32_flash_stream(p, dst, block, &crc_dst, arena, arena_len);
    if (status != BOOT_OK) {
      return status;
    }

    if (crc_src == crc_dst) {
      bool same = false;
      status = boot_swap_blocks_identical(p, src, dst, block, &same, arena, arena_len);
      if (status != BOOT_OK) {
        return status;
      }
      if (same) {
        offset += (uint32_t)block;
        continue;
      }
    }
#endif

    txn->delta_chunk_id = offset;
    txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = phase_magic;
    status = boot_journal_append(p, txn);
    if (status != BOOT_OK) {
      return status;
    }

    flash_effect_t fx[2];
    fx[0].op = EFF_ERASE;
    fx[0].src = 0U;
    fx[0].dst = dst;
    fx[0].len = (uint32_t)block;
    fx[0].post_crc = boot_effect_compute_erased_crc((uint32_t)block);
    fx[1].op = EFF_COPY;
    fx[1].src = src;
    fx[1].dst = dst;
    fx[1].len = (uint32_t)block;
    fx[1].post_crc = crc_src;

    status = boot_effect_execute(p, fx, 2U, wl, wl_n, arena, arena_len);
    if (status != BOOT_OK) {
      return status;
    }

    if (erases_out) {
      size_t d_sec = 0U;
      if (p->flash->get_sector_size(dst, &d_sec) == BOOT_OK && d_sec > 0U) {
        *erases_out += (uint32_t)((block + d_sec - 1U) / d_sec);
      } else {
        *erases_out += 1U;
      }
    }

    offset += (uint32_t)block;
  }

  txn->delta_chunk_id = length;
  return BOOT_OK;
}

boot_status_t boot_swap_commit_wear(const boot_platform_t *p, uint32_t app_erases,
                                    uint32_t staging_erases, uint32_t scratch_erases,
                                    uint8_t *arena, size_t arena_len) {
  (void)arena;
  (void)arena_len;
  if (app_erases == 0U && staging_erases == 0U && scratch_erases == 0U) {
    return BOOT_OK;
  }

  wal_tmr_payload_t tmr;
  boot_status_t st = boot_journal_get_tmr(p, &tmr);
  if (st != BOOT_OK) {
    return st;
  }

  tmr.app_slot_erase_counter += app_erases;
  tmr.staging_slot_erase_counter += staging_erases;
  tmr.swap_buffer_erase_counter += scratch_erases;

  return boot_journal_update_tmr(p, &tmr);
}
