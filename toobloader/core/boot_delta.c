/*
 * ==============================================================================
 * Toob-Boot Core: boot_delta.c  —  Streaming Delta VM (SDVM), rewritten
 * ==============================================================================
 *
 * Applies a TDS (Toob Delta Stream) patch by streaming instructions
 * (COPY_BASE / INSERT_LIT / BZERO / EOF) into `dest_addr`, decompressing
 * literals with heatshrink (LZSS), using only the caller-provided `arena`
 * (zero heap). Brownout-resumable via sector-aligned WAL checkpoints.
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/merkle_spec.md   (TDS streaming format)
 * - docs/concept_fusion.md (zero-allocation, brownout-resume)
 *
 * ------------------------------------------------------------------------------
 * WHAT CHANGED VS THE PREVIOUS REVISION (and why)
 * ------------------------------------------------------------------------------
 * K1 [correctness] Checkpoints are now ALWAYS sector-aligned. The previous code
 *     logged `flushed_offset` (a multiple of the window size) as the checkpoint;
 *     since the window size rarely divides the sector size, the resume
 *     fast-forward (`curr != checkpoint -> BOOT_ERR_INVALID_STATE`) failed for
 *     realistic arena sizes, i.e. delta resume was effectively broken. We now
 *     track `committed_off`, the high-water mark of FULLY-written sectors, and
 *     checkpoint there. Verified by model: with a window that does not divide
 *     the sector, every checkpoint still lands on a sector boundary, and resume
 *     from any checkpoint reproduces the exact image.
 *
 * K2 [correctness] The heatshrink decoder is no longer clobbered. Ghost-base
 *     hashing reads the base image into the WRITE-BUFFER region (never the hsd
 *     region), and the decoder is reset immediately before the execution loop.
 *     The previous code hashed base bytes into arena[0] — where hsd lives — then
 *     zeroed the arena and entered the loop without re-resetting, working only
 *     by the accident that a zeroed heatshrink decoder happens to equal a reset
 *     one.
 *
 * OPT [wear/speed/RAM] The read buffer is sized to the heatshrink input buffer
 *     (a few dozen bytes) instead of half the arena; the remainder goes to the
 *     write buffer. This ~doubles the write-combiner window on typical arenas,
 *     roughly halving the number of flushes, erases-checks, flash writes and
 *     read-backs.
 *
 * OPT [wear/speed] The "is this destination sector already erased?" scan now
 *     early-exits on the first non-erased byte. Constant-time full-scan was
 *     misapplied here: the destination content is prior firmware, not a secret,
 *     and a mis-decision is caught by the mandatory read-back verify anyway.
 *
 * STRUCT [size/clarity] Shared mutable state lives in one `sdvm_t` context; the
 *     three near-duplicate poll/flush blocks are unified into `drain_decoder()`
 *     and `emit_flush()`. Read-back verify uses a 256-byte window (was 64).
 *
 * SECURITY PROPERTIES PRESERVED: header + per-instruction CRC-32, CFI tokens,
 *     glitch-shielded verify/crypto decisions, subtractive overflow guards,
 *     zip-bomb bounds, ghost-base anti-brick, phase-bound read-back, and
 *     single-exit arena zeroization.
 *
 * NOTE: offset/flush/checkpoint/resume logic was validated against a reference
 *     model (fresh apply, resume from every checkpoint, brownout after every
 *     flush). The heatshrink and HAL interactions still require on-hardware
 *     testing.
 * ==============================================================================
 */

#include "boot_delta.h"
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "heatshrink_decoder.h"
#include <stddef.h>
#include <string.h>

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 1024,
               "Crypto Arena must be at least 1KB for the SDVM");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK MUST be high-hamming distance for glitch shielding");

/* CFI token slots (randomized per boot via TRNG). */
#define DELTA_CFI_SLOT_HDR  1
#define DELTA_CFI_SLOT_BASE 2
#define DELTA_CFI_SLOT_EOF  3

/* Read-back verify window (stack). Larger than the old 64 B -> fewer read ops. */
#define RB_WINDOW 256u

/* ==========================================================================
 * SDVM CONTEXT
 *
 * Invariant maintained throughout execution:
 *     the write buffer holds the contiguous logical run
 *         [ target_off - write_pos , target_off )
 *     and                              logical(write_buf[0]) = target_off - write_pos.
 * `target_off`   = total logical output PRODUCED (incl. dry-run replay).
 * `flushed_off`  = logical output actually written to flash.
 * `committed_off`= sector-aligned high-water of fully-written output (<= flushed_off).
 * ========================================================================== */
typedef struct {
  const boot_platform_t *platform;

  uint32_t dest_addr;   /* absolute base of the output slot */
  uint32_t base_addr;   /* absolute base of the source (base) image */
  uint32_t delta_addr;  /* absolute base of the delta stream */
  uint32_t base_size;
  uint32_t expected_target_size;

  uint8_t *write_buf;   uint32_t write_cap; uint32_t write_pos;
  uint8_t *read_buf;    uint32_t read_cap;
  heatshrink_decoder *hsd;

  uint32_t target_off;
  uint32_t flushed_off;
  uint32_t committed_off;
  uint32_t checkpoint_off;
  uint32_t erased_end;  /* absolute; sectors [dest_addr, erased_end) are erased */

  wal_entry_payload_t *txn;
} sdvm_t;

/* ==========================================================================
 * FLASH HELPERS
 * ========================================================================== */

/* Early-exit erased check. Not constant-time on purpose: the scanned bytes are
 * prior firmware, not a secret, and a wrong verdict is caught by read-back. */
static bool region_is_erased(const boot_platform_t *p, uint32_t addr, size_t len,
                             uint8_t *scratch, size_t scratch_len) {
  const uint8_t ev = p->flash->erased_value;
  size_t off = 0;
  while (off < len) {
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();
    size_t step = (len - off > scratch_len) ? scratch_len : (len - off);
    if (p->flash->read(addr + off, scratch, step) != BOOT_OK)
      return false; /* read failure -> treat as needs-erase */
    for (size_t i = 0; i < step; i++) {
      if (scratch[i] != ev)
        return false;
    }
    off += step;
  }
  return true;
}

/* Erase destination sectors just-in-time until they cover `write_end`.
 * Each sector is visited (and at most erased) exactly once across the whole
 * apply, because `erased_end` only ever advances. */
static boot_status_t erase_ahead(sdvm_t *s, uint32_t write_end) {
  const boot_platform_t *p = s->platform;
  uint8_t scratch[64] __attribute__((aligned(8)));

  while (s->erased_end < write_end) {
    size_t sec = 0;
    if (p->flash->get_sector_size(s->erased_end, &sec) != BOOT_OK || sec == 0)
      return BOOT_ERR_FLASH_HW;

    if (!region_is_erased(p, s->erased_end, sec, scratch, sizeof(scratch))) {
      const bool big = (sec >= CHIP_FLASH_MAX_SECTOR_SIZE);
      if (big && p->wdt && p->wdt->suspend_for_critical_section)
        p->wdt->suspend_for_critical_section();
      else if (p->wdt && p->wdt->kick)
        p->wdt->kick();

      boot_status_t er = p->flash->erase_sector(s->erased_end);

      if (big && p->wdt && p->wdt->resume)
        p->wdt->resume();
      else if (p->wdt && p->wdt->kick)
        p->wdt->kick();

      if (er != BOOT_OK)
        return er;
    }

    if (UINT32_MAX - s->erased_end < (uint32_t)sec)
      return BOOT_ERR_FLASH_BOUNDS;
    s->erased_end += (uint32_t)sec;
  }
  return BOOT_OK;
}

/* Phase-bound read-back verify (tearing / bit-rot). Zeroize-before-read makes a
 * "ghost match" impossible; comparison is glitch-safe. */
static boot_status_t verify_readback(const boot_platform_t *p, uint32_t addr,
                                     const uint8_t *expect, uint32_t len) {
  uint8_t rb[RB_WINDOW] __attribute__((aligned(8)));
  uint32_t off = 0;
  while (off < len) {
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();
    uint32_t step = (len - off > RB_WINDOW) ? RB_WINDOW : (len - off);
    boot_secure_zeroize(rb, step);
    if (p->flash->read(addr + off, rb, step) != BOOT_OK) {
      boot_secure_zeroize(rb, sizeof(rb));
      return BOOT_ERR_FLASH_HW;
    }
    BOOT_SECURE_REQUIRE(
        constant_time_memcmp_glitch_safe(rb, expect + off, step) == BOOT_OK, {
          boot_secure_zeroize(rb, sizeof(rb));
          return BOOT_ERR_FLASH_HW;
        });
    off += step;
  }
  boot_secure_zeroize(rb, sizeof(rb));
  return BOOT_OK;
}

/* ==========================================================================
 * WRITE-COMBINER FLUSH  (erase-ahead -> write -> verify -> commit -> checkpoint)
 *
 * Writes only the not-yet-flushed portion of the buffer (`valid_off` skips the
 * replayed prefix during resume), then advances the sector-aligned commit
 * high-water and, throttled, logs a sector-aligned WAL checkpoint.
 * ========================================================================== */
static boot_status_t emit_flush(sdvm_t *s, bool pad_final) {
  const boot_platform_t *p = s->platform;
  if (s->write_pos == 0)
    return BOOT_OK;

  const uint32_t logical_start = s->target_off - s->write_pos;

  /* Entire buffer lies in the already-flushed (replayed) region -> discard. */
  if (logical_start + s->write_pos <= s->flushed_off) {
    s->write_pos = 0;
    return BOOT_OK;
  }

  uint32_t valid_off = (logical_start < s->flushed_off)
                           ? (s->flushed_off - logical_start)
                           : 0u;
  uint32_t write_len = s->write_pos - valid_off;

  /* Final tail: pad up to the flash write alignment with the erased value. */
  if (pad_final && p->flash->write_align > 0) {
    uint32_t align = p->flash->write_align;
    uint32_t rem = write_len % align;
    if (rem != 0) {
      uint32_t pad = align - rem;
      if ((uint64_t)valid_off + write_len + pad > s->write_cap)
        return BOOT_ERR_FLASH_BOUNDS;
      memset(s->write_buf + valid_off + write_len, p->flash->erased_value, pad);
      write_len += pad;
    }
  }

  if (UINT32_MAX - s->dest_addr < s->flushed_off)
    return BOOT_ERR_FLASH_BOUNDS;
  const uint32_t dest = s->dest_addr + s->flushed_off;
  if (UINT32_MAX - dest < write_len)
    return BOOT_ERR_FLASH_BOUNDS;

  boot_status_t st = erase_ahead(s, dest + write_len);
  if (st != BOOT_OK)
    return st;

  if (p->wdt && p->wdt->kick)
    p->wdt->kick();
  if (p->flash->write(dest, s->write_buf + valid_off, write_len) != BOOT_OK)
    return BOOT_ERR_FLASH_HW;

  st = verify_readback(p, dest, s->write_buf + valid_off, write_len);
  if (st != BOOT_OK)
    return st;

  s->flushed_off += write_len;
  s->write_pos = 0;

  /* Advance the sector-aligned commit high-water over newly-complete sectors. */
  for (;;) {
    size_t sec = 0;
    if (p->flash->get_sector_size(s->dest_addr + s->committed_off, &sec) !=
            BOOT_OK ||
        sec == 0)
      return BOOT_ERR_FLASH_HW;
    if (s->committed_off + (uint32_t)sec > s->flushed_off)
      break;
    s->committed_off += (uint32_t)sec;
  }

  /* Throttled checkpoint — always sector-aligned (== committed_off), so the
   * resume fast-forward walks sectors and lands on it exactly. */
  if (s->committed_off - s->checkpoint_off >= CHIP_FLASH_MAX_SECTOR_SIZE) {
    s->txn->delta_chunk_id = s->committed_off;
    boot_status_t log = boot_journal_append(p, s->txn);
    if (log != BOOT_OK)
      return log;
    s->checkpoint_off = s->committed_off;
  }
  return BOOT_OK;
}

/* ==========================================================================
 * PRODUCERS
 * ========================================================================== */

/* COPY_BASE / BZERO. During resume replay (dry region), output is regenerable
 * and deterministic, so we skip it (no base read, no write) after emptying the
 * buffer to keep the buffer-contiguity invariant intact. */
static boot_status_t produce_copy_or_zero(sdvm_t *s, uint32_t opcode,
                                          uint32_t length, uint32_t src_off) {
  const boot_platform_t *p = s->platform;
  uint32_t rem = length;

  while (rem > 0) {
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();

    if (s->target_off < s->flushed_off) {
      /* Dry replay: cap to the boundary, empty the buffer, then skip. */
      uint32_t step = rem;
      if (s->target_off + step > s->flushed_off)
        step = s->flushed_off - s->target_off;
      boot_status_t st = emit_flush(s, false);
      if (st != BOOT_OK)
        return st;
      s->target_off += step;
      rem -= step;
    } else {
      uint32_t space = s->write_cap - s->write_pos;
      uint32_t step = (rem < space) ? rem : space;

      if (opcode == TOOB_TDS_OP_BZERO) {
        memset(s->write_buf + s->write_pos, 0x00, step);
      } else { /* TOOB_TDS_OP_COPY_BASE */
        uint32_t soff = src_off + (length - rem);
        if (UINT32_MAX - soff < step || soff + step > s->base_size)
          return BOOT_ERR_FLASH_BOUNDS;
        if (p->flash->read(s->base_addr + soff, s->write_buf + s->write_pos,
                           step) != BOOT_OK)
          return BOOT_ERR_FLASH_HW;
      }

      s->write_pos += step;
      s->target_off += step;
      rem -= step;

      if (s->write_pos == s->write_cap) {
        boot_status_t st = emit_flush(s, false);
        if (st != BOOT_OK)
          return st;
      }
    }
  }
  return BOOT_OK;
}

/* Poll the decoder until it is drained, flushing whenever the window fills. */
static boot_status_t drain_decoder(sdvm_t *s) {
  const boot_platform_t *p = s->platform;
  for (;;) {
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();

    uint32_t space = s->write_cap - s->write_pos;
    if (space == 0) {
      boot_status_t st = emit_flush(s, false);
      if (st != BOOT_OK)
        return st;
      space = s->write_cap;
    }

    size_t polled = 0;
    HSD_poll_res pres =
        heatshrink_decoder_poll(s->hsd, s->write_buf + s->write_pos, space, &polled);
    if (pres < 0)
      return BOOT_ERR_VERIFY;

    s->write_pos += (uint32_t)polled;
    s->target_off += (uint32_t)polled;

    /* Zip-bomb guard: a literal run may not exceed the declared target. */
    if (s->target_off > s->expected_target_size)
      return BOOT_ERR_INVALID_STATE;

    if (pres == HSDR_POLL_EMPTY)
      return BOOT_OK;
  }
}

/* INSERT_LIT: stream `compressed_len` bytes from the delta literal block through
 * the decoder. Runs identically on fresh apply and resume replay (the decoder
 * state must be rebuilt on resume); the flush suppresses already-written bytes. */
static boot_status_t produce_insert(sdvm_t *s, uint32_t compressed_len,
                                    uint32_t *lit_read_off,
                                    uint32_t delta_max_size) {
  const boot_platform_t *p = s->platform;
  uint32_t rem = compressed_len;

  while (rem > 0) {
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();

    uint32_t max_sink = (uint32_t)HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(s->hsd);
    uint32_t chunk = (rem < max_sink) ? rem : max_sink;
    if (chunk > s->read_cap)
      chunk = s->read_cap;

    if (UINT32_MAX - *lit_read_off < chunk ||
        *lit_read_off + chunk > delta_max_size)
      return BOOT_ERR_FLASH_BOUNDS;

    if (p->flash->read(s->delta_addr + *lit_read_off, s->read_buf, chunk) !=
        BOOT_OK)
      return BOOT_ERR_FLASH_HW;

    size_t sunk = 0;
    if (heatshrink_decoder_sink(s->hsd, s->read_buf, chunk, &sunk) < 0)
      return BOOT_ERR_VERIFY;
    if (sunk == 0)
      return BOOT_ERR_INVALID_STATE; /* no forward progress -> abort */

    boot_status_t st = drain_decoder(s);
    if (st != BOOT_OK)
      return st;

    *lit_read_off += (uint32_t)sunk;
    rem -= (uint32_t)sunk;
  }
  return BOOT_OK;
}

/* ==========================================================================
 * GHOST-BASE VERIFICATION  (anti-brick: refuse to patch the wrong base image)
 * Hashes into the write-buffer region so the decoder state is never touched.
 * ========================================================================== */
static boot_status_t verify_ghost_base(sdvm_t *s, const uint8_t *fingerprint) {
  const boot_platform_t *p = s->platform;

  uint64_t hash_ctx[32] __attribute__((aligned(8)));
  uint8_t computed[32] __attribute__((aligned(8)));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(computed, sizeof(computed));

  if (p->crypto->hash_init(hash_ctx, sizeof(hash_ctx)) != BOOT_OK)
    return BOOT_ERR_CRYPTO;

  uint32_t hashed = 0;
  while (hashed < s->base_size) {
    if (p->wdt && p->wdt->kick)
      p->wdt->kick();
    uint32_t step = (s->base_size - hashed > s->write_cap)
                        ? s->write_cap
                        : (s->base_size - hashed);
    if (p->flash->read(s->base_addr + hashed, s->write_buf, step) != BOOT_OK)
      return BOOT_ERR_FLASH_HW;
    if (p->crypto->hash_update(hash_ctx, s->write_buf, step) != BOOT_OK)
      return BOOT_ERR_CRYPTO;
    hashed += step;
  }
  boot_secure_zeroize(s->write_buf, s->write_cap);

  size_t dlen = sizeof(computed);
  if (p->crypto->hash_finish(hash_ctx, computed, &dlen) != BOOT_OK) {
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    return BOOT_ERR_CRYPTO;
  }
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

  /* 8-byte truncated fingerprint, glitch-safe compare. */
  boot_status_t match =
      constant_time_memcmp_glitch_safe(computed, fingerprint, 8);
  boot_secure_zeroize(computed, sizeof(computed));
  return (match == BOOT_OK) ? BOOT_OK : BOOT_ERR_DOWNGRADE;
}

/* ==========================================================================
 * PUBLIC ENTRY POINT
 * ========================================================================== */
boot_status_t boot_delta_apply(const boot_platform_t *platform,
                               uint32_t delta_addr, size_t delta_max_size,
                               uint32_t dest_addr, size_t dest_max_size,
                               uint32_t base_addr, size_t base_max_size,
                               wal_entry_payload_t *open_txn, uint8_t *arena,
                               size_t arena_len) {
  if (!arena || arena_len < 1024)
    return BOOT_ERR_INVALID_ARG;
  if (!platform || !platform->flash || !platform->crypto || !platform->wdt ||
      !open_txn)
    return BOOT_ERR_INVALID_ARG;
  if (!platform->flash->read || !platform->flash->write ||
      !platform->flash->erase_sector || !platform->flash->get_sector_size)
    return BOOT_ERR_INVALID_ARG;
  if (delta_max_size < sizeof(toob_tds_header_t) + sizeof(toob_tds_instr_t))
    return BOOT_ERR_VERIFY;

  boot_status_t status = BOOT_OK;

  /* ---- CFI ---- */
  uint32_t cfi_seed = 0;
  boot_random_safe(platform, (uint8_t *)&cfi_seed, sizeof(cfi_seed));
  boot_cfi_ctx_t cfi;
  boot_cfi_init(cfi, cfi_seed);
  boot_cfi_add_expected(cfi, DELTA_CFI_SLOT_HDR);
  boot_cfi_add_expected(cfi, DELTA_CFI_SLOT_BASE);
  boot_cfi_add_expected(cfi, DELTA_CFI_SLOT_EOF);

  /* ---- Arena layout:  [ hsd | read_buf | write_buf ] ---- */
  size_t hsd_size = (sizeof(heatshrink_decoder) + 7u) & ~((size_t)7);
  if (hsd_size + 8u >= arena_len)
    return BOOT_ERR_INVALID_STATE;

  heatshrink_decoder *hsd = (heatshrink_decoder *)arena;

  boot_secure_zeroize(arena, arena_len);
  heatshrink_decoder_reset(hsd);

  uint32_t read_cap =
      (uint32_t)(((size_t)HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(hsd) + 7u) &
                 ~((size_t)7));
  if (read_cap == 0)
    read_cap = 8u;

  if (hsd_size + read_cap + 8u >= arena_len)
    return BOOT_ERR_INVALID_STATE;

  uint8_t *read_buf = arena + hsd_size;
  uint8_t *write_buf = arena + hsd_size + read_cap;
  uint32_t write_cap = (uint32_t)(arena_len - hsd_size - read_cap);
  write_cap &= ~7u; /* 8-byte aligned window for SPI/DMA */
  if (write_cap < 8u) {
    status = BOOT_ERR_INVALID_STATE;
    goto cleanup;
  }

  /* ---- STEP 1: parse & verify TDS header ---- */
  toob_tds_header_t hdr __attribute__((aligned(8)));
  boot_secure_zeroize(&hdr, sizeof(hdr));
  if (platform->flash->read(delta_addr, (uint8_t *)&hdr, sizeof(hdr)) != BOOT_OK) {
    status = BOOT_ERR_FLASH_HW;
    goto cleanup;
  }

  {
    size_t crc_len = offsetof(toob_tds_header_t, header_crc32);
    uint32_t calc = compute_boot_crc32((const uint8_t *)&hdr, crc_len);
    bool ok = (hdr.magic == TOOB_TDS_MAGIC && calc == hdr.header_crc32);
    BOOT_SECURE_REQUIRE(ok, {
      status = BOOT_ERR_VERIFY;
      goto cleanup;
    });
  }

  if (hdr.expected_target_size == 0 ||
      hdr.expected_target_size > dest_max_size ||
      hdr.base_size > base_max_size) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto cleanup;
  }

  {
    uint32_t instr_bytes = hdr.instr_count * (uint32_t)sizeof(toob_tds_instr_t);
    if (hdr.instr_count != 0 &&
        instr_bytes / hdr.instr_count != (uint32_t)sizeof(toob_tds_instr_t)) {
      status = BOOT_ERR_INVALID_ARG; /* multiply overflow */
      goto cleanup;
    }
    if (UINT32_MAX - (uint32_t)sizeof(toob_tds_header_t) < instr_bytes) {
      status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }
    uint32_t expect_lit = (uint32_t)sizeof(toob_tds_header_t) + instr_bytes;
    /* Pin the literal block exactly after the instruction array -> no
     * attacker-chosen offset -> no arbitrary flash read. */
    if (hdr.literal_block_offset != expect_lit) {
      status = BOOT_ERR_VERIFY;
      goto cleanup;
    }
    if (expect_lit > delta_max_size) {
      status = BOOT_ERR_FLASH_BOUNDS;
      goto cleanup;
    }
  }

  boot_cfi_step(cfi, DELTA_CFI_SLOT_HDR);

  /* ---- STEP 2: resume checkpoint + ghost-base (skipped on resume) ---- */
  uint32_t checkpoint = 0;
  if (open_txn->intent == WAL_INTENT_UPDATE_PENDING ||
      open_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
    checkpoint = open_txn->delta_chunk_id;
    if (checkpoint > hdr.expected_target_size)
      checkpoint = hdr.expected_target_size;
  }

  sdvm_t s;
  boot_secure_zeroize(&s, sizeof(s));
  s.platform = platform;
  s.dest_addr = dest_addr;
  s.base_addr = base_addr;
  s.delta_addr = delta_addr;
  s.base_size = hdr.base_size;
  s.expected_target_size = hdr.expected_target_size;
  s.write_buf = write_buf;
  s.write_cap = write_cap;
  s.read_buf = read_buf;
  s.read_cap = read_cap;
  s.hsd = hsd;
  s.txn = open_txn;
  s.erased_end = dest_addr;

  if (checkpoint == 0) {
    status = verify_ghost_base(&s, hdr.base_fingerprint);
    if (status != BOOT_OK)
      goto cleanup;
  } else {
    /* Resume: base already verified in the prior run; fast-forward the write
     * frontier. `checkpoint` is sector-aligned by construction (K1), so the
     * sector walk lands on it exactly. */
    s.flushed_off = checkpoint;
    s.committed_off = checkpoint;
    s.checkpoint_off = checkpoint;
    uint32_t curr = 0;
    while (curr < checkpoint) {
      size_t sec = 0;
      if (platform->flash->get_sector_size(dest_addr + curr, &sec) != BOOT_OK ||
          sec == 0) {
        status = BOOT_ERR_FLASH_HW;
        goto cleanup;
      }
      if (UINT32_MAX - curr < (uint32_t)sec) {
        status = BOOT_ERR_FLASH_BOUNDS;
        goto cleanup;
      }
      curr += (uint32_t)sec;
    }
    if (curr != checkpoint) {
      status = BOOT_ERR_INVALID_STATE; /* checkpoint not sector-aligned */
      goto cleanup;
    }
    s.erased_end = dest_addr + checkpoint;
  }

  boot_cfi_step(cfi, DELTA_CFI_SLOT_BASE);

  /* ---- STEP 3: reset the decoder immediately before use (K2) ---- */
  heatshrink_decoder_reset(hsd);

  /* ---- STEP 4: streaming VM execution ---- */
  uint32_t delta_read_off = (uint32_t)sizeof(toob_tds_header_t);
  uint32_t lit_read_off = hdr.literal_block_offset;
  uint32_t inst_idx = 0;
  bool eof_reached = false;

  const uint32_t MAX_INSTRUCTIONS = 1000000u;
  uint32_t guard = 0;

  while (!eof_reached) {
    if (++guard > MAX_INSTRUCTIONS) {
      status = BOOT_ERR_INVALID_STATE;
      goto cleanup;
    }
    if (inst_idx >= hdr.instr_count) {
      status = BOOT_ERR_VERIFY; /* ran out of instructions before EOF */
      goto cleanup;
    }
    if (UINT32_MAX - delta_read_off < (uint32_t)sizeof(toob_tds_instr_t) ||
        delta_read_off + sizeof(toob_tds_instr_t) > delta_max_size) {
      status = BOOT_ERR_INVALID_ARG; /* stream truncated */
      goto cleanup;
    }

    toob_tds_instr_t inst __attribute__((aligned(8)));
    boot_secure_zeroize(&inst, sizeof(inst));
    if (platform->flash->read(delta_addr + delta_read_off, (uint8_t *)&inst,
                              sizeof(inst)) != BOOT_OK) {
      status = BOOT_ERR_FLASH_HW;
      goto cleanup;
    }

    uint32_t icrc =
        compute_boot_crc32((const uint8_t *)&inst, offsetof(toob_tds_instr_t, crc32));
    BOOT_SECURE_REQUIRE(icrc == inst.crc32, {
      status = BOOT_ERR_VERIFY; /* instruction corrupted */
      goto cleanup;
    });

    const uint32_t opcode = inst.opcode;
    const uint32_t length = inst.length;
    const uint32_t src_off = inst.offset;

    if (opcode == TOOB_TDS_OP_EOF) {
      eof_reached = true;
      break;
    }

    delta_read_off += (uint32_t)sizeof(toob_tds_instr_t);
    inst_idx++;

    switch (opcode) {
    case TOOB_TDS_OP_COPY_BASE:
    case TOOB_TDS_OP_BZERO:
      /* Zip-bomb guard for deterministic opcodes (INSERT is bounded in drain). */
      if (UINT32_MAX - s.target_off < length ||
          s.target_off + length > hdr.expected_target_size) {
        status = BOOT_ERR_FLASH_BOUNDS;
        goto cleanup;
      }
      status = produce_copy_or_zero(&s, opcode, length, src_off);
      break;

    case TOOB_TDS_OP_INSERT_LIT:
      status = produce_insert(&s, length, &lit_read_off, (uint32_t)delta_max_size);
      break;

    default:
      status = BOOT_ERR_VERIFY; /* unknown opcode */
      break;
    }
    if (status != BOOT_OK)
      goto cleanup;

    /* Flush at the exact target end so the final (padded) write happens once. */
    if (s.target_off == hdr.expected_target_size && s.write_pos > 0) {
      status = emit_flush(&s, true);
      if (status != BOOT_OK)
        goto cleanup;
    }
  }

  /* ---- EOF: drain any decoder tail, then final flush ---- */
  heatshrink_decoder_finish(hsd);
  status = drain_decoder(&s);
  if (status != BOOT_OK)
    goto cleanup;
  status = emit_flush(&s, true);
  if (status != BOOT_OK)
    goto cleanup;

  /* ---- STEP 5: final integrity resolution (anti-truncation) ---- */
  BOOT_SECURE_REQUIRE(eof_reached &&
                          s.target_off == hdr.expected_target_size, {
    status = BOOT_ERR_VERIFY;
    goto cleanup;
  });

  boot_cfi_step(cfi, DELTA_CFI_SLOT_EOF);
  boot_cfi_require(cfi, {
    status = BOOT_ERR_INVALID_STATE; /* control-flow glitch trapped */
    goto cleanup;
  });

  open_txn->delta_chunk_id = s.target_off;
  status = BOOT_OK;

cleanup:
  /* Single-exit: destroy any firmware fragments / crypto residue in the arena. */
  boot_secure_zeroize(arena, arena_len);
  return status;
}