/*
 * ==============================================================================
 * Toob-Boot Core: boot_delta.c  —  Streaming Delta VM (SDVM)
 * ==============================================================================
 *
 * Applies a TDS (Toob Delta Stream) patch by streaming instructions
 * (COPY_BASE / INSERT_LIT / BZERO / EOF) into `dest_addr`, decompressing
 * literals with heatshrink (LZSS), using only the caller-provided `arena`
 * (zero heap). Brownout-resumable via sector-aligned WAL checkpoints and
 * shared `boot_stream_writer_t` write-alignment buffering (ARCH-T02, MED-09).
 */

#include "boot_delta.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_features.h"
#include "boot_fih.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "boot_slot_transport.h"
#include "boot_stream_writer.h"
#include "generated_boot_config.h"
#include "heatshrink_decoder.h"
#include <stddef.h>
#include <string.h>

#if TOOB_FEATURE_DELTA

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 1024, "Crypto Arena must be at least 1KB for the SDVM");
_Static_assert(BOOT_OK == 0x55AA55AA, "BOOT_OK MUST be high-hamming distance for glitch shielding");

/* CFI token slots (randomized per boot via TRNG). */
#define DELTA_CFI_SLOT_HDR 1
#define DELTA_CFI_SLOT_BASE 2
#define DELTA_CFI_SLOT_EOF 3

typedef struct {
  boot_stream_writer_t writer;
  uint32_t base_addr;
  uint32_t delta_addr;
  uint32_t base_size;
  uint8_t *read_buf;
  uint32_t read_cap;
  heatshrink_decoder *hsd;
} sdvm_t;

/* COPY_BASE / BZERO. During resume replay (dry region), output is regenerable
 * and deterministic, so we skip it after emptying the buffer. */
static boot_status_t produce_copy_or_zero(sdvm_t *s, uint32_t opcode, uint32_t length,
                                          uint32_t src_off) {
  boot_stream_writer_t *w = &s->writer;
  const boot_platform_t *p = w->platform;
  uint32_t rem = length;

  while (rem > 0U) {
    if (p->wdt && p->wdt->kick) {
      p->wdt->kick();
    }

    if (w->target_off < w->flushed_off) {
      uint32_t step = rem;
      if (w->target_off + step > w->flushed_off) {
        step = w->flushed_off - w->target_off;
      }
      boot_status_t st = boot_stream_writer_flush(w, false);
      if (st != BOOT_OK) {
        return st;
      }
      w->target_off += step;
      rem -= step;
    } else {
      uint32_t space = w->write_cap - w->write_pos;
      uint32_t step = (rem < space) ? rem : space;

      if (opcode == TOOB_TDS_OP_BZERO) {
        memset(w->write_buf + w->write_pos, 0x00, step);
      } else {
        uint32_t soff = src_off + (length - rem);
        if (UINT32_MAX - soff < step || soff + step > s->base_size) {
          return BOOT_ERR_FLASH_BOUNDS;
        }
        if (p->flash->read(s->base_addr + soff, w->write_buf + w->write_pos, step) != BOOT_OK) {
          return BOOT_ERR_FLASH_HW;
        }
      }

      w->write_pos += step;
      w->target_off += step;
      rem -= step;

      if (w->write_pos == w->write_cap) {
        boot_status_t st = boot_stream_writer_flush(w, false);
        if (st != BOOT_OK) {
          return st;
        }
      }
    }
  }
  return BOOT_OK;
}

static boot_status_t produce_insert(sdvm_t *s, uint32_t compressed_len, uint32_t declared_len,
                                    uint32_t *lit_read_off, uint32_t delta_max_size) {
  boot_stream_writer_t *w = &s->writer;
  const boot_platform_t *p = w->platform;
  uint32_t rem = compressed_len;

  if (declared_len > 0U) {
    if (UINT32_MAX - w->target_off < declared_len ||
        w->target_off + declared_len > w->expected_target_size) {
      return BOOT_ERR_FLASH_BOUNDS;
    }
  }

  uint32_t start_target_off = w->target_off;
  heatshrink_decoder_reset(s->hsd);

  while (rem > 0U) {
    if (p->wdt && p->wdt->kick) {
      p->wdt->kick();
    }

    uint32_t max_sink = (uint32_t)HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(s->hsd);
    uint32_t chunk = (rem < max_sink) ? rem : max_sink;
    if (chunk > s->read_cap) {
      chunk = s->read_cap;
    }

    if (UINT32_MAX - *lit_read_off < chunk || *lit_read_off + chunk > delta_max_size) {
      return BOOT_ERR_FLASH_BOUNDS;
    }

    if (p->flash->read(s->delta_addr + *lit_read_off, s->read_buf, chunk) != BOOT_OK) {
      return BOOT_ERR_FLASH_HW;
    }

    size_t sunk = 0U;
    if (heatshrink_decoder_sink(s->hsd, s->read_buf, chunk, &sunk) < 0) {
      return BOOT_ERR_VERIFY;
    }
    if (sunk == 0U) {
      return BOOT_ERR_INVALID_STATE;
    }

    boot_status_t st = boot_stream_writer_drain_hsd(w, s->hsd);
    if (st != BOOT_OK) {
      return st;
    }

    *lit_read_off += (uint32_t)sunk;
    rem -= (uint32_t)sunk;
  }

  heatshrink_decoder_finish(s->hsd);
  boot_status_t st = boot_stream_writer_drain_hsd(w, s->hsd);
  if (st != BOOT_OK) {
    return st;
  }

  if (w->target_off <= w->flushed_off) {
    w->write_pos = 0U;
  }

  if (declared_len > 0U) {
    uint32_t produced = w->target_off - start_target_off;
    if (produced != declared_len) {
      return BOOT_ERR_VERIFY;
    }
  }
  return BOOT_OK;
}

/* Ghost-base verification (hashes into write_buf so decoder state is untouched) */
static boot_status_t verify_ghost_base(sdvm_t *s, const uint8_t *fingerprint) {
  boot_stream_writer_t *w = &s->writer;
  const boot_platform_t *p = w->platform;

  if (!p->crypto->hash_init || !p->crypto->hash_update || !p->crypto->hash_finish) {
    return BOOT_ERR_CRYPTO;
  }

  uint64_t hash_ctx[32] __attribute__((aligned(8)));
  uint8_t computed[32] __attribute__((aligned(8)));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(computed, sizeof(computed));

  size_t ctx_sz = sizeof(hash_ctx);
  if (p->crypto->get_hash_ctx_size != NULL) {
    size_t req = p->crypto->get_hash_ctx_size();
    if (req == 0U || req > sizeof(hash_ctx)) {
      return BOOT_ERR_CRYPTO;
    }
    ctx_sz = req;
  }

  if (p->crypto->hash_init(hash_ctx, ctx_sz) != BOOT_OK) {
    return BOOT_ERR_CRYPTO;
  }

  uint32_t hashed = 0U;
  while (hashed < s->base_size) {
    if (p->wdt && p->wdt->kick) {
      p->wdt->kick();
    }
    uint32_t step = (s->base_size - hashed > w->write_cap) ? w->write_cap : (s->base_size - hashed);
    if (p->flash->read(s->base_addr + hashed, w->write_buf, step) != BOOT_OK) {
      return BOOT_ERR_FLASH_HW;
    }
    if (p->crypto->hash_update(hash_ctx, w->write_buf, step) != BOOT_OK) {
      return BOOT_ERR_CRYPTO;
    }
    hashed += step;
  }
  boot_secure_zeroize(w->write_buf, w->write_cap);

  size_t dlen = sizeof(computed);
  if (p->crypto->hash_finish(hash_ctx, computed, &dlen) != BOOT_OK) {
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    return BOOT_ERR_CRYPTO;
  }
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

  boot_status_t match = constant_time_memcmp_glitch_safe(computed, fingerprint, 8U);
  boot_secure_zeroize(computed, sizeof(computed));
  return (match == BOOT_OK) ? BOOT_OK : BOOT_ERR_DOWNGRADE;
}

boot_status_t boot_delta_apply(const boot_platform_t *platform, uint32_t delta_addr,
                               size_t delta_max_size, uint32_t dest_addr, size_t dest_max_size,
                               uint32_t base_addr, size_t base_max_size,
                               wal_entry_payload_t *open_txn, uint8_t *arena, size_t arena_len) {
  if (!arena || arena_len < 1024U) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!platform || !platform->flash || !platform->crypto || !platform->wdt || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!platform->flash->read || !platform->flash->write || !platform->flash->erase_sector ||
      !platform->flash->get_sector_size) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (delta_max_size < sizeof(toob_tds_header_t) + sizeof(toob_tds_instr_t)) {
    return BOOT_ERR_VERIFY;
  }

  boot_status_t status = BOOT_OK;

  uint32_t cfi_seed = 0U;
  (void)boot_random_safe(platform, (uint8_t *)&cfi_seed, sizeof(cfi_seed));
  boot_cfi_ctx_t cfi;
  boot_cfi_init(cfi, cfi_seed);
  boot_cfi_add_expected(cfi, DELTA_CFI_SLOT_HDR);
  boot_cfi_add_expected(cfi, DELTA_CFI_SLOT_BASE);
  boot_cfi_add_expected(cfi, DELTA_CFI_SLOT_EOF);

  size_t hsd_size = (sizeof(heatshrink_decoder) + 7U) & ~((size_t)7U);
  if (hsd_size + 8U >= arena_len) {
    return BOOT_ERR_INVALID_STATE;
  }

  heatshrink_decoder *hsd = (heatshrink_decoder *)arena;
  boot_secure_zeroize(arena, arena_len);
  heatshrink_decoder_reset(hsd);

  uint32_t read_cap =
      (uint32_t)(((size_t)HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(hsd) + 7U) & ~((size_t)7U));
  if (read_cap == 0U) {
    read_cap = 8U;
  }
  if (hsd_size + read_cap + 64U > arena_len) {
    return BOOT_ERR_INVALID_STATE;
  }

  uint8_t *read_buf = arena + hsd_size;
  uint8_t *write_buf = arena + hsd_size + read_cap;
  uint32_t raw_write_cap = (uint32_t)(arena_len - hsd_size - read_cap);

  /* STEP 1: parse & verify TDS header */
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

  if (hdr.expected_target_size == 0U || hdr.expected_target_size > dest_max_size ||
      hdr.base_size > base_max_size) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto cleanup;
  }

  {
    if (hdr.instr_count == 0U) {
      status = BOOT_ERR_VERIFY;
      goto cleanup;
    }
    if (hdr.instr_count > (UINT32_MAX / (uint32_t)sizeof(toob_tds_instr_t))) {
      status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }
    uint32_t instr_bytes = hdr.instr_count * (uint32_t)sizeof(toob_tds_instr_t);
    if (UINT32_MAX - (uint32_t)sizeof(toob_tds_header_t) < instr_bytes) {
      status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }
    uint32_t expect_lit = (uint32_t)sizeof(toob_tds_header_t) + instr_bytes;
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

  /* STEP 2: shared stream writer + ghost-base check */
  sdvm_t s;
  boot_secure_zeroize(&s, sizeof(s));
  status = boot_stream_writer_init(&s.writer, platform, dest_addr, hdr.expected_target_size,
                                   write_buf, raw_write_cap, open_txn);
  if (status != BOOT_OK) {
    goto cleanup;
  }
  s.base_addr = base_addr;
  s.delta_addr = delta_addr;
  s.base_size = hdr.base_size;
  s.read_buf = read_buf;
  s.read_cap = read_cap;
  s.hsd = hsd;

  if (s.writer.flushed_off == 0U) {
    status = verify_ghost_base(&s, hdr.base_fingerprint);
    if (status != BOOT_OK) {
      goto cleanup;
    }
  }

  boot_cfi_step(cfi, DELTA_CFI_SLOT_BASE);

  /* STEP 3: reset decoder immediately before use */
  heatshrink_decoder_reset(hsd);

  /* STEP 4: streaming VM execution */
  uint32_t delta_read_off = (uint32_t)sizeof(toob_tds_header_t);
  uint32_t lit_read_off = hdr.literal_block_offset;
  uint32_t inst_idx = 0U;
  bool eof_reached = false;

  const uint32_t MAX_INSTRUCTIONS = 1000000U;
  uint32_t guard = 0U;

  while (!eof_reached) {
    if (++guard > MAX_INSTRUCTIONS) {
      status = BOOT_ERR_INVALID_STATE;
      goto cleanup;
    }
    if (inst_idx >= hdr.instr_count) {
      status = BOOT_ERR_VERIFY;
      goto cleanup;
    }
    if (UINT32_MAX - delta_read_off < (uint32_t)sizeof(toob_tds_instr_t) ||
        delta_read_off + sizeof(toob_tds_instr_t) > delta_max_size) {
      status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    toob_tds_instr_t inst __attribute__((aligned(8)));
    boot_secure_zeroize(&inst, sizeof(inst));
    if (platform->flash->read(delta_addr + delta_read_off, (uint8_t *)&inst, sizeof(inst)) !=
        BOOT_OK) {
      status = BOOT_ERR_FLASH_HW;
      goto cleanup;
    }

    uint32_t icrc = compute_boot_crc32((const uint8_t *)&inst, offsetof(toob_tds_instr_t, crc32));
    BOOT_SECURE_REQUIRE(icrc == inst.crc32, {
      status = BOOT_ERR_VERIFY;
      goto cleanup;
    });

    const uint32_t opcode = inst.opcode;
    const uint32_t length = inst.length;
    const uint32_t src_off = inst.offset;

    if (opcode == TOOB_TDS_OP_EOF) {
      if (length != 0U || src_off != 0U) {
        status = BOOT_ERR_VERIFY;
        goto cleanup;
      }
      eof_reached = true;
      break;
    }

    delta_read_off += (uint32_t)sizeof(toob_tds_instr_t);
    inst_idx++;

    switch (opcode) {
    case TOOB_TDS_OP_COPY_BASE:
    case TOOB_TDS_OP_BZERO:
      if (UINT32_MAX - s.writer.target_off < length ||
          s.writer.target_off + length > hdr.expected_target_size) {
        status = BOOT_ERR_FLASH_BOUNDS;
        goto cleanup;
      }
      status = produce_copy_or_zero(&s, opcode, length, src_off);
      break;

    case TOOB_TDS_OP_INSERT_LIT:
      if (src_off > 0U && (UINT32_MAX - s.writer.target_off >= src_off) &&
          (s.writer.target_off + src_off <= s.writer.flushed_off)) {
        if (UINT32_MAX - lit_read_off < length ||
            lit_read_off + length > (uint32_t)delta_max_size) {
          status = BOOT_ERR_FLASH_BOUNDS;
          goto cleanup;
        }
        s.writer.write_pos = 0U;
        s.writer.target_off += src_off;
        lit_read_off += length;
      } else {
        status = produce_insert(&s, length, src_off, &lit_read_off, (uint32_t)delta_max_size);
      }
      break;

    default:
      status = BOOT_ERR_VERIFY;
      break;
    }
    if (status != BOOT_OK) {
      goto cleanup;
    }

    if (s.writer.target_off == hdr.expected_target_size && s.writer.write_pos > 0U) {
      status = boot_stream_writer_flush(&s.writer, true);
      if (status != BOOT_OK) {
        goto cleanup;
      }
    }
  }

  /* EOF: final flush */
  status = boot_stream_writer_flush(&s.writer, true);
  if (status != BOOT_OK) {
    goto cleanup;
  }

  BOOT_SECURE_REQUIRE(eof_reached && inst_idx == hdr.instr_count - 1U &&
                          s.writer.target_off == hdr.expected_target_size &&
                          lit_read_off == (uint32_t)delta_max_size,
                      {
                        status = BOOT_ERR_VERIFY;
                        goto cleanup;
                      });

  boot_cfi_step(cfi, DELTA_CFI_SLOT_EOF);
  boot_cfi_require(cfi, {
    status = BOOT_ERR_INVALID_STATE;
    goto cleanup;
  });

  open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0U;
  open_txn->delta_chunk_id = 0U;
  status = BOOT_OK;

cleanup:
  boot_secure_zeroize(arena, arena_len);
  return status;
}

#else /* !TOOB_FEATURE_DELTA */

boot_status_t boot_delta_apply(const boot_platform_t *platform, uint32_t delta_addr,
                               size_t delta_max_size, uint32_t dest_addr, size_t dest_max_size,
                               uint32_t base_addr, size_t base_max_size,
                               wal_entry_payload_t *open_txn, uint8_t *arena, size_t arena_len) {
  (void)delta_addr;
  (void)delta_max_size;
  (void)dest_addr;
  (void)dest_max_size;
  (void)base_addr;
  (void)base_max_size;
  if (!arena || arena_len < 1024U || !platform || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_ERR_NOT_SUPPORTED;
}

#endif /* TOOB_FEATURE_DELTA */
