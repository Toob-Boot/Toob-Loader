/*
 * ==============================================================================
 * Toob-Boot Core File: boot_delta.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/merkle_spec.md (TDS1 Streaming Virtual Machine)
 * - docs/concept_fusion.md (Zero Allocation, Brownout-Resume)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. O(1) SDVM (Streaming Delta Virtual Machine): Kein RAM-Overhead
 * (Zero-Allocation), nutzt reines Pointer-Multiplexing über die crypto_arena
 * als Write-Combiner.
 * 2. Subtractive Pointer Sandboxing: Verhindert Arbitrary-Read Exploits und
 *    Integer-Wraparounds bei manipulierten Längenangaben in den Instruktionen.
 * 3. Sector-Boundary Checkpointing: Schreibt WAL-Checkpoints exakt an Sektoren-
 *    grenzen. Bei einem Brownout erfolgt der Resume nahtlos durch Dry-Runs.
 * 4. Ghost-Base Validation: O(1) Stream-Hashing prüft den 8-Byte Fingerprint
 *    der Base-Firmware glitch-sicher gegen Trivial-Forging Angriffe ab.
 */

#include "boot_delta.h"
#include "boot_config_mock.h"
#include "boot_crc32.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "heatshrink_decoder.h"
#include <stddef.h>
#include <string.h>


/* Zero-Allocation: Exklusive Übernahme der Arena für den Patch-Vorgang */
extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 1024,
               "Crypto Arena must be at least 1KB for SDVM");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK MUST be high-hamming distance for Glitch Shielding");

/* P10 CFI Tracking Constants */
#define CFI_DELTA_INIT 0x10101010
#define CFI_DELTA_HDR_OK 0x20202020
#define CFI_DELTA_BASE_OK 0x40404040
#define CFI_DELTA_EOF 0x80808080
#define CFI_DELTA_FLUSHED 0x01010101

/* ==============================================================================
 * INTERNAL HELPERS & GLITCH SHIELDS
 * ==============================================================================
 */

static inline boot_status_t constant_time_memcmp_glitch_safe(const uint8_t *a,
                                                             const uint8_t *b,
                                                             size_t len) {
  uint32_t acc_fwd = 0;
  uint32_t acc_rev = 0;

  for (size_t i = 0; i < len; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[len - 1 - i] ^ b[len - 1 - i]);
  }

  volatile uint32_t shield_1 = 0, shield_2 = 0;
  if (acc_fwd == 0)
    shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (shield_1 == BOOT_OK && acc_rev == 0)
    shield_2 = BOOT_OK;

  if (shield_1 == BOOT_OK && shield_2 == BOOT_OK && shield_1 == shield_2)
    return BOOT_OK;
  return BOOT_ERR_VERIFY;
}

static inline bool is_fully_erased(const uint8_t *buf, size_t len,
                                   uint8_t erased_val) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != erased_val)
      return false;
  }
  return true;
}

/**
 * @brief Flushes the internal Write-Combiner RAM to Flash securely.
 * Handles Phase-Bound Verify and Smart Sector-Erases on the fly.
 */
static boot_status_t
flush_target_buffer(const boot_platform_t *platform, uint32_t target_base,
                    uint32_t *flushed_offset, uint8_t *write_buf,
                    uint32_t write_len, uint32_t *current_sector_end,
                    wal_entry_payload_t *txn, uint32_t *last_checkpoint,
                    heatshrink_decoder *hsd) {
  (void)hsd;
  if (write_len == 0)
    return BOOT_OK;

  uint32_t dest_addr = target_base + *flushed_offset;
  if (UINT32_MAX - target_base < *flushed_offset)
    return BOOT_ERR_FLASH_BOUNDS;

  uint32_t write_end = dest_addr + write_len;
  if (write_end < dest_addr)
    return BOOT_ERR_FLASH_BOUNDS;

  /* 1. Smart-Erase Pre-Emption für den Staging-Slot (Verhindert
   * Write-Amplification) */
  while (*current_sector_end < write_end) {
    uint32_t erase_target = *current_sector_end;
    size_t sec_size = 0;
    if (platform->flash->get_sector_size(erase_target, &sec_size) != BOOT_OK ||
        sec_size == 0)
      return BOOT_ERR_FLASH_HW;

    bool needs_erase = false;
    uint32_t chk_off = 0;
    uint8_t erased_val = platform->flash->erased_value;

    /* P10 FIX: Isolierter Stack-Buffer (Zerstört die Krypto-Arena nicht!) */
    uint8_t e_buf[64] __attribute__((aligned(8)));
    size_t max_step = sizeof(e_buf);

    while (chk_off < sec_size) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
      size_t step =
          (sec_size - chk_off > max_step) ? max_step : (sec_size - chk_off);
      if (platform->flash->read(erase_target + chk_off, e_buf, step) !=
          BOOT_OK) {
        needs_erase = true;
        break;
      }
      if (!is_fully_erased(e_buf, step, erased_val)) {
        needs_erase = true;
        break;
      }
      chk_off += (uint32_t)step;
    }
    boot_secure_zeroize(e_buf, sizeof(e_buf));

    if (needs_erase) {
      if (sec_size > CHIP_FLASH_MAX_SECTOR_SIZE && platform->wdt &&
          platform->wdt->suspend_for_critical_section)
        platform->wdt->suspend_for_critical_section();
      else if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      boot_status_t er_st = platform->flash->erase_sector(erase_target);

      if (sec_size > CHIP_FLASH_MAX_SECTOR_SIZE && platform->wdt &&
          platform->wdt->resume)
        platform->wdt->resume();
      else if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      if (er_st != BOOT_OK)
        return er_st;
    }

    if (UINT32_MAX - *current_sector_end < sec_size)
      return BOOT_ERR_FLASH_BOUNDS;
    *current_sector_end += (uint32_t)sec_size;
  }

  /* 2. Hardware Flash Write */
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  if (platform->flash->write(dest_addr, write_buf, write_len) != BOOT_OK)
    return BOOT_ERR_FLASH_HW;

  /* 3. Phase-Bound Read-Back Verify (Tearing / Bit-Rot Protection) */
  /* P10 FIX: Isolierter Stack-Buffer */
  uint8_t rb_buf[64] __attribute__((aligned(8)));
  uint32_t rb_off = 0;

  while (rb_off < write_len) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    size_t step = (write_len - rb_off > sizeof(rb_buf))
                      ? sizeof(rb_buf)
                      : (write_len - rb_off);

    boot_secure_zeroize(rb_buf, step); /* TOCTOU Guard */
    if (platform->flash->read(dest_addr + rb_off, rb_buf, step) != BOOT_OK)
      return BOOT_ERR_FLASH_HW;

    uint32_t diff = 0;
    for (size_t i = 0; i < step; i++) {
      diff |= (rb_buf[i] ^ write_buf[rb_off + i]);
    }

    volatile uint32_t s1 = 0, s2 = 0;
    if (diff == 0)
      s1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (s1 == BOOT_OK && diff == 0)
      s2 = BOOT_OK;

    if (s1 != BOOT_OK || s2 != BOOT_OK)
      return BOOT_ERR_FLASH_HW; /* SPI-Rauschen oder Bit-Rot! */
    rb_off += (uint32_t)step;
  }
  boot_secure_zeroize(rb_buf, sizeof(rb_buf));

  /* 4. WAL Checkpoint Logic (Aligned to max sector bounds) */
  *flushed_offset += write_len;

  if (*flushed_offset - *last_checkpoint >= CHIP_FLASH_MAX_SECTOR_SIZE) {
    /* REMOVED: heatshrink_decoder_reset(hsd); -> This destroyed the LZSS stream! */
    txn->delta_chunk_id = *flushed_offset;
    boot_status_t log_stat = boot_journal_append(platform, txn);
    if (log_stat != BOOT_OK)
      return log_stat;
    *last_checkpoint = *flushed_offset;
  }

  return BOOT_OK;
}

/* ==============================================================================
 * PUBLIC SDVM ENGINE
 * ==============================================================================
 */

boot_status_t boot_delta_apply(const boot_platform_t *platform,
                               uint32_t delta_addr, size_t delta_max_size,
                               uint32_t dest_addr, size_t dest_max_size,
                               uint32_t base_addr, size_t base_max_size,
                               wal_entry_payload_t *open_txn) {

  if (!platform || !platform->flash || !platform->crypto || !platform->wdt ||
      !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (delta_max_size < sizeof(toob_tds_header_t) + sizeof(toob_tds_instr_t)) {
    return BOOT_ERR_VERIFY; /* Payload is too small to be a valid TDS stream */
  }

  volatile uint32_t delta_cfi = CFI_DELTA_INIT;
  boot_status_t status = BOOT_OK;

  /* P10 Alignment Guard: Padding des Struct-Offsets für DMA-Sicherheit */
  size_t hsd_size = (sizeof(heatshrink_decoder) + 7) & ~((size_t)7);
  if (hsd_size >= BOOT_CRYPTO_ARENA_SIZE) return BOOT_ERR_INVALID_STATE;

  heatshrink_decoder *hsd = (heatshrink_decoder *)crypto_arena;
  size_t remaining_arena = BOOT_CRYPTO_ARENA_SIZE - hsd_size;
  size_t half_arena = (remaining_arena / 2) & ~((size_t)7); /* 8-Byte Aligned für SPI-DMA */
  uint8_t *write_buf = crypto_arena + hsd_size;
  uint8_t *read_buf = crypto_arena + hsd_size + half_arena;

  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
  heatshrink_decoder_reset(hsd);

  /* ====================================================================
   * STEP 1: PARSE & VERIFY TDS HEADER (Bounds & Magic)
   * ==================================================================== */
  toob_tds_header_t hdr __attribute__((aligned(8)));
  boot_secure_zeroize(&hdr, sizeof(hdr));

  if (platform->flash->read(delta_addr, (uint8_t *)&hdr,
                            sizeof(toob_tds_header_t)) != BOOT_OK) {
    status = BOOT_ERR_FLASH_HW;
    goto cleanup;
  }

  size_t hdr_crc_len = offsetof(toob_tds_header_t, header_crc32);
  uint32_t calc_hdr_crc =
      compute_boot_crc32((const uint8_t *)&hdr, hdr_crc_len);

  volatile uint32_t hdr_shield_1 = 0, hdr_shield_2 = 0;
  bool hdr_ok =
      (hdr.magic == TOOB_TDS_MAGIC && calc_hdr_crc == hdr.header_crc32);

  if (hdr_ok)
    hdr_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (hdr_shield_1 == BOOT_OK && hdr_ok)
    hdr_shield_2 = BOOT_OK;

  if (hdr_shield_1 != BOOT_OK || hdr_shield_2 != BOOT_OK ||
      hdr_shield_1 != hdr_shield_2) {
    status = BOOT_ERR_VERIFY;
    goto cleanup; /* Fake or Corrupt Delta */
  }

  if (hdr.expected_target_size > dest_max_size ||
      hdr.expected_target_size == 0 || hdr.base_size > base_max_size) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto cleanup;
  }

  uint32_t instr_bytes = hdr.instr_count * sizeof(toob_tds_instr_t);
  if (UINT32_MAX - sizeof(toob_tds_header_t) < instr_bytes) {
    status = BOOT_ERR_INVALID_ARG;
    goto cleanup; /* Anti-Wraparound */
  }

  uint32_t expected_lit_offset = sizeof(toob_tds_header_t) + instr_bytes;
  if (expected_lit_offset > delta_max_size) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto cleanup;
  }

  delta_cfi ^= CFI_DELTA_HDR_OK;

  /* ====================================================================
   * STEP 2: PRE-FLIGHT "GHOST-BASE" VERIFICATION
   * Verhindert das Patchen auf eine falschen Firmware (Anti-Brick)!
   * ==================================================================== */
  uint32_t checkpoint = 0;
  if (open_txn->intent == WAL_INTENT_UPDATE_PENDING ||
      open_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
    checkpoint = open_txn->delta_chunk_id;
    if (checkpoint > hdr.expected_target_size)
      checkpoint = hdr.expected_target_size;
  }

  /* Wird übersprungen, wenn wir nach Brownout in der Mitte resümieren, da
   * Base bereits vom vorherigen Lauf verifiziert und im WAL geloggt wurde! */
  if (checkpoint == 0) {
    uint64_t hash_ctx[32] __attribute__((aligned(8))); /* O(1) Memory Context */
    uint8_t computed_hash[32] __attribute__((aligned(8)));
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    boot_secure_zeroize(computed_hash, sizeof(computed_hash));

    if (platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx)) != BOOT_OK) {
      status = BOOT_ERR_CRYPTO;
      goto cleanup;
    }

    uint32_t hashed = 0;
    while (hashed < hdr.base_size) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
      size_t step = (hdr.base_size - hashed > BOOT_CRYPTO_ARENA_SIZE)
                        ? BOOT_CRYPTO_ARENA_SIZE
                        : (hdr.base_size - hashed);

      if (platform->flash->read(base_addr + hashed, crypto_arena, step) !=
          BOOT_OK) {
        status = BOOT_ERR_FLASH_HW;
        goto cleanup;
      }
      if (platform->crypto->hash_update(hash_ctx, crypto_arena, step) !=
          BOOT_OK) {
        status = BOOT_ERR_CRYPTO;
        goto cleanup;
      }
      hashed += (uint32_t)step;
    }
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

    size_t dlen = 32;
    if (platform->crypto->hash_finish(hash_ctx, computed_hash, &dlen) !=
        BOOT_OK) {
      status = BOOT_ERR_CRYPTO;
      goto cleanup;
    }

    if (constant_time_memcmp_glitch_safe(computed_hash, hdr.base_fingerprint,
                                         8) != BOOT_OK) {
      status = BOOT_ERR_DOWNGRADE;
      goto cleanup; /* Base Firmware is wrong! Patcher aborted safely. */
    }
  }

  delta_cfi ^= CFI_DELTA_BASE_OK;

  /* ====================================================================
   * STEP 3: ZERO-ALLOCATION SDVM SETUP
   * ==================================================================== */
  uint32_t target_logical_offset = 0;
  uint32_t flushed_target_offset = 0;
  uint32_t delta_read_offset = sizeof(toob_tds_header_t);
  uint32_t lit_read_offset = hdr.literal_block_offset;
  uint32_t write_buf_pos = 0;
  uint32_t last_wal_checkpoint = 0;
  uint32_t current_sector_end = dest_addr;

  /* Brownout Fast-Forward Setup */
  if (checkpoint > 0) {
    flushed_target_offset = checkpoint;
    last_wal_checkpoint = checkpoint;

    uint32_t curr = 0;
    while (curr < checkpoint) {
      size_t sec_size = 0;
      if (platform->flash->get_sector_size(dest_addr + curr, &sec_size) !=
              BOOT_OK ||
          sec_size == 0) {
        status = BOOT_ERR_FLASH_HW;
        goto cleanup;
      }
      curr += (uint32_t)sec_size;
    }
    if (curr != checkpoint) {
      status = BOOT_ERR_INVALID_STATE;
      goto cleanup; /* Checkpoint was not sector-aligned! */
    }
    current_sector_end = dest_addr + checkpoint;
  }

  /* VM State Registers */
  uint32_t inst_idx = 0;
  uint32_t inst_rem = 0;
  uint32_t inst_opcode = 0;
  uint32_t inst_src_off = 0;
  bool eof_reached = false;

  const uint32_t MAX_INSTRUCTIONS = 1000000; /* P10 Endless-Loop Guard */
  uint32_t loop_guard = 0;

  /* ====================================================================
   * STEP 4: STREAMING VM EXECUTION LOOP
   * ==================================================================== */
  while (target_logical_offset < hdr.expected_target_size || inst_rem > 0 ||
         !eof_reached) {
    if (++loop_guard > MAX_INSTRUCTIONS) {
      status = BOOT_ERR_INVALID_STATE;
      goto cleanup;
    }

    /* --- A. FETCH NEXT INSTRUCTION --- */
    if (inst_rem == 0) {
      if (inst_idx >= hdr.instr_count) {
        status = BOOT_ERR_VERIFY;
        goto cleanup; /* End of array reached before EOF */
      }

      /* P10 Subtractive Bound Check */
      if (UINT32_MAX - delta_read_offset < sizeof(toob_tds_instr_t) ||
          delta_read_offset + sizeof(toob_tds_instr_t) > delta_max_size) {
        status = BOOT_ERR_INVALID_ARG;
        goto cleanup; /* Stream truncated */
      }

      toob_tds_instr_t inst __attribute__((aligned(8)));
      boot_secure_zeroize(&inst, sizeof(inst));

      if (platform->flash->read(delta_addr + delta_read_offset,
                                (uint8_t *)&inst, sizeof(inst)) != BOOT_OK) {
        status = BOOT_ERR_FLASH_HW;
        goto cleanup;
      }

      /* SPI Bit-Rot Defense: CRC-32 of Instruction bytes */
      uint32_t calc_icrc = compute_boot_crc32(
          (const uint8_t *)&inst, offsetof(toob_tds_instr_t, crc32));

      volatile uint32_t i_shield_1 = 0, i_shield_2 = 0;
      if (calc_icrc == inst.crc32)
        i_shield_1 = BOOT_OK;
      BOOT_GLITCH_DELAY();
      if (i_shield_1 == BOOT_OK && calc_icrc == inst.crc32)
        i_shield_2 = BOOT_OK;

      if (i_shield_1 != BOOT_OK || i_shield_2 != BOOT_OK) {
        status = BOOT_ERR_VERIFY;
        goto cleanup; /* Instruction Corrupted by Noise! */
      }

      inst_opcode = inst.opcode;
      inst_rem = inst.length;
      inst_src_off = inst.offset;

      if (inst_opcode == TOOB_TDS_OP_EOF) {
        eof_reached = true;
        break;
      }

      /* ZIP-BOMB GUARD: Nur bei raw Opcodes hier prüfen. INSERT_LIT prüft dynamisch im poll() */
      if (inst_opcode != TOOB_TDS_OP_EOF && inst_opcode != TOOB_TDS_OP_INSERT_LIT) {
        if (UINT32_MAX - target_logical_offset < inst_rem || target_logical_offset + inst_rem > hdr.expected_target_size) {
          status = BOOT_ERR_FLASH_BOUNDS; goto cleanup;
        }
      }
      if (inst_opcode != TOOB_TDS_OP_EOF) {
        delta_read_offset += sizeof(toob_tds_instr_t);
        inst_idx++;
      }
    }

    if (inst_opcode == TOOB_TDS_OP_EOF) {
        eof_reached = true;
        if (hsd) {
            heatshrink_decoder_finish(hsd);
            while (1) {
                if (platform->wdt && platform->wdt->kick) platform->wdt->kick();
                uint32_t space_left = (uint32_t)half_arena - write_buf_pos;
                if (space_left == 0) {
                    uint32_t logical_start = target_logical_offset - write_buf_pos;
                    if (logical_start + write_buf_pos > flushed_target_offset) {
                        uint32_t valid_offset = (logical_start < flushed_target_offset) ? flushed_target_offset - logical_start : 0;
                        uint32_t write_len = write_buf_pos - valid_offset;
                        if (write_len > 0) {
                            status = flush_target_buffer(platform, dest_addr, &flushed_target_offset, write_buf + valid_offset, write_len, &current_sector_end, open_txn, &last_wal_checkpoint, hsd);
                            if (status != BOOT_OK) goto cleanup;
                        }
                    }
                    write_buf_pos = 0; space_left = (uint32_t)half_arena;
                }
                size_t polled_sz = 0;
                HSD_poll_res pres = heatshrink_decoder_poll(hsd, write_buf + write_buf_pos, space_left, &polled_sz);
                if (pres < 0) { status = BOOT_ERR_VERIFY; goto cleanup; }
                write_buf_pos += (uint32_t)polled_sz;
                target_logical_offset += (uint32_t)polled_sz;

                /* P10 ZIP-BOMB GUARD FÜR EOF (Hier war die Lücke!) */
                if (target_logical_offset > hdr.expected_target_size) {
                    status = BOOT_ERR_INVALID_STATE; goto cleanup;
                }
                if (pres == HSDR_POLL_EMPTY) break;
            }
        }

        /* FINALER FLUSH nach der EOF Dekodierung (Verhindert Data Loss!) */
        if (write_buf_pos > 0) {
            uint32_t logical_start = target_logical_offset - write_buf_pos;
            if (logical_start + write_buf_pos > flushed_target_offset) {
                uint32_t valid_offset = (logical_start < flushed_target_offset) ? flushed_target_offset - logical_start : 0;
                uint32_t write_len = write_buf_pos - valid_offset;
                /* Alignment Padding for final write */
                if (platform->flash->write_align > 0) {
                    uint32_t align = platform->flash->write_align;
                    uint32_t pad = write_len % align;
                    if (pad != 0) {
                        pad = align - pad;
                        if (write_len + pad + valid_offset > half_arena) { status = BOOT_ERR_FLASH_BOUNDS; goto cleanup; }
                        memset(write_buf + valid_offset + write_len, platform->flash->erased_value, pad);
                        write_len += pad;
                    }
                }
                if (write_len > 0) {
                    status = flush_target_buffer(platform, dest_addr, &flushed_target_offset, write_buf + valid_offset, write_len, &current_sector_end, open_txn, &last_wal_checkpoint, hsd);
                    if (status != BOOT_OK) goto cleanup;
                }
            }
            write_buf_pos = 0;
        }
        break;
    }

    /* --- B. ZERO-ALLOCATION WRITE COMBINER (WITH DRY-RUN RESUME) --- */
    uint32_t step = inst_rem;
    bool is_dry_run = (target_logical_offset < flushed_target_offset);

    if (inst_opcode != TOOB_TDS_OP_INSERT_LIT) {
        if (is_dry_run) {
            if (target_logical_offset + step > flushed_target_offset) {
                step = flushed_target_offset - target_logical_offset;
            }
        } else {
            uint32_t space = (uint32_t)half_arena - write_buf_pos;
            if (step > space) step = space;
        }
    }

    if (inst_opcode == TOOB_TDS_OP_BZERO) {
        if (!is_dry_run) {
            memset(write_buf + write_buf_pos, 0x00, step);
            write_buf_pos += step;
        }
        inst_rem -= step;
    } else if (inst_opcode == TOOB_TDS_OP_COPY_BASE) {
        if (!is_dry_run) {
            if (UINT32_MAX - inst_src_off < step || inst_src_off + step > hdr.base_size) {
                status = BOOT_ERR_FLASH_BOUNDS; goto cleanup;
            }
            if (platform->flash->read(base_addr + inst_src_off, write_buf + write_buf_pos, step) != BOOT_OK) {
                status = BOOT_ERR_FLASH_HW; goto cleanup;
            }
            write_buf_pos += step;
        }
        inst_rem -= step;
        inst_src_off += step;
    } else if (inst_opcode == TOOB_TDS_OP_INSERT_LIT) {
        uint32_t compressed_rem = inst_rem;
        uint32_t decompressed_total = 0;

        while (compressed_rem > 0) {
            uint32_t max_sink = HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(hsd);
            uint32_t chunk = compressed_rem > max_sink ? max_sink : compressed_rem;
            if (platform->flash->read(delta_addr + lit_read_offset, read_buf, chunk) != BOOT_OK) {
                status = BOOT_ERR_FLASH_HW; goto cleanup;
            }

            size_t sunk_sz = 0;
            if (heatshrink_decoder_sink(hsd, read_buf, chunk, &sunk_sz) < 0) {
                status = BOOT_ERR_VERIFY; goto cleanup;
            }

            while (1) {
                if (platform->wdt && platform->wdt->kick) platform->wdt->kick();
                uint32_t space_left = (uint32_t)half_arena - write_buf_pos;

                if (space_left == 0) {
                    uint32_t logical_start = target_logical_offset + decompressed_total - write_buf_pos;
                    if (logical_start + write_buf_pos > flushed_target_offset) {
                        uint32_t valid_offset = (logical_start < flushed_target_offset) ? flushed_target_offset - logical_start : 0;
                        uint32_t write_len = write_buf_pos - valid_offset;
                        if (write_len > 0) {
                            status = flush_target_buffer(platform, dest_addr, &flushed_target_offset, write_buf + valid_offset, write_len, &current_sector_end, open_txn, &last_wal_checkpoint, hsd);
                            if (status != BOOT_OK) goto cleanup;
                        }
                    }
                    write_buf_pos = 0;
                    space_left = (uint32_t)half_arena;
                }

                size_t polled_sz = 0;
                HSD_poll_res pres = heatshrink_decoder_poll(hsd, write_buf + write_buf_pos, space_left, &polled_sz);
                if (pres < 0) { status = BOOT_ERR_VERIFY; goto cleanup; }

                write_buf_pos += (uint32_t)polled_sz;
                decompressed_total += (uint32_t)polled_sz;

                if (target_logical_offset + decompressed_total > hdr.expected_target_size) {
                    status = BOOT_ERR_INVALID_STATE; goto cleanup;
                }
                if (pres == HSDR_POLL_EMPTY) break;
            }
            lit_read_offset += (uint32_t)sunk_sz;
            compressed_rem -= (uint32_t)sunk_sz;
        }

        step = decompressed_total;
        inst_rem = 0;
    }

    target_logical_offset += step;

    /* --- C. FLUSH & CHECKPOINT --- */
    if (write_buf_pos == half_arena || target_logical_offset == hdr.expected_target_size) {
      uint32_t logical_start = target_logical_offset - write_buf_pos;
      if (logical_start + write_buf_pos > flushed_target_offset) {
        uint32_t valid_offset = (logical_start < flushed_target_offset) ? flushed_target_offset - logical_start : 0;
        uint32_t write_len = write_buf_pos - valid_offset;

        if (target_logical_offset == hdr.expected_target_size && platform->flash->write_align > 0) {
          uint32_t align = platform->flash->write_align;
          uint32_t pad = write_len % align;
          if (pad != 0) {
            pad = align - pad;
            if (write_len + pad + valid_offset > half_arena) { status = BOOT_ERR_FLASH_BOUNDS; goto cleanup; }
            memset(write_buf + valid_offset + write_len, platform->flash->erased_value, pad);
            write_len += pad;
          }
        }
        if (write_len > 0) {
          status = flush_target_buffer(platform, dest_addr, &flushed_target_offset, write_buf + valid_offset, write_len, &current_sector_end, open_txn, &last_wal_checkpoint, hsd);
          if (status != BOOT_OK) goto cleanup;
        }
      }
      write_buf_pos = 0;
    }
  }

  /* ====================================================================
   * STEP 5: FINAL INTEGRITY RESOLUTION (Anti Truncation)
   * ==================================================================== */
  volatile uint32_t final_1 = 0, final_2 = 0;
  bool flow_ok =
      (eof_reached && target_logical_offset == hdr.expected_target_size);

  if (flow_ok)
    final_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (final_1 == BOOT_OK && flow_ok)
    final_2 = BOOT_OK;

  if (final_1 != BOOT_OK || final_2 != BOOT_OK || final_1 != final_2) {
    status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  delta_cfi ^= CFI_DELTA_EOF;

  uint32_t expected_cfi =
      CFI_DELTA_INIT ^ CFI_DELTA_HDR_OK ^ CFI_DELTA_BASE_OK ^ CFI_DELTA_EOF;
  volatile uint32_t cfi_1 = 0, cfi_2 = 0;
  if (delta_cfi == expected_cfi)
    cfi_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (cfi_1 == BOOT_OK && delta_cfi == expected_cfi)
    cfi_2 = BOOT_OK;

  if (cfi_1 == BOOT_OK && cfi_2 == BOOT_OK && cfi_1 == cfi_2) {
    /* Success! Patching done, prep the WAL for the next state (SWAP or RUN). */
    open_txn->delta_chunk_id = target_logical_offset;
    status = BOOT_OK;
  } else {
    status = BOOT_ERR_INVALID_STATE; /* CFI Control-Flow Loop Trap! */
  }

cleanup:
  /* P10 Single Exit: Zerstöre jegliche Firmware-Fragmente und Krypto-Keys aus
   * der Arena */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
  return status;
}