/**
 * @file boot_stream_writer.h
 * @brief Shared brownout-resumable, write_align-buffered Flash Stream Writer.
 *
 * Used by both boot_delta.c (SDVM) and boot_decomp.c (Heatshrink full-image)
 * to eliminate duplicated erase-ahead, write-combining, read-back verification,
 * and sector-aligned WAL checkpointing while enforcing arbitrary power-of-two /
 * ECC / XTS-AES flash write alignments up to 32 bytes (ARCH-T02, MED-09).
 */

#ifndef BOOT_STREAM_WRITER_H
#define BOOT_STREAM_WRITER_H

#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_types.h"
#include "heatshrink_decoder.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BOOT_STREAM_MAX_WRITE_ALIGN 32U
#define BOOT_STREAM_RB_WINDOW 256U

/**
 * @brief Shared streaming flash writer state.
 *
 * Invariant:
 *   write_buf[0 .. write_pos) holds logical output bytes
 *   [target_off - write_pos, target_off).
 *   `flushed_off` is always an exact multiple of `write_align` during mid-stream
 *   writes; unaligned tail bytes (< write_align) are carried across flushes and
 *   padded with `platform->flash->erased_value` only on `pad_final == true`.
 */
typedef struct {
  const boot_platform_t *platform;
  uint32_t dest_addr;
  uint32_t expected_target_size;
  uint32_t write_align;

  uint8_t *write_buf;
  uint32_t write_cap;
  uint32_t write_pos;

  uint32_t target_off;
  uint32_t flushed_off;
  uint32_t committed_off;
  uint32_t checkpoint_off;
  uint32_t erased_end;

  wal_entry_payload_t *txn;
} boot_stream_writer_t;

/**
 * @brief Initializes the stream writer and validates/fast-forwards any
 *        sector-aligned resume checkpoint from `open_txn`.
 */
boot_status_t boot_stream_writer_init(boot_stream_writer_t *w, const boot_platform_t *platform,
                                      uint32_t dest_addr, uint32_t expected_target_size,
                                      uint8_t *write_buf, uint32_t raw_write_cap,
                                      wal_entry_payload_t *open_txn);

/**
 * @brief Flushes buffered output to flash, preserving `write_align` carry bytes
 *        on intermediate flushes (`pad_final == false`) and padding the final
 *        tail with `erased_value` when `pad_final == true`.
 */
boot_status_t boot_stream_writer_flush(boot_stream_writer_t *w, bool pad_final);

#ifdef HEATSHRINK_DECODER_H
/**
 * @brief Drains a heatshrink decoder into the stream writer, flushing whenever
 *        `write_buf` fills and enforcing the `expected_target_size` zip-bomb cap.
 */
static inline boot_status_t boot_stream_writer_drain_hsd(boot_stream_writer_t *w,
                                                         heatshrink_decoder *hsd) {
  const boot_platform_t *p = w->platform;
  for (;;) {
    if (p->wdt != NULL && p->wdt->kick != NULL) {
      p->wdt->kick();
    }

    uint32_t space = w->write_cap - w->write_pos;
    if (space == 0U) {
      boot_status_t st = boot_stream_writer_flush(w, false);
      if (st != BOOT_OK) {
        return st;
      }
      space = w->write_cap - w->write_pos;
      if (space == 0U) {
        return BOOT_ERR_INVALID_STATE;
      }
    }

    size_t polled = 0U;
    HSD_poll_res pres = heatshrink_decoder_poll(hsd, w->write_buf + w->write_pos, space, &polled);
    if (pres < 0) {
      return BOOT_ERR_VERIFY;
    }

    w->write_pos += (uint32_t)polled;
    w->target_off += (uint32_t)polled;

    if (w->target_off > w->expected_target_size) {
      return BOOT_ERR_INVALID_STATE;
    }

    if (pres == HSDR_POLL_EMPTY) {
      return BOOT_OK;
    }
  }
}
#endif /* HEATSHRINK_DECODER_H */

#endif /* BOOT_STREAM_WRITER_H */
