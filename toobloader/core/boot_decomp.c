/*
 * ==============================================================================
 * Toob-Boot Core: boot_decomp.c — Streaming Decompressor for Compressed Images
 * ==============================================================================
 *
 * Expands a Heatshrink (LZSS) compressed image from staging flash into a target
 * partition using the shared `boot_stream_writer_t` (ARCH-T02, MED-09).
 */

#include "boot_decomp.h"
#include "boot_features.h"
#include "boot_fih.h"
#include "boot_secure_zeroize.h"
#include "boot_slot_transport.h"
#include "boot_stream_writer.h"
#include "generated_boot_config.h"
#include "heatshrink_decoder.h"
#include <stddef.h>

#if TOOB_FEATURE_DECOMP

boot_status_t boot_decomp_apply(const boot_platform_t *platform, uint32_t src_addr, size_t src_size,
                                uint32_t dest_addr, size_t dest_max_size,
                                uint32_t expected_installed_size, wal_entry_payload_t *open_txn,
                                uint8_t *arena, size_t arena_len) {
  if (!arena || arena_len < 1024U) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!platform || !platform->flash || !platform->wdt || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (!platform->flash->read || !platform->flash->write || !platform->flash->erase_sector ||
      !platform->flash->get_sector_size) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (expected_installed_size == 0U || expected_installed_size > dest_max_size) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  boot_status_t status = BOOT_OK;

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

  boot_stream_writer_t writer;
  status = boot_stream_writer_init(&writer, platform, dest_addr, expected_installed_size, write_buf,
                                   raw_write_cap, open_txn);
  if (status != BOOT_OK) {
    goto cleanup;
  }

  heatshrink_decoder_reset(hsd);

  uint32_t read_off = 0U;
  uint32_t rem = (uint32_t)src_size;

  while (rem > 0U) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }

    uint32_t max_sink = (uint32_t)HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(hsd);
    uint32_t chunk = (rem < max_sink) ? rem : max_sink;
    if (chunk > read_cap) {
      chunk = read_cap;
    }

    if (platform->flash->read(src_addr + read_off, read_buf, chunk) != BOOT_OK) {
      status = BOOT_ERR_FLASH_HW;
      goto cleanup;
    }

    size_t sunk = 0U;
    if (heatshrink_decoder_sink(hsd, read_buf, chunk, &sunk) < 0) {
      status = BOOT_ERR_VERIFY;
      goto cleanup;
    }
    if (sunk == 0U) {
      status = BOOT_ERR_INVALID_STATE;
      goto cleanup;
    }

    status = boot_stream_writer_drain_hsd(&writer, hsd);
    if (status != BOOT_OK) {
      goto cleanup;
    }

    read_off += (uint32_t)sunk;
    rem -= (uint32_t)sunk;
  }

  heatshrink_decoder_finish(hsd);
  status = boot_stream_writer_drain_hsd(&writer, hsd);
  if (status != BOOT_OK) {
    goto cleanup;
  }

  status = boot_stream_writer_flush(&writer, true);
  if (status != BOOT_OK) {
    goto cleanup;
  }

  BOOT_SECURE_REQUIRE(writer.target_off == expected_installed_size, {
    status = BOOT_ERR_VERIFY;
    goto cleanup;
  });

  open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE] = 0U;
  open_txn->delta_chunk_id = 0U;
  status = BOOT_OK;

cleanup:
  boot_secure_zeroize(arena, arena_len);
  return status;
}

#else /* !TOOB_FEATURE_DECOMP */

boot_status_t boot_decomp_apply(const boot_platform_t *platform, uint32_t src_addr, size_t src_size,
                                uint32_t dest_addr, size_t dest_max_size,
                                uint32_t expected_installed_size, wal_entry_payload_t *open_txn,
                                uint8_t *arena, size_t arena_len) {
  (void)src_addr;
  (void)src_size;
  (void)dest_addr;
  (void)dest_max_size;
  (void)expected_installed_size;
  if (!arena || arena_len < 1024U || !platform || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_ERR_NOT_SUPPORTED;
}

#endif /* TOOB_FEATURE_DECOMP */
