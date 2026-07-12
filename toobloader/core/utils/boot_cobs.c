/*
 * ==============================================================================
 * Toob-Boot Core File: boot_cobs.c
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/stage_1_5_spec.md (COBS Frame Format, Sync Markers)
 * - S. Cheshire, M. Baker: "Consistent Overhead Byte Stuffing" (IEEE/ACM 1999)
 *
 * ORIGIN: Extracted from boot_panic.c to enable reuse by boot_provisioning.c.
 *
 * ARCHITECTURAL PROPERTIES:
 * 1. Zero-Allocation: Decode operates in-place (write_idx <= read_idx invariant).
 * 2. Glitch-Shielded: Every COBS block boundary check uses dual-volatile shields
 *    with BOOT_GLITCH_DELAY() to resist voltage/EMFI faults.
 * 3. Anti-Leakage: Trailing garbage after decoded payload is zeroized.
 * 4. WDT-Safe: Long transmissions and blocking receives feed the watchdog.
 */

#include "boot_cobs.h"
#include "boot_fih.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>

void boot_cobs_send_frame(const boot_platform_t *platform,
                          const uint8_t *data, size_t len) {
  if (!platform || !platform->console || !platform->console->putchar ||
      len == 0 || !data)
    return;

  /* Frame Start Marker (Sync) */
  platform->console->putchar((char)COBS_MARKER_START);

  size_t ptr = 0;
  while (ptr < len) {
    uint8_t code = 1;
    size_t end = ptr;

    /* Find next zero or hit 254 data bytes limit (0xFF code) */
    while (end < len && data[end] != 0 && code < 0xFF) {
      end++;
      code++;
    }

    /* Write Block Code */
    platform->console->putchar((char)code);

    /* Write Block Data */
    for (size_t i = ptr; i < end; i++) {
      platform->console->putchar((char)data[i]);
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
    }

    ptr = end;
    /* Consume the physical zero that we encoded virtually */
    if (ptr < len && data[ptr] == 0) {
      ptr++;
    }
  }

  /* Frame End Marker */
  platform->console->putchar((char)COBS_MARKER_END);
  if (platform->console->flush) {
    platform->console->flush();
  }
}

boot_status_t boot_cobs_decode_in_place(uint8_t *__restrict data, size_t len,
                                        size_t *__restrict out_len) {
  if (!data || !out_len || len == 0)
    return BOOT_ERR_INVALID_ARG;

  size_t read_idx = 0;
  size_t write_idx = 0;

  while (read_idx < len) {
    uint8_t code = data[read_idx++];
    if (code == 0)
      return BOOT_ERR_INVALID_ARG; /* Zeroes sind in COBS-Payloads illegal */

    uint8_t copy_len = code - 1;

    bool is_within_bounds = (len - read_idx >= copy_len);

    BOOT_SECURE_REQUIRE(is_within_bounds, {
      return BOOT_ERR_INVALID_ARG; /* Exploit Trap */
    });

    /* O(1) in-place shift. Funktioniert sicher, da write_idx <= read_idx
     * garantiert ist */
    for (uint8_t i = 0; i < copy_len; i++) {
      data[write_idx++] = data[read_idx++];
    }

    /* Implizite Nullen wiederherstellen */
    if (code < 0xFF && read_idx < len) {
      if (write_idx >= len)
        return BOOT_ERR_INVALID_ARG;
      data[write_idx++] = 0x00;
    }
  }

  *out_len = write_idx;

  /* P10 Defense: Reste (Trailing Garbage) nullen, um logische Leakage zu
   * verhindern */
  if (write_idx < len) {
    boot_secure_zeroize(&data[write_idx], len - write_idx);
  }

  return BOOT_OK;
}

boot_status_t boot_cobs_recv_frame(const boot_platform_t *platform,
                                   uint8_t *buf, size_t buf_max,
                                   size_t *out_len) {
  if (!platform || !platform->console || !platform->console->getchar ||
      !buf || !out_len || buf_max == 0)
    return BOOT_ERR_INVALID_ARG;

  size_t rx_len = 0;

  while (1) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    uint8_t c;
    if (platform->console->getchar(&c, 100) != BOOT_OK)
      continue;

    if (c == COBS_MARKER_END) {
      if (rx_len > 0) {
        *out_len = rx_len;
        return BOOT_OK;
      }
      /* Empty frame (consecutive markers) — keep listening */
      continue;
    }

    if (rx_len < buf_max) {
      buf[rx_len++] = c;
    } else {
      /* Overflow Defense: Buffer vernichten und auf nächsten Sync warten */
      boot_secure_zeroize(buf, buf_max);
      rx_len = 0;
    }
  }
}
