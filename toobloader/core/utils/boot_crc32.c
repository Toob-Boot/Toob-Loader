#include "boot_crc32.h"
#include "boot_secure_zeroize.h"

uint32_t boot_crc32_update(uint32_t crc_init, const uint8_t *data, size_t len) {
    uint32_t crc = crc_init;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return crc;
}

uint32_t compute_boot_crc32(const uint8_t *data, size_t len) {
    return ~boot_crc32_update(0xFFFFFFFF, data, len);
}

boot_status_t boot_crc32_flash_stream(const boot_platform_t *platform,
                                      uint32_t addr, size_t len,
                                      uint32_t *out_crc,
                                      uint8_t *arena, size_t arena_len) {
  uint32_t crc = 0xFFFFFFFF;
  size_t offset = 0;

  while (offset < len) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    size_t step = (len - offset > arena_len) ? arena_len : (len - offset);

    boot_status_t st = platform->flash->read(
        addr + (uint32_t)offset, arena, (uint32_t)step);
    if (st != BOOT_OK) {
      boot_secure_zeroize(arena, arena_len);
      return st;
    }

    crc = boot_crc32_update(crc, arena, step);
    offset += step;
  }

  boot_secure_zeroize(arena, arena_len);
  *out_crc = ~crc;
  return BOOT_OK;
}
