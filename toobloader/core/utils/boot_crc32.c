#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_secure_zeroize.h"
#include "toob_crc32_contract.h"

static inline uint32_t crc32_byte(uint32_t crc, uint8_t val) {
  crc ^= val;
  for (uint8_t j = 0; j < 8U; j++) {
    crc = (crc >> 1U) ^ (((crc & 1U) != 0U) ? TOOB_CRC32_POLY : 0U);
  }
  return crc;
}

uint32_t boot_crc32_update(uint32_t crc_init, const uint8_t *data, size_t len) {
  uint32_t crc = crc_init;
  for (size_t i = 0; i < len; i++) {
    crc = crc32_byte(crc, data[i]);
  }
  return crc;
}

uint32_t compute_boot_crc32(const uint8_t *data, size_t len) {
  return boot_crc32_update(TOOB_CRC32_INIT, data, len) ^ TOOB_CRC32_FINAL_XOR;
}

boot_status_t boot_crc32_flash_stream(const boot_platform_t *platform, uint32_t addr, size_t len,
                                      uint32_t *out_crc, uint8_t *arena, size_t arena_len) {
  if (platform == NULL || platform->flash == NULL || platform->flash->read == NULL ||
      out_crc == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (len == 0U) {
    if (arena != NULL && arena_len > 0U) {
      boot_secure_zeroize(arena, arena_len);
    }
    *out_crc = TOOB_CRC32_INIT ^ TOOB_CRC32_FINAL_XOR;
    return BOOT_OK;
  }
  if (arena == NULL || arena_len == 0U || len > (size_t)UINT32_MAX ||
      (UINT32_MAX - addr) < (uint32_t)(len - 1U)) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint32_t crc = TOOB_CRC32_INIT;
  size_t offset = 0;

  while (offset < len) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }

    size_t step = (len - offset > arena_len) ? arena_len : (len - offset);

    boot_status_t st = platform->flash->read(addr + (uint32_t)offset, arena, (uint32_t)step);
    if (st != BOOT_OK) {
      boot_secure_zeroize(arena, arena_len);
      return st;
    }

    crc = boot_crc32_update(crc, arena, step);
    offset += step;
  }

  boot_secure_zeroize(arena, arena_len);
  *out_crc = crc ^ TOOB_CRC32_FINAL_XOR;
  return BOOT_OK;
}

uint32_t boot_crc32_fill(uint32_t crc_init, uint8_t val, size_t len) {
  uint32_t crc = crc_init;
  for (size_t i = 0; i < len; i++) {
    crc = crc32_byte(crc, val);
  }
  return crc;
}

boot_status_t boot_flash_is_erased(const boot_platform_t *platform, uint32_t addr, size_t len,
                                   bool *out_erased) {
  if (platform == NULL || platform->flash == NULL || platform->flash->read == NULL ||
      out_erased == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (len == 0U) {
    *out_erased = true;
    return BOOT_OK;
  }

  if (len > (size_t)UINT32_MAX || (UINT32_MAX - addr) < (uint32_t)(len - 1U)) {
    *out_erased = false;
    return BOOT_ERR_INVALID_ARG;
  }

  const uint8_t ev = platform->flash->erased_value;
  const uint32_t ev_word =
      (uint32_t)ev | ((uint32_t)ev << 8U) | ((uint32_t)ev << 16U) | ((uint32_t)ev << 24U);
  uint32_t chunk_words[64];
  size_t offset = 0U;

  while (offset < len) {
    if (platform->wdt != NULL && platform->wdt->kick != NULL) {
      platform->wdt->kick();
    }

    size_t rem = len - offset;
    size_t step = (rem > sizeof(chunk_words)) ? sizeof(chunk_words) : rem;
    boot_status_t st = platform->flash->read(addr + (uint32_t)offset, chunk_words, step);
    if (st != BOOT_OK) {
      *out_erased = false;
      return st;
    }

    size_t full_words = step / sizeof(uint32_t);
    for (size_t w = 0U; w < full_words; w++) {
      if (chunk_words[w] != ev_word) {
        *out_erased = false;
        return BOOT_OK;
      }
    }

    const uint8_t *tail = (const uint8_t *)chunk_words;
    for (size_t b = full_words * sizeof(uint32_t); b < step; b++) {
      if (tail[b] != ev) {
        *out_erased = false;
        return BOOT_OK;
      }
    }

    offset += step;
  }

  *out_erased = true;
  return BOOT_OK;
}

boot_status_t boot_secure_confirm_impl(boot_status_t one_shot_status, bool inject) {
  volatile uint32_t s1 = 0U;
  volatile uint32_t s2 = 0U;
  if (one_shot_status == BOOT_OK && !inject) {
    s1 = BOOT_OK;
  }
  BOOT_GLITCH_DELAY();
  if (s1 == BOOT_OK && one_shot_status == BOOT_OK && !inject) {
    s2 = BOOT_OK;
  }
  if (s1 == BOOT_OK && s2 == BOOT_OK && s1 == s2) {
    return BOOT_OK;
  }
  return BOOT_ERR_VERIFY;
}

boot_status_t constant_time_memcmp_glitch_safe(const uint8_t *a, const uint8_t *b, size_t len) {
  if (len == 0U || a == NULL || b == NULL) {
    return BOOT_ERR_VERIFY;
  }

  volatile uint32_t acc_fwd = 0U;
  volatile uint32_t acc_rev = 0U;

  for (size_t i = 0U; i < len; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[len - 1U - i] ^ b[len - 1U - i]);
  }

  BOOT_SECURE_REQUIRE(acc_fwd == 0U && acc_rev == 0U, { return BOOT_ERR_VERIFY; });
  return BOOT_OK;
}

boot_status_t boot_random_safe(const boot_platform_t *platform, uint8_t *buf, size_t len) {
  if (!platform || !platform->entropy || !platform->entropy->random) {
    return BOOT_ERR_NOT_SUPPORTED;
  }

  boot_status_t stat = platform->entropy->random(buf, len);
  if (stat != BOOT_OK) {
    return stat;
  }

  uint8_t or_acc = 0x00U;
  uint8_t and_acc = 0xFFU;
  for (size_t i = 0U; i < len; i++) {
    or_acc |= buf[i];
    and_acc &= buf[i];
  }

  if (or_acc == 0x00U || and_acc == 0xFFU) {
    return BOOT_ERR_CRYPTO;
  }

  return BOOT_OK;
}

boot_status_t boot_flash_write_guarded(const flash_hal_t *flash, uint32_t addr, const void *buf,
                                       size_t len) {
  if (!flash || !flash->write || (!buf && len > 0U)) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (len == 0U) {
    return BOOT_OK;
  }
  if (boot_flash_range_hits_immutable_boot(addr, len)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  return flash->write(addr, buf, len);
}

boot_status_t boot_flash_erase_sector_guarded(const flash_hal_t *flash, uint32_t addr) {
  if (!flash || !flash->erase_sector) {
    return BOOT_ERR_INVALID_ARG;
  }
  size_t sector_len = 1U;
  if (flash->get_sector_size) {
    size_t queried = 0U;
    if (flash->get_sector_size(addr, &queried) == BOOT_OK && queried > 0U) {
      sector_len = queried;
    }
  }
  if (boot_flash_range_hits_immutable_boot(addr, sector_len)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  return flash->erase_sector(addr);
}
