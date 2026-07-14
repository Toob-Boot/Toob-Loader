#include "boot_effect.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_swap.h"
#include "boot_fih.h"
#include "generated_boot_config.h"
#include "boot_secure_zeroize.h"
#include "boot_slot_caps.h"

static boot_status_t stream_copy(const boot_platform_t *platform, uint32_t src,
                                 uint32_t dest, size_t len,
                                 uint8_t *arena, size_t arena_len) {
  size_t offset = 0;
  while (offset < len) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    size_t step = (len - offset > arena_len) ? arena_len : (len - offset);

    boot_status_t st = platform->flash->read(src + (uint32_t)offset, arena, (uint32_t)step);
    if (st != BOOT_OK) {
      boot_secure_zeroize(arena, arena_len);
      return st;
    }

    st = platform->flash->write(dest + (uint32_t)offset, arena, (uint32_t)step);
    if (st != BOOT_OK) {
      boot_secure_zeroize(arena, arena_len);
      return st;
    }

    offset += step;
  }
  boot_secure_zeroize(arena, arena_len);
  return BOOT_OK;
}

boot_status_t boot_effect_execute(const boot_platform_t *platform,
                                  const flash_effect_t *fx, size_t n,
                                  const boot_allowed_region_t *whitelist, size_t wl_n,
                                  uint8_t *arena, size_t arena_len) {
  for (size_t i = 0; i < n; i++) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }

    /* 1. Whitelist Check (Double Defense) */
    bool allowed = false;
    for (size_t w = 0; w < wl_n; w++) {
      if (is_buffer_within((const uint8_t *)(uintptr_t)fx[i].dst, fx[i].len,
                           (const uint8_t *)(uintptr_t)whitelist[w].base_addr, whitelist[w].max_size)) {
        allowed = true;
        break;
      }
    }
    BOOT_SECURE_REQUIRE(allowed, { return BOOT_ERR_FLASH_BOUNDS; });

    /* 2. Idempotenz-Check: Ist der Soll-Zustand bereits erreicht? */
    uint32_t cur_crc = 0;
    boot_status_t crc_stat = boot_crc32_flash_stream(platform, fx[i].dst, fx[i].len, &cur_crc, arena, arena_len);
    if (crc_stat == BOOT_OK && cur_crc == fx[i].post_crc) {
      continue; /* Bereits im Sollzustand (Zero-Wear Skip) */
    }

    /* 3. Operation ausführen */
    boot_status_t op_stat = BOOT_OK;
    if (fx[i].op == EFF_ERASE) {
      op_stat = boot_swap_erase_safe(platform, fx[i].dst, fx[i].len, arena, arena_len);
    } else if (fx[i].op == EFF_COPY) {
      op_stat = stream_copy(platform, fx[i].src, fx[i].dst, fx[i].len, arena, arena_len);
    } else if (fx[i].op == EFF_FLIP) {
      const slot_caps_t *caps = platform->slot_caps;
      if (!caps) {
        caps = boot_get_slot_caps();
      }
      if (!caps) {
        return BOOT_ERR_INVALID_ARG;
      }

      if (caps->exec_model == SLOT_EXEC_BANK_SWAP) {
        if (!caps->bank_flip) return BOOT_ERR_NOT_SUPPORTED;
        op_stat = caps->bank_flip(fx[i].dst);
      } else if (caps->exec_model == SLOT_EXEC_XIP_REMAP) {
        if (!caps->xip_remap_commit) return BOOT_ERR_NOT_SUPPORTED;
        op_stat = caps->xip_remap_commit(fx[i].src);
      } else if (caps->exec_model == SLOT_EXEC_RELOCATABLE) {
#ifdef TOOB_TMR_HAS_ACTIVE_APP_SLOT
        wal_tmr_payload_t tmr __attribute__((aligned(8)));
        boot_secure_zeroize(&tmr, sizeof(tmr));
        op_stat = boot_journal_get_tmr(platform, &tmr);
        if (op_stat == BOOT_OK) {
          tmr.active_app_slot = (uint8_t)fx[i].dst;
          op_stat = boot_journal_update_tmr(platform, &tmr);
        }
        boot_secure_zeroize(&tmr, sizeof(tmr));
#else
        op_stat = BOOT_ERR_NOT_SUPPORTED;
#endif
      } else {
        op_stat = BOOT_ERR_NOT_SUPPORTED;
      }

      if (op_stat == BOOT_OK && caps->get_active_slot) {
        uint32_t active = 0xFFFFFFFFu;
        op_stat = caps->get_active_slot(&active);
        if (op_stat == BOOT_OK) {
          BOOT_SECURE_REQUIRE(active == fx[i].dst, { return BOOT_ERR_VERIFY; });
        }
      }
      if (op_stat != BOOT_OK) return op_stat;
      continue; /* Skip standard flash read-back CRC check */
    }
    if (op_stat != BOOT_OK) return op_stat;

    /* 4. Read-Back & Verification */
    uint32_t verify_crc = 0;
    crc_stat = boot_crc32_flash_stream(platform, fx[i].dst, fx[i].len, &verify_crc, arena, arena_len);
    if (crc_stat != BOOT_OK) return crc_stat;
    BOOT_SECURE_REQUIRE(verify_crc == fx[i].post_crc, { return BOOT_ERR_FLASH_HW; });
  }
  return BOOT_OK;
}

uint32_t boot_effect_compute_erased_crc(size_t len) {
  return ~boot_crc32_fill(0xFFFFFFFF, 0xFF, len);
}

static inline bool supply_sufficient(uint32_t mv, uint64_t worst_us, uint32_t margin) {
  /* Minimum safe voltage for stable flash write/erase operations is 2700 mV */
  uint32_t required_mv = 2700U + margin;

  /* Bei sehr langen Schreibvorgängen (> 5s) fordern wir eine zusätzliche Marge,
   * um Spannungseinbrüche unter Last abzufedern. */
  if (worst_us > 5000000ULL) {
    required_mv += 100U;
  }

  return (mv >= required_mv);
}

boot_status_t boot_effect_admit_or_defer(const boot_platform_t *platform,
                                         const wal_tmr_payload_t *tmr,
                                         uint32_t image_size,
                                         const boot_component_t *components,
                                         size_t num_components,
                                         bool requires_swap) {
  uint32_t sector_size = platform->flash->max_sector_size;
  if (sector_size == 0) {
    sector_size = 4096;
  }

  uint32_t app_erases = 0;
  uint32_t staging_erases = 0;
  uint32_t scratch_erases = 0;
  uint64_t total_write_bytes = 0;

  if (requires_swap) {
    uint32_t num_sectors = (image_size + sector_size - 1) / sector_size;
    app_erases += num_sectors;
    staging_erases += num_sectors;
    scratch_erases += num_sectors;
    total_write_bytes += (uint64_t)image_size * 3;
  }

  for (size_t i = 0; i < num_components; i++) {
    uint32_t num_sectors = (components[i].image_size + sector_size - 1) / sector_size;
    if (components[i].target_addr >= CHIP_APP_SLOT_ABS_ADDR &&
        components[i].target_addr < CHIP_APP_SLOT_ABS_ADDR + CHIP_APP_SLOT_SIZE) {
      app_erases += num_sectors;
    } else if (components[i].target_addr >= CHIP_STAGING_SLOT_ABS_ADDR &&
               components[i].target_addr < CHIP_STAGING_SLOT_ABS_ADDR + CHIP_STAGING_SLOT_SIZE) {
      staging_erases += num_sectors;
    }
    total_write_bytes += components[i].image_size;
  }

  /* 1. Wear-Leveling Erase-Budgetprüfung */
  if (platform->flash->max_erase_cycles > 0) {
    if (tmr->app_slot_erase_counter + app_erases >= platform->flash->max_erase_cycles ||
        tmr->staging_slot_erase_counter + staging_erases >= platform->flash->max_erase_cycles ||
        tmr->swap_buffer_erase_counter + scratch_erases >= platform->flash->max_erase_cycles) {
      return BOOT_ERR_COUNTER_EXHAUSTED;
    }
  }

  /* 2. Worst-Case-Zeit berechnen */
  uint64_t worst_us = 0;
  if (platform->flash->erase_time_us_max > 0) {
    uint32_t total_erases = app_erases + staging_erases + scratch_erases;
    worst_us += (uint64_t)total_erases * platform->flash->erase_time_us_max;
  }
  if (platform->flash->write_time_us_page > 0 && platform->flash->write_align > 0) {
    uint64_t num_pages = (total_write_bytes + platform->flash->write_align - 1) / platform->flash->write_align;
    worst_us += num_pages * platform->flash->write_time_us_page;
  }

  /* 3. Spannungsprüfung (sofern Hardware ADC-Callback bereitstellt) */
  if (platform->flash->get_supply_mv != NULL) {
    uint32_t mv = 0;
    boot_status_t supply_stat = platform->flash->get_supply_mv(&mv);
    if (supply_stat == BOOT_OK) {
      if (!supply_sufficient(mv, worst_us, 100U)) {
        return BOOT_ERR_DEFER;
      }
    }
  }

  return BOOT_OK;
}
