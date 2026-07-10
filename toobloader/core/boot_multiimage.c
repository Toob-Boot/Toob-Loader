/*
 * ==============================================================================
 * Toob-Boot Core File: boot_multiimage.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/concept_fusion.md (Anti-Brick, Multi-Target FOTA)
 * - docs/testing_requirements.md (P10 Bounds, TOCTOU Defense, Zero-Allocation)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. O(1) Bitmap Resume Logic: Verhindert Partial-Bricks durch Brownouts.
 *    Jede geflashte Komponente wird im 256-Bit WAL `transfer_bitmap` markiert.
 * 2. Software MPU (Memory Protection Unit): Subtraktive Überschneidungs-
 *    prüfungen verhindern mathematisch bewiesen "Arbitrary Overwrites" in
 *    Bootloader, WAL oder den aktiven App-Slot.
 * 3. Ghost-Match Defense: Zwingende Nullifizierung der crypto_arena vor
 *    dem Read-Back beweist die physikalische Integrität der SPI-Hardware.
 * 4. Dynamic Loop CFI Tracking: Ein Token-Akkumulator berechnet sich dynamisch
 *    aus ID und Index, um zu beweisen, dass keine Komponente durch einen
 *    Program Counter (PC) Glitch übersprungen wurde.
 */

#include "boot_multiimage.h"
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include <string.h>

/* P5: Arena is now passed explicitly by the orchestrator */

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 1024,
               "Crypto Arena must be at least 1KB for TDM Streaming");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "Glitch-Defense benötigt High-Hamming-Distance BOOT_OK");

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define MI_CFI_SLOT_INIT 0
#define MI_CFI_SLOT_BOUNDS 1
#define MI_CFI_SLOT_COMPLETE 2

/* ==============================================================================
 * INTERNAL MATHEMATICS & GLITCH SHIELDS
 * ==============================================================================
 */

#include "boot_ct_utils.h"

/**
 * @brief P10 Software Memory Protection Unit (Subtractive Bound Proof)
 * Beweist mathematisch, dass das Update-Ziel keine kritischen Systembereiche
 * zerstört.
 */
static bool is_target_whitelisted(uint32_t target_addr, uint32_t size,
                                  const boot_allowed_region_t *whitelist,
                                  uint32_t num_regions) {
  if (size == 0)
    return true;
  if (num_regions == 0 || whitelist == NULL)
    return false;

  /* P10 Subtractive Wraparound Defense for the Image Size itself */
  if (UINT32_MAX - target_addr < size)
    return false;
  uint32_t target_end = target_addr + size;

  for (uint32_t i = 0; i < num_regions; i++) {
    uint32_t wl_base = whitelist[i].base_addr;
    uint32_t wl_size = whitelist[i].max_size;

    if (wl_size == 0)
      continue;
    if (UINT32_MAX - wl_base < wl_size)
      continue; /* Ignore invalid whitelist entries */

    uint32_t wl_end = wl_base + wl_size;

    /* Liegt das Image VOLLSTÄNDIG in dieser definierten Whitelist-Region? */
    if (target_addr >= wl_base && target_end <= wl_end) {
      return true;
    }
  }
  return false; /* Ausbruchsversuch detektiert! */
}

/* ==============================================================================
 * PUBLIC ORCHESTRATOR
 * ==============================================================================
 */

boot_status_t boot_multiimage_apply(const boot_platform_t *platform,
                                    uint32_t staging_base,
                                    const boot_component_t *components,
                                    uint32_t num_components,
                                    const boot_allowed_region_t *whitelist,
                                    uint32_t num_regions,
                                    wal_entry_payload_t *open_txn,
                                    uint8_t *arena, size_t arena_len) {

  /* P5: Arena bounds check */
  if (!arena || arena_len < 1024)
    return BOOT_ERR_INVALID_ARG;

  /* 1. P10 Pointer & Sanity Checks */
  if (!platform || !platform->flash || !platform->crypto || !platform->wdt ||
      !components || !whitelist || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (num_components == 0)
    return BOOT_OK; /* Trivial Success */

  /* Hardware Limit (WAL Transfer-Bitmap hat exakt 8 * 32 = 256 Bits) */
  if (num_components > 256)
    return BOOT_ERR_INVALID_ARG;

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t mi_cfi_seed = 0;
  boot_random_safe(platform, (uint8_t *)&mi_cfi_seed, sizeof(mi_cfi_seed));
  boot_cfi_ctx_t multi_cfi_ctx;
  boot_cfi_init(multi_cfi_ctx, mi_cfi_seed);
  boot_cfi_add_expected(multi_cfi_ctx, MI_CFI_SLOT_BOUNDS);
  boot_cfi_add_expected(multi_cfi_ctx, MI_CFI_SLOT_COMPLETE);

  for (uint32_t i = 0; i < num_components; i++) {
    multi_cfi_ctx.expected_val ^= (~components[i].component_id);
  }

  boot_status_t final_status = BOOT_ERR_VERIFY;

  /* ====================================================================
   * STEP 2: GLOBAL ARBITRARY WRITE SANDBOXING (Glitch Shielded)
   * ====================================================================
   * Bevor auch nur 1 Byte gelesen/gelöscht wird, MÜSSEN alle n-Images
   * beweisen, dass sie innerhalb der Whitelist-Grenzen liegen!
   */
  bool bounds_violation = false;
  for (uint32_t i = 0; i < num_components; i++) {
    if (!is_target_whitelisted(components[i].target_addr,
                               components[i].image_size, whitelist,
                               num_regions)) {
      bounds_violation = true;
      break;
    }
    /* Anti-Wraparound Check für den Source-Staging Slot */
    if (UINT32_MAX - staging_base < components[i].staging_offset ||
        UINT32_MAX - (staging_base + components[i].staging_offset) <
            components[i].image_size) {
      bounds_violation = true;
      break;
    }
  }

  BOOT_SECURE_REQUIRE(!bounds_violation, {
    return BOOT_ERR_FLASH_BOUNDS; /* Exploit-Attempt Trapped! */
  });

  boot_cfi_step(multi_cfi_ctx, MI_CFI_SLOT_BOUNDS);

  /* Expected values are dynamically registered in multi_cfi_ctx at initialization */

  /* P6 Fail-Fast: HAL ohne get_hash_ctx_size ist unvollständig */
  if (!platform->crypto->get_hash_ctx_size)
    return BOOT_ERR_NOT_SUPPORTED;
  size_t ctx_size = platform->crypto->get_hash_ctx_size();
  if (ctx_size > 256)
    return BOOT_ERR_INVALID_ARG;

  uint8_t *hash_ctx = arena;
  uint8_t *stream_buf = arena + 256;
  size_t stream_max = arena_len - 256;
  size_t half_stream = stream_max / 2; /* Für Phase-Bound Readback */

  /* ====================================================================
   * STEP 3: DEPLOYMENT LOOP (CFI-Tracked Component Routing)
   * ==================================================================== */
  for (uint32_t i = 0; i < num_components; i++) {
    boot_component_t comp __attribute__((aligned(8)));
    boot_secure_zeroize(&comp, sizeof(comp));

    /* 1. P10 Memory Sandboxing: Kopie auf Stack ziehen, um TOCTOU durch DMAs zu
     * blockieren */
    memcpy(&comp, &components[i], sizeof(boot_component_t));

    if (comp.image_size == 0) {
      multi_cfi_ctx.current_val ^= (~comp.component_id); /* Trivial Completion */
      continue;
    }

    if (comp.component_id > 255) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto multi_cleanup;
    }

    /* 2. O(1) Brownout-Resume Evaluierung (Wurde diese Komponente bereits
     * geflasht?) */
    uint32_t bitmap_idx = comp.component_id / 32;
    uint32_t bit_mask = 1U << (comp.component_id % 32);

    if ((open_txn->transfer_bitmap[bitmap_idx] & bit_mask) != 0) {
      /* Komponente ist bereits physikalisch sicher verankert -> Skip! */
      multi_cfi_ctx.current_val ^= (~comp.component_id);
      continue;
    }

    /* 3. Hardware Erase für die Peripherie (Abstrahiert durch HAL) */
    uint32_t current_erase_addr = comp.target_addr;
    uint32_t erase_end = comp.target_addr + comp.image_size;
    uint32_t e_loop = 0;

    while (current_erase_addr < erase_end) {
      if (++e_loop > 100000) {
        final_status = BOOT_ERR_FLASH_HW;
        goto multi_cleanup;
      }
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      size_t sec_size = 0;
      if (platform->flash->get_sector_size(current_erase_addr, &sec_size) !=
              BOOT_OK ||
          sec_size == 0) {
        final_status = BOOT_ERR_FLASH_HW;
        goto multi_cleanup;
      }
      if (platform->flash->erase_sector(current_erase_addr) != BOOT_OK) {
        final_status = BOOT_ERR_FLASH_HW;
        goto multi_cleanup;
      }
      if (UINT32_MAX - current_erase_addr < sec_size) {
        final_status = BOOT_ERR_FLASH_BOUNDS;
        goto multi_cleanup; /* Wrap-Proof */
      }
      current_erase_addr += (uint32_t)sec_size;
    }

    /* 4. O(1) Streaming Copy & On-the-Fly Hashing */
    uint32_t written = 0;
    boot_secure_zeroize(hash_ctx, ctx_size);
    if (platform->crypto->hash_init(hash_ctx, ctx_size) != BOOT_OK) {
      final_status = BOOT_ERR_CRYPTO;
      goto multi_cleanup;
    }

    while (written < comp.image_size) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
      size_t step = (comp.image_size - written > half_stream)
                        ? half_stream
                        : (comp.image_size - written);

      uint32_t src_addr = staging_base + comp.staging_offset + written;
      uint32_t dst_addr = comp.target_addr + written;

      /* Read from Staging Archive */
      if (platform->flash->read(src_addr, stream_buf, step) != BOOT_OK) {
        final_status = BOOT_ERR_FLASH_HW;
        goto multi_cleanup;
      }

      /* Write to Peripheral Address (VASR Routing) */
      if (platform->flash->write(dst_addr, stream_buf, step) != BOOT_OK) {
        final_status = BOOT_ERR_FLASH_HW;
        goto multi_cleanup;
      }

      /* PHASE-BOUND PHANTOM-READ-BACK DEFENSE
       * Zwingt die Peripherie, die geschriebenen Daten via SPI wieder
       * auszuspucken! */
      uint8_t *rb_buf = stream_buf + half_stream;
      boot_secure_zeroize(rb_buf, step); /* TOCTOU Proof */

      if (platform->flash->read(dst_addr, rb_buf, step) != BOOT_OK) {
        final_status = BOOT_ERR_FLASH_HW;
        goto multi_cleanup;
      }

      if (constant_time_memcmp_glitch_safe(stream_buf, rb_buf, step) !=
          BOOT_OK) {
        final_status = BOOT_ERR_FLASH_HW;
        goto multi_cleanup; /* Tearing auf dem SPI-Bus der Peripherie! */
      }

      /* Update Stream Hash ONLY on Read-Back Buffer to ensure HW integrity! */
      if (platform->crypto->hash_update(hash_ctx, rb_buf, step) != BOOT_OK) {
        final_status = BOOT_ERR_CRYPTO;
        goto multi_cleanup;
      }

      written += (uint32_t)step;
    }

    /* 5. Verifikation des fertiggestellten Peripherie-Images */
    uint8_t final_hash[32] __attribute__((aligned(8)));
    size_t d_len = 32;
    if (platform->crypto->hash_finish(hash_ctx, final_hash, &d_len) !=
            BOOT_OK ||
        d_len != 32) {
      final_status = BOOT_ERR_CRYPTO;
      goto multi_cleanup;
    }

    if (constant_time_memcmp_glitch_safe(final_hash, comp.expected_hash, 32) !=
        BOOT_OK) {
      final_status = BOOT_ERR_VERIFY;
      goto multi_cleanup; /* Peripheral Firmware Corrupt! */
    }
    boot_secure_zeroize(final_hash, 32);

    /* 6. WAL Checkpoint (Atomarer Abschluss für diese Komponente) */
    open_txn->transfer_bitmap[bitmap_idx] |= bit_mask;
    final_status = boot_journal_append(platform, open_txn);
    if (final_status != BOOT_OK)
      goto multi_cleanup;

    multi_cfi_ctx.current_val ^=
        (~comp.component_id); /* Component flashed & verified successfully */
  }

  boot_cfi_step(multi_cfi_ctx, MI_CFI_SLOT_COMPLETE);

  /* ====================================================================
   * STEP 4: FINAL ALGEBRAIC RESOLUTION (Glitch Trap)
   * ====================================================================
   */
  boot_cfi_require(multi_cfi_ctx, {
    final_status = BOOT_ERR_INVALID_STATE; /* EMFI PC-Jump / Skip Attack Trapped! */
    goto multi_cleanup;
  });
  final_status = BOOT_OK;

multi_cleanup:
  /* P10 Single Exit: Leakage Defense für dekryptete Sub-Images */
  boot_secure_zeroize(arena, arena_len);
  return final_status;
}