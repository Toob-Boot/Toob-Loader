/*
 * ==============================================================================
 * Toob-Boot Core File: boot_multiimage.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/concept_fusion.md (Anti-Brick, Multi-Target FOTA)
 * - docs/testing_requirements.md (P10 Bounds, TOCTOU Defense, Zero-Allocation)
 */

#include "boot_multiimage.h"
#include "boot_features.h"
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_effect.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include <string.h>

#if TOOB_FEATURE_MULTIIMAGE

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 1024,
               "Crypto Arena must be at least 1KB for TDM Streaming");
_Static_assert(BOOT_OK == 0x55AA55AA, "Glitch-Defense benötigt High-Hamming-Distance BOOT_OK");

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define MI_CFI_SLOT_INIT 0
#define MI_CFI_SLOT_BOUNDS 1
#define MI_CFI_SLOT_COMPLETE 2

static boot_status_t validate_stage1_component_image(const boot_platform_t *platform,
                                                     uint32_t staging_base,
                                                     const boot_component_t *comp) {
  bool targets_s1a = false;
  bool targets_s1b = false;
#if defined(CHIP_STAGE1A_ABS_ADDR) && defined(CHIP_STAGE1A_SIZE) && (CHIP_STAGE1A_SIZE > 0U)
  targets_s1a = (comp->target_addr >= CHIP_STAGE1A_ABS_ADDR) &&
                (comp->target_addr < (CHIP_STAGE1A_ABS_ADDR + CHIP_STAGE1A_SIZE));
#endif
#if defined(CHIP_STAGE1B_ABS_ADDR) && defined(CHIP_STAGE1B_SIZE) && (CHIP_STAGE1B_SIZE > 0U)
  targets_s1b = (comp->target_addr >= CHIP_STAGE1B_ABS_ADDR) &&
                (comp->target_addr < (CHIP_STAGE1B_ABS_ADDR + CHIP_STAGE1B_SIZE));
#endif

  if (!targets_s1a && !targets_s1b) {
    return BOOT_OK;
  }

  if (!platform || !platform->flash || !platform->flash->read) {
    return BOOT_ERR_INVALID_ARG;
  }

#if defined(CHIP_STAGE1A_ABS_ADDR) && defined(CHIP_STAGE1A_SIZE) && (CHIP_STAGE1A_SIZE > 0U)
  if (targets_s1a && comp->target_addr != CHIP_STAGE1A_ABS_ADDR) {
    return BOOT_ERR_VERIFY;
  }
#endif
#if defined(CHIP_STAGE1B_ABS_ADDR) && defined(CHIP_STAGE1B_SIZE) && (CHIP_STAGE1B_SIZE > 0U)
  if (targets_s1b && comp->target_addr != CHIP_STAGE1B_ABS_ADDR) {
    return BOOT_ERR_VERIFY;
  }
#endif

  const uint32_t hdr_size = (uint32_t)sizeof(toob_image_header_t);
  if (comp->image_size <= hdr_size) {
    return BOOT_ERR_VERIFY;
  }

  const uint32_t src_addr = staging_base + comp->staging_offset;
  toob_image_header_t hdr __attribute__((aligned(8)));
  boot_secure_zeroize(&hdr, sizeof(hdr));

  boot_status_t rd_st = platform->flash->read(src_addr, (uint8_t *)&hdr, sizeof(hdr));
  if (rd_st != BOOT_OK) {
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return rd_st;
  }

  if (hdr.magic != TOOB_MAGIC_HEADER || hdr.image_size == 0U ||
      hdr.image_size > (comp->image_size - hdr_size)) {
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return BOOT_ERR_VERIFY;
  }

  const uint32_t payload_end_off = hdr_size + hdr.image_size;
  if (hdr.entry_point < payload_end_off) {
    /* XIP Stage 1 image: entry_point is a bank-relative offset */
    if (hdr.entry_point < hdr_size) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }

    uint32_t exec_base = comp->target_addr;
#if defined(CHIP_FLASH_XIP_BASE) && (CHIP_FLASH_XIP_BASE != 0U)
#if defined(CHIP_FLASH_BASE_ADDR) && (CHIP_FLASH_BASE_ADDR != 0U)
    if (comp->target_addr < (uint32_t)CHIP_FLASH_BASE_ADDR) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }
    uint32_t rel_bank = comp->target_addr - (uint32_t)CHIP_FLASH_BASE_ADDR;
#else
    uint32_t rel_bank = comp->target_addr;
#endif
    if (UINT32_MAX - (uint32_t)CHIP_FLASH_XIP_BASE < rel_bank) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }
    exec_base = (uint32_t)CHIP_FLASH_XIP_BASE + rel_bank;
#endif

    if (UINT32_MAX - exec_base < payload_end_off) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }

#if defined(__arm__) || defined(__thumb__) || defined(__TARGET_ARCH_THUMB) ||                      \
    defined(CHIP_VTOR_ALIGNMENT)
    /* On Cortex-M XIP, [src_addr + hdr.entry_point + 4] holds Reset_Handler;
     * verify it targets comp->target_addr's XIP window (rejects Stage1A->Stage1B mismatch). */
    if (payload_end_off - hdr.entry_point < 8U) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }
    uint32_t reset_vec = 0U;
    rd_st = platform->flash->read(src_addr + hdr.entry_point + 4U, (uint8_t *)&reset_vec,
                                  sizeof(reset_vec));
    if (rd_st != BOOT_OK) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return rd_st;
    }
    uint32_t reset_addr = reset_vec & ~1U;
    if ((reset_vec & 1U) == 0U || reset_addr < (exec_base + hdr_size) ||
        reset_addr >= (exec_base + payload_end_off)) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }
#endif
  } else {
    /* RAM-exec Stage 1 image: entry_point is an absolute IRAM address */
#if defined(CHIP_IRAM_BASE) && defined(CHIP_IRAM_SIZE) && (CHIP_IRAM_SIZE > 0U)
    if (hdr.entry_point < (uint32_t)CHIP_IRAM_BASE ||
        (hdr.entry_point - (uint32_t)CHIP_IRAM_BASE) >= (uint32_t)CHIP_IRAM_SIZE) {
      boot_secure_zeroize(&hdr, sizeof(hdr));
      return BOOT_ERR_VERIFY;
    }
#else
    boot_secure_zeroize(&hdr, sizeof(hdr));
    return BOOT_ERR_VERIFY;
#endif
  }

  boot_secure_zeroize(&hdr, sizeof(hdr));
  return BOOT_OK;
}

static bool is_target_whitelisted(uint32_t target_addr, uint32_t size,
                                  const boot_allowed_region_t *whitelist, uint32_t num_regions) {
  if (size == 0) {
    return true;
  }
  if (num_regions == 0 || whitelist == NULL) {
    return false;
  }

  if (UINT32_MAX - target_addr < size) {
    return false;
  }
  uint32_t target_end = target_addr + size;

  for (uint32_t i = 0; i < num_regions; i++) {
    uint32_t wl_base = whitelist[i].base_addr;
    uint32_t wl_size = whitelist[i].max_size;

    if (wl_size == 0) {
      continue;
    }
    if (UINT32_MAX - wl_base < wl_size) {
      continue;
    }

    uint32_t wl_end = wl_base + wl_size;
    if (target_addr >= wl_base && target_end <= wl_end) {
      return true;
    }
  }
  return false;
}

static boot_status_t verify_component_digest_at_addr(const boot_platform_t *platform,
                                                     const boot_component_t *comp,
                                                     uint32_t base_addr, uint8_t *hash_ctx,
                                                     size_t ctx_size, uint8_t *stream_buf,
                                                     size_t stream_len) {
  if (!platform->flash->read || !platform->crypto->hash_init || !platform->crypto->hash_update ||
      !platform->crypto->hash_finish) {
    return BOOT_ERR_NOT_SUPPORTED;
  }
  if ((UINT32_MAX - base_addr) < comp->image_size) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  if (comp->chunk_size > 0U) {
    uint32_t expected_chunks = comp->image_size / comp->chunk_size +
                               ((comp->image_size % comp->chunk_size != 0U) ? 1U : 0U);
    if (comp->num_chunks != expected_chunks || (UINT32_MAX / 32U) < comp->num_chunks ||
        (UINT32_MAX - comp->chunk_hashes_flash_addr) < (comp->num_chunks * 32U)) {
      return BOOT_ERR_INVALID_ARG;
    }

    uint32_t verified_bytes = 0U;
    for (uint32_t c_idx = 0U; c_idx < comp->num_chunks; c_idx++) {
      uint32_t chunk_len = (comp->image_size - verified_bytes > comp->chunk_size)
                               ? comp->chunk_size
                               : (comp->image_size - verified_bytes);

      uint8_t exp_hash[32] __attribute__((aligned(8)));
      uint8_t calc_hash[32] __attribute__((aligned(8)));
      boot_secure_zeroize(exp_hash, sizeof(exp_hash));
      boot_secure_zeroize(calc_hash, sizeof(calc_hash));

      /* Load expected digest into local RAM before hashing to prevent TOCTOU */
      if (platform->flash->read(comp->chunk_hashes_flash_addr + (c_idx * 32U), exp_hash, 32U) !=
          BOOT_OK) {
        boot_secure_zeroize(exp_hash, sizeof(exp_hash));
        return BOOT_ERR_FLASH_HW;
      }

      boot_secure_zeroize(hash_ctx, ctx_size);
      if (platform->crypto->hash_init(hash_ctx, ctx_size) != BOOT_OK) {
        boot_secure_zeroize(exp_hash, sizeof(exp_hash));
        return BOOT_ERR_CRYPTO;
      }

      uint32_t chunk_off = 0U;
      while (chunk_off < chunk_len) {
        if (platform->wdt && platform->wdt->kick) {
          platform->wdt->kick();
        }
        size_t step =
            ((chunk_len - chunk_off) > stream_len) ? stream_len : (size_t)(chunk_len - chunk_off);
        if (platform->flash->read(base_addr + verified_bytes + chunk_off, stream_buf, step) !=
            BOOT_OK) {
          boot_secure_zeroize(exp_hash, sizeof(exp_hash));
          return BOOT_ERR_FLASH_HW;
        }
        if (platform->crypto->hash_update(hash_ctx, stream_buf, step) != BOOT_OK) {
          boot_secure_zeroize(exp_hash, sizeof(exp_hash));
          return BOOT_ERR_CRYPTO;
        }
        chunk_off += (uint32_t)step;
      }

      size_t d_len = sizeof(calc_hash);
      if (platform->crypto->hash_finish(hash_ctx, calc_hash, &d_len) != BOOT_OK || d_len != 32U) {
        boot_secure_zeroize(calc_hash, sizeof(calc_hash));
        boot_secure_zeroize(exp_hash, sizeof(exp_hash));
        return BOOT_ERR_CRYPTO;
      }

      boot_status_t match = constant_time_memcmp_glitch_safe(calc_hash, exp_hash, 32U);
      boot_secure_zeroize(calc_hash, sizeof(calc_hash));
      boot_secure_zeroize(exp_hash, sizeof(exp_hash));
      BOOT_SECURE_REQUIRE(match == BOOT_OK, { return BOOT_ERR_VERIFY; });

      verified_bytes += chunk_len;
    }
    return BOOT_OK;
  }

  uint8_t exp_hash[32] __attribute__((aligned(8)));
  uint8_t final_hash[32] __attribute__((aligned(8)));
  memcpy(exp_hash, comp->expected_hash, 32U);
  boot_secure_zeroize(final_hash, sizeof(final_hash));

  boot_secure_zeroize(hash_ctx, ctx_size);
  if (platform->crypto->hash_init(hash_ctx, ctx_size) != BOOT_OK) {
    boot_secure_zeroize(exp_hash, sizeof(exp_hash));
    return BOOT_ERR_CRYPTO;
  }

  uint32_t hashed_len = 0U;
  while (hashed_len < comp->image_size) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    size_t step = ((comp->image_size - hashed_len) > stream_len)
                      ? stream_len
                      : (size_t)(comp->image_size - hashed_len);

    if (platform->flash->read(base_addr + hashed_len, stream_buf, step) != BOOT_OK) {
      boot_secure_zeroize(exp_hash, sizeof(exp_hash));
      return BOOT_ERR_FLASH_HW;
    }

    if (platform->crypto->hash_update(hash_ctx, stream_buf, step) != BOOT_OK) {
      boot_secure_zeroize(exp_hash, sizeof(exp_hash));
      return BOOT_ERR_CRYPTO;
    }
    hashed_len += (uint32_t)step;
  }

  size_t d_len = sizeof(final_hash);
  if (platform->crypto->hash_finish(hash_ctx, final_hash, &d_len) != BOOT_OK || d_len != 32U) {
    boot_secure_zeroize(final_hash, sizeof(final_hash));
    boot_secure_zeroize(exp_hash, sizeof(exp_hash));
    return BOOT_ERR_CRYPTO;
  }

  boot_status_t match = constant_time_memcmp_glitch_safe(final_hash, exp_hash, 32U);
  boot_secure_zeroize(final_hash, sizeof(final_hash));
  boot_secure_zeroize(exp_hash, sizeof(exp_hash));
  BOOT_SECURE_REQUIRE(match == BOOT_OK, { return BOOT_ERR_VERIFY; });

  return BOOT_OK;
}

boot_status_t boot_multiimage_apply(const boot_platform_t *platform, uint32_t staging_base,
                                    const boot_component_t *components, uint32_t num_components,
                                    const boot_allowed_region_t *whitelist, uint32_t num_regions,
                                    wal_entry_payload_t *open_txn, uint8_t *arena,
                                    size_t arena_len) {
  if (!arena || arena_len < 1024) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (!platform || !platform->flash || !platform->crypto || !platform->wdt || !components ||
      !whitelist || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (num_components == 0) {
    return BOOT_OK;
  }

  if (num_components > 256) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint32_t mi_cfi_seed = 0U;
  boot_status_t rnd_st = boot_random_safe(platform, (uint8_t *)&mi_cfi_seed, sizeof(mi_cfi_seed));
  if (rnd_st != BOOT_OK) {
    return rnd_st;
  }
  boot_cfi_ctx_t multi_cfi_ctx;
  boot_cfi_init(multi_cfi_ctx, mi_cfi_seed);
  boot_cfi_add_expected(multi_cfi_ctx, MI_CFI_SLOT_BOUNDS);
  for (uint32_t i = 0; i < num_components; i++) {
    multi_cfi_ctx.expected_val =
        boot_cfi_mix_val(multi_cfi_ctx.expected_val, ~components[i].component_id);
  }
  boot_cfi_add_expected(multi_cfi_ctx, MI_CFI_SLOT_COMPLETE);

  boot_status_t final_status = BOOT_ERR_VERIFY;

  bool bounds_violation = false;
  bool id_violation = false;
  uint32_t seen_comp_ids = 0U;
  for (uint32_t i = 0; i < num_components; i++) {
    if (!is_target_whitelisted(components[i].target_addr, components[i].image_size, whitelist,
                               num_regions)) {
      bounds_violation = true;
      break;
    }
    if (UINT32_MAX - staging_base < components[i].staging_offset ||
        UINT32_MAX - (staging_base + components[i].staging_offset) < components[i].image_size) {
      bounds_violation = true;
      break;
    }
    if (components[i].image_size > 0U) {
      if (components[i].component_id >= 32U) {
        id_violation = true;
        break;
      }
      uint32_t cid_mask = 1U << components[i].component_id;
      if ((seen_comp_ids & cid_mask) != 0U) {
        id_violation = true;
        break;
      }
      seen_comp_ids |= cid_mask;
    }
  }

  BOOT_SECURE_REQUIRE(!bounds_violation, { return BOOT_ERR_FLASH_BOUNDS; });
  if (id_violation) {
    return BOOT_ERR_INVALID_ARG;
  }

  boot_cfi_step(multi_cfi_ctx, MI_CFI_SLOT_BOUNDS);

  if (!platform->crypto->get_hash_ctx_size) {
    return BOOT_ERR_NOT_SUPPORTED;
  }
  size_t ctx_size = platform->crypto->get_hash_ctx_size();
  if (ctx_size > 256) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint8_t *hash_ctx = arena;
  uint8_t *stream_buf = arena + 256;
  size_t stream_max = arena_len - 256;
  size_t half_stream = stream_max / 2;

  for (uint32_t i = 0; i < num_components; i++) {
    boot_component_t comp __attribute__((aligned(8)));
    boot_secure_zeroize(&comp, sizeof(comp));
    memcpy(&comp, &components[i], sizeof(boot_component_t));

    if (comp.image_size == 0) {
      multi_cfi_ctx.current_val = boot_cfi_mix_val(multi_cfi_ctx.current_val, ~comp.component_id);
      continue;
    }

    /* CRIT-30: Restrict multi-image checkpoint bits to transfer_bitmap[0] so
     * indices [1..7] remain exclusively reserved for swap/SDVM metadata. */
    if (comp.component_id >= 32U) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto multi_cleanup;
    }

    uint32_t bitmap_idx = comp.component_id / 32;
    uint32_t bit_mask = 1U << (comp.component_id % 32);

    if ((open_txn->transfer_bitmap[bitmap_idx] & bit_mask) != 0) {
      multi_cfi_ctx.current_val = boot_cfi_mix_val(multi_cfi_ctx.current_val, ~comp.component_id);
      continue;
    }

    /* Verify-Before-Commit: stream-verify staging payload before erasing/programming destination. */
    final_status =
        verify_component_digest_at_addr(platform, &comp, staging_base + comp.staging_offset,
                                        hash_ctx, ctx_size, stream_buf, half_stream);
    if (final_status != BOOT_OK) {
      goto multi_cleanup;
    }

    uint32_t src_crc = 0;
    final_status = boot_crc32_flash_stream(platform, staging_base + comp.staging_offset,
                                           comp.image_size, &src_crc, stream_buf, half_stream);
    if (final_status != BOOT_OK) {
      goto multi_cleanup;
    }

    flash_effect_t fx[2];
    size_t planned_n = 0;
    final_status =
        boot_multiimage_plan_component(platform, staging_base, &comp, src_crc, fx, 2, &planned_n);
    if (final_status != BOOT_OK) {
      goto multi_cleanup;
    }

    final_status = boot_effect_execute(platform, fx, planned_n, whitelist, num_regions, stream_buf,
                                       half_stream);
    if (final_status != BOOT_OK) {
      goto multi_cleanup;
    }

    /* Post-write read-back SHA-256 verification against destination slot */
    final_status = verify_component_digest_at_addr(platform, &comp, comp.target_addr, hash_ctx,
                                                   ctx_size, stream_buf, half_stream);
    if (final_status != BOOT_OK) {
      goto multi_cleanup;
    }

    open_txn->transfer_bitmap[bitmap_idx] |= bit_mask;
    final_status = boot_journal_append(platform, open_txn);
    if (final_status != BOOT_OK) {
      goto multi_cleanup;
    }

    multi_cfi_ctx.current_val = boot_cfi_mix_val(multi_cfi_ctx.current_val, ~comp.component_id);
  }

  boot_cfi_step(multi_cfi_ctx, MI_CFI_SLOT_COMPLETE);

  boot_cfi_require(multi_cfi_ctx, {
    final_status = BOOT_ERR_INVALID_STATE;
    goto multi_cleanup;
  });
  final_status = BOOT_OK;

multi_cleanup:
  boot_secure_zeroize(arena, arena_len);
  return final_status;
}

boot_status_t boot_multiimage_plan_component(const boot_platform_t *platform, uint32_t staging_base,
                                             const boot_component_t *comp, uint32_t src_crc,
                                             flash_effect_t *out_fx, size_t cap, size_t *n_out) {
  if (!comp || !out_fx || !n_out || cap < 2U) {
    return BOOT_ERR_INVALID_ARG;
  }

  boot_status_t s1_st = validate_stage1_component_image(platform, staging_base, comp);
  if (s1_st != BOOT_OK) {
    return s1_st;
  }

  out_fx[0].op = EFF_ERASE;
  out_fx[0].src = 0;
  out_fx[0].dst = comp->target_addr;
  out_fx[0].len = comp->image_size;
  out_fx[0].post_crc = boot_effect_compute_erased_crc(comp->image_size);

  out_fx[1].op = EFF_COPY;
  out_fx[1].src = staging_base + comp->staging_offset;
  out_fx[1].dst = comp->target_addr;
  out_fx[1].len = comp->image_size;
  out_fx[1].post_crc = src_crc;

  *n_out = 2;
  return BOOT_OK;
}

#else /* !TOOB_FEATURE_MULTIIMAGE */

boot_status_t boot_multiimage_apply(const boot_platform_t *platform, uint32_t staging_base,
                                    const boot_component_t *components, uint32_t num_components,
                                    const boot_allowed_region_t *whitelist, uint32_t num_regions,
                                    wal_entry_payload_t *open_txn, uint8_t *arena,
                                    size_t arena_len) {
  (void)staging_base;
  (void)num_components;
  (void)num_regions;
  if (!arena || arena_len < 1024U || !platform || !components || !whitelist || !open_txn) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_ERR_NOT_SUPPORTED;
}

boot_status_t boot_multiimage_plan_component(const boot_platform_t *platform, uint32_t staging_base,
                                             const boot_component_t *comp, uint32_t src_crc,
                                             flash_effect_t *out_fx, size_t cap, size_t *n_out) {
  (void)platform;
  (void)staging_base;
  (void)src_crc;
  if (!comp || !out_fx || !n_out || cap < 2U) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_ERR_NOT_SUPPORTED;
}

#endif /* TOOB_FEATURE_MULTIIMAGE */
