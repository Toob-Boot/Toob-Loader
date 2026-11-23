/**
 * @file boot_cloud_cmd.c
 * @brief Implementierung der Cloud-Command Verifikation & Execution Pipeline.
 *
 * Architektur-Direktiven:
 * - Zero-Allocation Pre-Auth TCC1 Parsing via crypto_arena
 * - Glitch-Resistant Command Evaluation (Double-Check Pattern + CFI)
 * - TOCTOU Defense (Single Flash Read + Stack Header Snapshot)
 * - Exhaustion Defense (Counter Advance strictly POST-Signature)
 * - KDM Quorum-Store (Phase 4: 3-fach quorum-geschützt via boot_rstore)
 */

#include "boot_cloud_cmd.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_features.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_identity.h"
#include "boot_journal.h"
#include "boot_rstore.h"
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include <string.h>

#if TOOB_FEATURE_CLOUD_COMMANDS

/* Die Adressen müssen zwingend aus der vom Manifest Compiler generierten Config kommen. */
#ifndef CHIP_CLOUD_CMD_SLOT_ABS_ADDR
#error "CHIP_CLOUD_CMD_SLOT_ABS_ADDR is required by the bootloader but not provided by the layout!"
#endif

#ifndef CHIP_CLOUD_CMD_SLOT_SIZE
#error "CHIP_CLOUD_CMD_SLOT_SIZE is required by the bootloader but not provided by the layout!"
#endif

#ifndef CHIP_KDM_QUORUM_ABS_ADDR
#error "CHIP_KDM_QUORUM_ABS_ADDR is required by the bootloader but not provided by the layout!"
#endif

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define CMD_CFI_SLOT_INIT 0
#define CMD_CFI_SLOT_PARSE 1
#define CMD_CFI_SLOT_VERIFY 2
#define CMD_CFI_SLOT_ID 3
#define CMD_CFI_SLOT_COUNTER 4
#define CMD_CFI_NUM_TOKENS 5

/* Phase 4: KDM Quorum Store Descriptor */
#define KDM_QUORUM_SLOT_COUNT 3U
#define KDM_RSTORE_MAGIC 0x4B444D51U /* "KDMQ" */

#ifdef TOOB_KDM_SLOT_ADDRS
static const uint32_t kdm_slot_addrs[KDM_QUORUM_SLOT_COUNT] = TOOB_KDM_SLOT_ADDRS;
#else
static const uint32_t kdm_slot_addrs[KDM_QUORUM_SLOT_COUNT] = {
    CHIP_KDM_QUORUM_ABS_ADDR,
    CHIP_KDM_QUORUM_ABS_ADDR + (CHIP_KDM_QUORUM_SIZE / KDM_QUORUM_SLOT_COUNT),
    CHIP_KDM_QUORUM_ABS_ADDR + 2U * (CHIP_KDM_QUORUM_SIZE / KDM_QUORUM_SLOT_COUNT)};
#endif

#ifdef TOOB_KDM_SLOT_SIZES
static const size_t kdm_slot_sizes[KDM_QUORUM_SLOT_COUNT] = TOOB_KDM_SLOT_SIZES;
#else
static const size_t kdm_slot_sizes[KDM_QUORUM_SLOT_COUNT] = {
    (CHIP_KDM_QUORUM_SIZE / KDM_QUORUM_SLOT_COUNT), (CHIP_KDM_QUORUM_SIZE / KDM_QUORUM_SLOT_COUNT),
    (CHIP_KDM_QUORUM_SIZE / KDM_QUORUM_SLOT_COUNT)};
#endif
static const boot_rstore_desc_t kdm_rstore_desc = {.slot_addrs = kdm_slot_addrs,
                                                   .slot_sizes = kdm_slot_sizes,
                                                   .slot_count = KDM_QUORUM_SLOT_COUNT,
                                                   .record_size = sizeof(toob_kdm_t),
                                                   .magic = KDM_RSTORE_MAGIC};

/**
 * @brief Verifies a KDM record against the active contiguous OTP root key.
 */
static boot_status_t verify_kdm_against_active_root(const boot_platform_t *platform,
                                                    const toob_kdm_t *kdm) {
  uint8_t active_idx = 0U;
  boot_status_t stat = boot_otp_get_active_key_index(platform, &active_idx);
  if (stat != BOOT_OK) {
    return stat;
  }

  uint8_t root_pubkey[32] __attribute__((aligned(8)));
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  if (platform->keystore->read_pubkey(root_pubkey, sizeof(root_pubkey), active_idx) != BOOT_OK) {
    boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
    return BOOT_ERR_NOT_FOUND;
  }

  if (verify_not_all_zeros_glitch_safe(root_pubkey, sizeof(root_pubkey)) != BOOT_OK ||
      verify_not_all_zeros_glitch_safe(kdm->new_cloud_pubkey, sizeof(kdm->new_cloud_pubkey)) !=
          BOOT_OK) {
    boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
    return BOOT_ERR_VERIFY;
  }

  boot_status_t sig_stat = platform->crypto->verify_signature(
      (const uint8_t *)kdm, offsetof(toob_kdm_t, signature_ed25519), kdm->signature_ed25519,
      root_pubkey);
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));

  BOOT_SECURE_REQUIRE(sig_stat == BOOT_OK, { return BOOT_ERR_VERIFY; });
  if (boot_secure_confirm(sig_stat) != BOOT_OK) {
    return BOOT_ERR_VERIFY;
  }
  return BOOT_OK;
}

/**
 * @brief Lädt den aktiven Cloud-Public-Key via KDM Quorum-Store.
 *
 * Phase 4: Replaces the old A/B-Slot logic with boot_rstore_read.
 * Self-healing of defective slots is handled by boot_rstore_read internally.
 */
static boot_status_t load_active_cloud_key(const boot_platform_t *platform, uint8_t *out_pubkey,
                                           uint32_t *out_seq) {
  if (!platform || !platform->crypto || !platform->keystore || !platform->flash) {
    return BOOT_ERR_INVALID_ARG;
  }

  wal_tmr_payload_t tmr;
  boot_secure_zeroize(&tmr, sizeof(tmr));
  bool has_tmr = (boot_journal_get_tmr(platform, &tmr) == BOOT_OK);
  uint32_t tmr_kdm_floor = has_tmr ? tmr.kdm_seq_floor : 0U;
  boot_secure_zeroize(&tmr, sizeof(tmr));

  /* Read KDM via 3-way quorum (with bounded opportunistic healing) */
  toob_kdm_t kdm;
  boot_secure_zeroize(&kdm, sizeof(kdm));
  boot_status_t stat = boot_rstore_read(platform, &kdm_rstore_desc, &kdm);

  if (stat == BOOT_OK) {
    if (kdm.sequence_number >= tmr_kdm_floor &&
        verify_kdm_against_active_root(platform, &kdm) == BOOT_OK) {
      memcpy(out_pubkey, kdm.new_cloud_pubkey, sizeof(kdm.new_cloud_pubkey));
      *out_seq = kdm.sequence_number;
      boot_secure_zeroize(&kdm, sizeof(kdm));
      return BOOT_OK;
    }

    boot_secure_zeroize(&kdm, sizeof(kdm));
  }

  /* Fallback auf eFuse-Slot 1 NUR erlaubt im Initial Provisioning State (DSLC == 0 und Floor == 0). */
  uint8_t dslc_val = 0U;
  size_t dslc_len = 1U;
  if (tmr_kdm_floor == 0U && platform->keystore->read_dslc &&
      platform->keystore->read_dslc(&dslc_val, &dslc_len) == BOOT_OK) {
    if (dslc_len > 0U && dslc_val == 0x00U) {
      if (platform->keystore->read_pubkey &&
          platform->keystore->read_pubkey(out_pubkey, 32U, 1U) == BOOT_OK &&
          verify_not_all_zeros_glitch_safe(out_pubkey, 32U) == BOOT_OK) {
        *out_seq = 0U;
        return BOOT_OK;
      }
    }
  }
  return BOOT_ERR_NOT_FOUND;
}

boot_status_t boot_cloud_cmd_evaluate_buffer(const boot_platform_t *platform,
                                             const uint8_t *envelope_buf, size_t envelope_len,
                                             uint8_t *crypto_arena, toob_cloud_cmd_t *out_cmd) {
  if (!platform || !platform->crypto || !platform->keystore || !envelope_buf || !crypto_arena ||
      !out_cmd) {
    return BOOT_ERR_INVALID_ARG;
  }
  (void)crypto_arena;

  if (!platform->keystore->read_pubkey || !platform->crypto->verify_signature) {
    return BOOT_ERR_NOT_SUPPORTED;
  }

  boot_status_t final_status = BOOT_ERR_VERIFY;
  toob_cloud_cmd_hdr_t hdr;
  toob_cloud_cmd_envelope_t decoded;
  boot_secure_zeroize(&hdr, sizeof(hdr));
  boot_secure_zeroize(&decoded, sizeof(decoded));

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t cmd_cfi_seed = 0U;
  boot_status_t rng_stat =
      boot_random_safe(platform, (uint8_t *)&cmd_cfi_seed, sizeof(cmd_cfi_seed));
  if (rng_stat != BOOT_OK) {
    final_status = (rng_stat == BOOT_ERR_NOT_SUPPORTED) ? BOOT_ERR_CRYPTO : rng_stat;
    goto cleanup;
  }
  boot_cfi_ctx_t cmd_cfi_ctx;
  boot_cfi_init(cmd_cfi_ctx, cmd_cfi_seed);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_PARSE);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_VERIFY);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_ID);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_COUNTER);

  /* 1. Fixed TCC1 Header Pre-Check (Zero variable-length parsing pre-auth!) */
  if (envelope_len < TOOB_CLOUD_CMD_MIN_SIZE) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  memcpy(&hdr, envelope_buf, sizeof(hdr));

  if (hdr.magic == 0xFFFFFFFFU) {
    final_status = BOOT_ERR_NOT_FOUND;
    goto cleanup;
  }

  if (hdr.magic != TOOB_CLOUD_CMD_MAGIC || hdr.version != TOOB_CLOUD_CMD_VERSION ||
      hdr.flags != 0U || hdr._reserved != 0U) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (hdr.total_len < TOOB_CLOUD_CMD_MIN_SIZE || hdr.total_len > TOOB_CLOUD_CMD_MAX_SIZE ||
      (hdr.total_len % TOOB_CLOUD_CMD_ALIGN) != 0U || (size_t)hdr.total_len > envelope_len) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (hdr.params_len > TOOB_CLOUD_CMD_MAX_PARAMS) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  uint32_t aligned_plen = TOOB_CLOUD_CMD_ALIGN_UP(hdr.params_len);
  if ((TOOB_CLOUD_CMD_HDR_SIZE + aligned_plen + TOOB_CLOUD_CMD_SIG_SIZE) != hdr.total_len) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  uint32_t hdr_crc = compute_boot_crc32((const uint8_t *)&hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);
  if (hdr_crc != hdr.crc32) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_PARSE);

  /* 2. TRUE Pre-Auth Ed25519 Signature Verification over [0 .. total_len - 64) */
  uint8_t cloud_pubkey[32] __attribute__((aligned(8)));
  uint32_t kdm_seq = 0U;
  boot_secure_zeroize(cloud_pubkey, sizeof(cloud_pubkey));

  if (load_active_cloud_key(platform, cloud_pubkey, &kdm_seq) != BOOT_OK) {
    boot_secure_zeroize(cloud_pubkey, sizeof(cloud_pubkey));
    final_status = BOOT_ERR_NOT_FOUND;
    goto cleanup;
  }

  size_t sig_payload_len = (size_t)hdr.total_len - TOOB_CLOUD_CMD_SIG_SIZE;
  const uint8_t *sig_ptr = envelope_buf + sig_payload_len;

  if (platform->wdt && platform->wdt->kick) {
    platform->wdt->kick();
  }
  boot_status_t sig_stat =
      platform->crypto->verify_signature(envelope_buf, sig_payload_len, sig_ptr, cloud_pubkey);
  if (platform->wdt && platform->wdt->kick) {
    platform->wdt->kick();
  }

  boot_secure_zeroize(cloud_pubkey, sizeof(cloud_pubkey));

  if (boot_secure_confirm(sig_stat) != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  /* Populate authenticated command view ONLY AFTER signature is proven */
  memcpy(decoded.device_id, hdr.device_id, sizeof(decoded.device_id));
  decoded.command = hdr.command;
  decoded.counter_min = hdr.counter_min;
  decoded.issued_at = hdr.issued_at;
  decoded.params_len = (size_t)hdr.params_len;
  decoded.params = (hdr.params_len > 0U) ? (envelope_buf + TOOB_CLOUD_CMD_HDR_SIZE) : NULL;
  memcpy(decoded.signature_ed25519, sig_ptr, TOOB_CLOUD_CMD_SIG_SIZE);

  if (decoded.command > (uint8_t)TOOB_CMD_REVOKE) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_VERIFY);

  /* 3. Device-ID Match (Glitch-Safe) */
  uint8_t local_id[32];
  boot_secure_zeroize(local_id, sizeof(local_id));
  if (boot_derive_device_id(platform, local_id) != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  boot_status_t id_match =
      constant_time_memcmp_glitch_safe(decoded.device_id, local_id, sizeof(local_id));
  boot_secure_zeroize(local_id, sizeof(local_id));

  if (boot_secure_confirm(id_match) != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }
  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_ID);

  /* 4. Anti-Replay Counter & Freshness Check */
  if (!platform->keystore->advance_monotonic_counter) {
    final_status = BOOT_ERR_NOT_SUPPORTED;
    goto cleanup;
  }
  uint32_t current_counter = 0U;
  boot_status_t cnt_stat = boot_read_monotonic_counter_safe(platform, &current_counter);
  if (cnt_stat != BOOT_OK) {
    final_status = cnt_stat;
    goto cleanup;
  }

  BOOT_SECURE_REQUIRE(decoded.counter_min > current_counter, {
    final_status = BOOT_ERR_DOWNGRADE;
    goto cleanup;
  });

  /* Freshness Check (UPD-006): Reject stale commands whose issued_at
   * is not strictly greater than the last accepted value. */
  {
    wal_tmr_payload_t freshness_tmr;
    boot_secure_zeroize(&freshness_tmr, sizeof(freshness_tmr));
    boot_status_t tmr_stat = boot_journal_get_tmr(platform, &freshness_tmr);
    uint32_t last_accepted = 0U;
    if (tmr_stat == BOOT_OK) {
      last_accepted = freshness_tmr.last_accepted_issued_at;
    }
    boot_secure_zeroize(&freshness_tmr, sizeof(freshness_tmr));

    BOOT_SECURE_REQUIRE(decoded.issued_at > last_accepted, {
      final_status = BOOT_ERR_CMD_REPLAY;
      goto cleanup;
    });
  }

  uint32_t burns_needed = decoded.counter_min - current_counter;

  /* UPD-006: Hard cap — a single command must never burn more than
   * TOOB_CMD_MAX_BURN_STEPS OTP bits. */
  if (burns_needed > TOOB_CMD_MAX_BURN_STEPS) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_COUNTER);

  /* 5. Exhaustion Defense: Advance Counter ONLY after signature, ID & freshness checks */
  for (uint32_t i = 0U; i < burns_needed; i++) {
    boot_status_t burn_stat = platform->keystore->advance_monotonic_counter();

    if (boot_secure_confirm(burn_stat) != BOOT_OK) {
      final_status = BOOT_ERR_FLASH_HW;
      goto cleanup;
    }
  }

  /* 6. CFI Resolution & Dispatch */
  boot_cfi_require(cmd_cfi_ctx, {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  });

  /* 7. ROTATE_KEY: Atomic KDM Write (Module-Owner Principle) */
  uint32_t accepted_kdm_seq = 0U;
  bool update_kdm_floor = false;
  if ((toob_cloud_cmd_t)decoded.command == TOOB_CMD_ROTATE_KEY) {
    if (decoded.params == NULL || decoded.params_len != sizeof(toob_kdm_t)) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    toob_kdm_t new_kdm;
    boot_secure_zeroize(&new_kdm, sizeof(new_kdm));
    memcpy(&new_kdm, decoded.params, sizeof(toob_kdm_t));

    if (verify_kdm_against_active_root(platform, &new_kdm) != BOOT_OK) {
      boot_secure_zeroize(&new_kdm, sizeof(new_kdm));
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    /* Anti-Replay: New KDM sequence must be > max(rstore, K4-TMR floor). */
    uint32_t current_kdm_seq = 0U;
    toob_kdm_t current_kdm;
    boot_secure_zeroize(&current_kdm, sizeof(current_kdm));
    if (boot_rstore_read(platform, &kdm_rstore_desc, &current_kdm) == BOOT_OK) {
      current_kdm_seq = current_kdm.sequence_number;
    }
    boot_secure_zeroize(&current_kdm, sizeof(current_kdm));

    wal_tmr_payload_t floor_tmr;
    boot_secure_zeroize(&floor_tmr, sizeof(floor_tmr));
    if (boot_journal_get_tmr(platform, &floor_tmr) == BOOT_OK &&
        floor_tmr.kdm_seq_floor > current_kdm_seq) {
      current_kdm_seq = floor_tmr.kdm_seq_floor;
    }
    boot_secure_zeroize(&floor_tmr, sizeof(floor_tmr));

    if (new_kdm.sequence_number <= current_kdm_seq) {
      boot_secure_zeroize(&new_kdm, sizeof(new_kdm));
      final_status = BOOT_ERR_DOWNGRADE;
      goto cleanup;
    }

    accepted_kdm_seq = new_kdm.sequence_number;
    boot_status_t write_stat = boot_rstore_write(platform, &kdm_rstore_desc, &new_kdm);
    boot_secure_zeroize(&new_kdm, sizeof(new_kdm));

    if (write_stat != BOOT_OK) {
      final_status = write_stat;
      goto cleanup;
    }
    update_kdm_floor = true;
  }

  *out_cmd = (toob_cloud_cmd_t)decoded.command;
  final_status = BOOT_OK;

  /* UPD-006 / HIGH-104: Persist accepted issued_at & KDM floor into K4-MAC'd TMR. */
  {
    wal_tmr_payload_t persist_tmr;
    boot_secure_zeroize(&persist_tmr, sizeof(persist_tmr));
    if (boot_journal_get_tmr(platform, &persist_tmr) == BOOT_OK) {
      persist_tmr.last_accepted_issued_at = decoded.issued_at;
      if (update_kdm_floor && accepted_kdm_seq > persist_tmr.kdm_seq_floor) {
        persist_tmr.kdm_seq_floor = accepted_kdm_seq;
      }
      persist_tmr.struct_version = WAL_TMR_VERSION_CURRENT;
      persist_tmr.populated_size = WAL_TMR_POPULATED_SIZE;
      boot_status_t tmr_stat = boot_journal_update_tmr(platform, &persist_tmr);
      if (tmr_stat != BOOT_OK) {
        final_status = tmr_stat;
      }
    }
    boot_secure_zeroize(&persist_tmr, sizeof(persist_tmr));
  }

cleanup:
  boot_secure_zeroize(&hdr, sizeof(hdr));
  boot_secure_zeroize(&decoded, sizeof(decoded));
  return final_status;
}

boot_status_t boot_cloud_cmd_evaluate_flash(const boot_platform_t *platform, uint8_t *crypto_arena,
                                            toob_cloud_cmd_t *out_cmd) {
  if (!platform || !platform->flash || !crypto_arena || !out_cmd) {
    return BOOT_ERR_INVALID_ARG;
  }

  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  /* TOCTOU Defense: Einmaliges Einlesen in SRAM! (Gap 5) */
  _Static_assert(BOOT_CRYPTO_ARENA_SIZE > 256U,
                 "BOOT_CRYPTO_ARENA_SIZE must exceed 256B work zone");
  const size_t arena_env_cap = BOOT_CRYPTO_ARENA_SIZE - 256U;
  size_t max_read =
      (arena_env_cap > CHIP_CLOUD_CMD_SLOT_SIZE) ? CHIP_CLOUD_CMD_SLOT_SIZE : arena_env_cap;

  boot_status_t read_stat =
      platform->flash->read(CHIP_CLOUD_CMD_SLOT_ABS_ADDR, crypto_arena, max_read);
  if (read_stat != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    return read_stat;
  }

  /* Parse from SRAM buffer */
  size_t envelope_zone = max_read;
  size_t work_zone_offset = (envelope_zone + 7U) & ~((size_t)7U); /* 8-Byte align */
  if (work_zone_offset + 256U > BOOT_CRYPTO_ARENA_SIZE) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    return BOOT_ERR_INVALID_ARG;
  }
  uint8_t *work_arena = crypto_arena + work_zone_offset;

  /* P10 FIX: Aliasing-Verbot! envelope_buf und work_buffer dürfen nicht
   * identisch sein. */
  boot_status_t result =
      boot_cloud_cmd_evaluate_buffer(platform, crypto_arena, max_read, work_arena, out_cmd);

  /* Zero-Allocation Wipe */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  return result;
}

#else /* !TOOB_FEATURE_CLOUD_COMMANDS */

boot_status_t boot_cloud_cmd_evaluate_buffer(const boot_platform_t *platform,
                                             const uint8_t *envelope_buf, size_t envelope_len,
                                             uint8_t *crypto_arena, toob_cloud_cmd_t *out_cmd) {
  (void)envelope_len;
  if (!platform || !platform->crypto || !platform->keystore || !envelope_buf || !crypto_arena ||
      !out_cmd) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_ERR_NOT_SUPPORTED;
}

boot_status_t boot_cloud_cmd_evaluate_flash(const boot_platform_t *platform, uint8_t *crypto_arena,
                                            toob_cloud_cmd_t *out_cmd) {
  if (!platform || !platform->flash || !crypto_arena || !out_cmd) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_ERR_NOT_SUPPORTED;
}

#endif /* TOOB_FEATURE_CLOUD_COMMANDS */
