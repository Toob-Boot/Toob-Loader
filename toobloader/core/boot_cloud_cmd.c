/**
 * @file boot_cloud_cmd.c
 * @brief Implementierung der Cloud-Command Verifikation & Execution Pipeline.
 *
 * Architektur-Direktiven:
 * - Zero-Allocation Parsing via crypto_arena
 * - Glitch-Resistant Command Evaluation (Double-Check Pattern + CFI)
 * - TOCTOU Defense (Single Flash Read)
 * - Exhaustion Defense (Counter Advance strictly POST-Signature)
 * - KDM Quorum-Store (Phase 4: 3-fach quorum-geschützt via boot_rstore)
 */

#include "boot_cloud_cmd.h"
#include "boot_fih.h"
#include "boot_ct_utils.h"
#include "boot_identity.h"
#include "boot_rstore.h"
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include <string.h>

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

/* Die vom zcbor Generator erstellten Prototypen für das CDDL-Parsing */
extern int cbor_decode_toob_cloud_cmd(const uint8_t *payload,
                                      size_t payload_len,
                                      toob_cloud_cmd_envelope_t *result,
                                      size_t *payload_len_out);

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define CMD_CFI_SLOT_INIT    0
#define CMD_CFI_SLOT_PARSE   1
#define CMD_CFI_SLOT_ID      2
#define CMD_CFI_SLOT_COUNTER 3
#define CMD_CFI_SLOT_VERIFY  4
#define CMD_CFI_NUM_TOKENS   5

/* Phase 4: KDM Quorum Store Descriptor */
#define KDM_QUORUM_SLOT_COUNT 3
#define KDM_RSTORE_MAGIC 0x4B444D51 /* "KDMQ" */

static const uint32_t kdm_slot_addrs[KDM_QUORUM_SLOT_COUNT] = {
    CHIP_KDM_QUORUM_ABS_ADDR,
    CHIP_KDM_QUORUM_ABS_ADDR + CHIP_FLASH_MAX_SECTOR_SIZE,
    CHIP_KDM_QUORUM_ABS_ADDR + 2 * CHIP_FLASH_MAX_SECTOR_SIZE};
static const size_t kdm_slot_sizes[KDM_QUORUM_SLOT_COUNT] = {
    CHIP_FLASH_MAX_SECTOR_SIZE, CHIP_FLASH_MAX_SECTOR_SIZE,
    CHIP_FLASH_MAX_SECTOR_SIZE};
static const boot_rstore_desc_t kdm_rstore_desc = {
    .slot_addrs = kdm_slot_addrs,
    .slot_sizes = kdm_slot_sizes,
    .slot_count = KDM_QUORUM_SLOT_COUNT,
    .record_size = sizeof(toob_kdm_t),
    .magic = KDM_RSTORE_MAGIC};

/**
 * @brief Lädt den aktiven Cloud-Public-Key via KDM Quorum-Store.
 *
 * Phase 4: Replaces the old A/B-Slot logic with boot_rstore_read.
 * Self-healing of defective slots is handled by boot_rstore_read internally.
 */
static boot_status_t load_active_cloud_key(const boot_platform_t *platform,
                                           uint8_t *out_pubkey,
                                           uint32_t *out_seq) {
  if (!platform || !platform->crypto || !platform->flash)
    return BOOT_ERR_INVALID_ARG;

  /* Read KDM via 3-way quorum (with bounded opportunistic healing) */
  toob_kdm_t kdm;
  boot_secure_zeroize(&kdm, sizeof(kdm));
  boot_status_t stat = boot_rstore_read(platform, &kdm_rstore_desc, &kdm);

  if (stat == BOOT_OK) {
    /* Root-Key für Signaturprüfung laden */
    uint8_t root_pubkey[32] __attribute__((aligned(8)));
    boot_secure_zeroize(root_pubkey, 32);
    if (platform->crypto->read_pubkey(root_pubkey, 32, 0) != BOOT_OK) {
      boot_secure_zeroize(&kdm, sizeof(kdm));
      return BOOT_ERR_NOT_FOUND;
    }

    /* Zero-Key Forgery Defense */
    if (verify_not_all_zeros_glitch_safe(root_pubkey, 32) != BOOT_OK) {
      boot_secure_zeroize(root_pubkey, 32);
      boot_secure_zeroize(&kdm, sizeof(kdm));
      return BOOT_ERR_VERIFY;
    }

    /* Verify KDM signature against Root Key */
    boot_status_t sig_stat = platform->crypto->verify_signature(
        (const uint8_t *)&kdm, offsetof(toob_kdm_t, signature_ed25519),
        kdm.signature_ed25519, root_pubkey);
    boot_secure_zeroize(root_pubkey, 32);

    if (boot_secure_confirm(sig_stat) == BOOT_OK) {
      memcpy(out_pubkey, kdm.new_cloud_pubkey, 32);
      *out_seq = kdm.sequence_number;
      boot_secure_zeroize(&kdm, sizeof(kdm));
      return BOOT_OK;
    }

    boot_secure_zeroize(&kdm, sizeof(kdm));
  }

  /* Fallback auf eFuse-Slot 1 NUR erlaubt im Initial Provisioning State.
   * P10 SECURITY FIX: Verhindert Downgrade-Attacken durch absichtliches
   * Zerstören der Flash-Slots. Wenn das Gerät provisioniert ist (DSLC >
   * 0), ist der Fallback verboten! */
  uint8_t dslc_val = 0;
  size_t dslc_len = 1;
  if (platform->crypto->read_dslc &&
      platform->crypto->read_dslc(&dslc_val, &dslc_len) == BOOT_OK) {
    if (dslc_val == 0x00) {
      if (platform->crypto->read_pubkey(out_pubkey, 32, 1) == BOOT_OK) {
        *out_seq = 0;
        return BOOT_OK;
      }
    }
  }
  return BOOT_ERR_NOT_FOUND;
}

boot_status_t boot_cloud_cmd_evaluate_buffer(const boot_platform_t *platform,
                                             const uint8_t *envelope_buf,
                                             size_t envelope_len,
                                             uint8_t *crypto_arena,
                                             toob_cloud_cmd_t *out_cmd) {
  boot_status_t final_status = BOOT_ERR_VERIFY;

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t cmd_cfi_seed = 0;
  boot_random_safe(platform, (uint8_t *)&cmd_cfi_seed, sizeof(cmd_cfi_seed));
  boot_cfi_ctx_t cmd_cfi_ctx;
  boot_cfi_init(cmd_cfi_ctx, cmd_cfi_seed);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_PARSE);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_ID);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_COUNTER);
  boot_cfi_add_expected(cmd_cfi_ctx, CMD_CFI_SLOT_VERIFY);

  if (!platform || !platform->crypto || !envelope_buf || !crypto_arena ||
      !out_cmd) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* 1. Parse CBOR Envelope */
  toob_cloud_cmd_envelope_t decoded;
  boot_secure_zeroize(&decoded, sizeof(decoded));
  size_t decoded_len = 0;

  if (cbor_decode_toob_cloud_cmd(envelope_buf, envelope_len, &decoded,
                                 &decoded_len) != 0) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }
  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_PARSE);

  /* 2. Device-ID Match (Glitch-Safe) */
  uint8_t local_id[32];
  boot_secure_zeroize(local_id, 32);
  if (boot_derive_device_id(platform, local_id) != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  boot_status_t id_match =
      constant_time_memcmp_glitch_safe(decoded.device_id, local_id, 32);
  boot_secure_zeroize(local_id, 32);

  if (boot_secure_confirm(id_match) != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }
  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_ID);

  /* 3. Anti-Replay Counter Check */
  if (!platform->crypto->advance_monotonic_counter) {
    final_status = BOOT_ERR_NOT_SUPPORTED;
    goto cleanup;
  }
  uint32_t current_counter = 0;
  boot_status_t cnt_stat = boot_read_monotonic_counter_safe(platform, &current_counter);
  if (cnt_stat != BOOT_OK) {
      final_status = cnt_stat;
      goto cleanup;
  }

  BOOT_SECURE_REQUIRE(decoded.counter_min > current_counter, {
    final_status = BOOT_ERR_DOWNGRADE;
    goto cleanup;
  });
  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_COUNTER);

  /* 4. Signature Verification */
  uint8_t cloud_pubkey[32] __attribute__((aligned(8)));
  uint32_t kdm_seq = 0;
  boot_secure_zeroize(cloud_pubkey, 32);

  if (load_active_cloud_key(platform, cloud_pubkey, &kdm_seq) != BOOT_OK) {
    boot_secure_zeroize(cloud_pubkey, 32);
    final_status = BOOT_ERR_NOT_FOUND;
    goto cleanup;
  }

  /* P6 FIX: Signierte Region basiert auf dem CBOR-dekodierten Ergebnis, nicht
   * auf dem Pufferrand. Key 101 (2B) + bstr .size 64 Header (2B) + 64B
   * Signatur = 68 Bytes fixer CBOR-Overhead für das Signaturfeld. Die zu
   * verifizierende Region ist alles VOR diesem Feld im dekodierten Stream. */
#define CLOUD_CMD_SIG_CBOR_SIZE (2 + 2 + 64) /* key(101) + bstr_hdr(.size 64) + payload */
  if (decoded_len <= CLOUD_CMD_SIG_CBOR_SIZE) {
    boot_secure_zeroize(cloud_pubkey, 32);
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }
  size_t sig_payload_len = decoded_len - CLOUD_CMD_SIG_CBOR_SIZE;

  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  boot_status_t sig_stat = platform->crypto->verify_signature(
      envelope_buf, sig_payload_len, decoded.signature_ed25519, cloud_pubkey);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  boot_secure_zeroize(cloud_pubkey, 32); /* Wipe key immediately */

  if (boot_secure_confirm(sig_stat) != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }
  boot_cfi_step(cmd_cfi_ctx, CMD_CFI_SLOT_VERIFY);

  /* 5. Exhaustion Defense: Advance Counter ONLY after successful verify */
  /* Burn the exact difference */
  uint32_t burns_needed = decoded.counter_min - current_counter;
  for (uint32_t i = 0; i < burns_needed; i++) {
    /* P10 Fix: eFuse Burning ist riskant! Spannungseinbruch = Replay-Risk. */
    boot_status_t burn_stat = platform->crypto->advance_monotonic_counter();

    if (boot_secure_confirm(burn_stat) != BOOT_OK) {
      /* Fatale Hardware-Fehlfunktion! Wir dürfen den Command Dispatch
       * unter keinen Umständen fortsetzen, da sonst ein Replay möglich ist!
       */
      final_status = BOOT_ERR_FLASH_HW;
      goto cleanup;
    }
  }

  /* 6. CFI Resolution & Dispatch */
  boot_cfi_require(cmd_cfi_ctx, {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  });

  /* 7. ROTATE_KEY: Atomic KDM Write (Module-Owner Principle)
   * The new KDM is in decoded.params, signed by the Root Key.
   * We verify + write it here BEFORE returning to the dispatcher,
   * because the decoded struct is about to be zeroized. */
  if ((toob_cloud_cmd_t)decoded.command == TOOB_CMD_ROTATE_KEY) {
    if (decoded.params == NULL || decoded.params_len != sizeof(toob_kdm_t)) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    /* The KDM's internal signature is verified against the Root Key
     * by boot_rstore_read on next boot. Here we only verify the
     * params are structurally valid before persisting. */
    toob_kdm_t new_kdm;
    boot_secure_zeroize(&new_kdm, sizeof(new_kdm));
    memcpy(&new_kdm, decoded.params, sizeof(toob_kdm_t));

    /* Root-Key Verification of the new KDM */
    uint8_t rotate_root_key[32] __attribute__((aligned(8)));
    boot_secure_zeroize(rotate_root_key, 32);
    if (platform->crypto->read_pubkey(rotate_root_key, 32, 0) != BOOT_OK) {
      boot_secure_zeroize(&new_kdm, sizeof(new_kdm));
      final_status = BOOT_ERR_NOT_FOUND;
      goto cleanup;
    }

    boot_status_t kdm_sig = platform->crypto->verify_signature(
        (const uint8_t *)&new_kdm, offsetof(toob_kdm_t, signature_ed25519),
        new_kdm.signature_ed25519, rotate_root_key);
    boot_secure_zeroize(rotate_root_key, 32);

    if (boot_secure_confirm(kdm_sig) != BOOT_OK) {
      boot_secure_zeroize(&new_kdm, sizeof(new_kdm));
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    /* Anti-Replay: New KDM sequence must be > current */
    uint32_t current_kdm_seq = 0;
    toob_kdm_t current_kdm;
    boot_secure_zeroize(&current_kdm, sizeof(current_kdm));
    if (boot_rstore_read(platform, &kdm_rstore_desc, &current_kdm) == BOOT_OK) {
      current_kdm_seq = current_kdm.sequence_number;
    }
    boot_secure_zeroize(&current_kdm, sizeof(current_kdm));

    if (new_kdm.sequence_number <= current_kdm_seq) {
      boot_secure_zeroize(&new_kdm, sizeof(new_kdm));
      final_status = BOOT_ERR_DOWNGRADE;
      goto cleanup;
    }

    /* Atomic Quorum Write */
    boot_status_t write_stat =
        boot_rstore_write(platform, &kdm_rstore_desc, &new_kdm);
    boot_secure_zeroize(&new_kdm, sizeof(new_kdm));

    if (write_stat != BOOT_OK) {
      final_status = write_stat;
      goto cleanup;
    }
  }

  *out_cmd = (toob_cloud_cmd_t)decoded.command;
  final_status = BOOT_OK;

cleanup:
  boot_secure_zeroize(&decoded, sizeof(decoded));
  return final_status;
}

boot_status_t boot_cloud_cmd_evaluate_flash(const boot_platform_t *platform,
                                            uint8_t *crypto_arena,
                                            toob_cloud_cmd_t *out_cmd) {
  if (!platform || !platform->flash || !crypto_arena || !out_cmd) {
    return BOOT_ERR_INVALID_ARG;
  }

  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  /* TOCTOU Defense: Einmaliges Einlesen in SRAM! (Gap 5) */
  size_t max_read = (BOOT_CRYPTO_ARENA_SIZE > CHIP_CLOUD_CMD_SLOT_SIZE)
                        ? CHIP_CLOUD_CMD_SLOT_SIZE
                        : BOOT_CRYPTO_ARENA_SIZE;

  boot_status_t read_stat = platform->flash->read(CHIP_CLOUD_CMD_SLOT_ABS_ADDR, crypto_arena, max_read);
  if (read_stat != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    return read_stat;
  }

  /* Parse from SRAM buffer */
  size_t envelope_zone = max_read;
  size_t work_zone_offset =
      (envelope_zone + 7) & ~((size_t)7); /* 8-Byte align */
  if (work_zone_offset + 256 > BOOT_CRYPTO_ARENA_SIZE) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    return BOOT_ERR_INVALID_ARG;
  }
  uint8_t *work_arena = crypto_arena + work_zone_offset;

  /* P10 FIX: Aliasing-Verbot! envelope_buf und work_buffer dürfen nicht
   * identisch sein. */
  boot_status_t result = boot_cloud_cmd_evaluate_buffer(
      platform, crypto_arena, max_read, work_arena, out_cmd);

  /* Zero-Allocation Wipe */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  return result;
}
