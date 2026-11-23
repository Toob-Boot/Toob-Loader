/**
 * @file test_tds1_e2e.c
 * @brief Cross-language E2E Host SIL verification for TDS1 (Toob Delta Stream v1)
 *
 * Exercises Go-encoded TDS1 streams and signed TBM1 v2 bundles against the
 * real C bootloader pipeline (SDVM, Heatshrink LZSS, Monocypher Ed25519,
 * SHA-256 Merkle verification, WAL brownout checkpoints, Zero-Copy POINTER
 * scratch-less TrailerLayout, and ONEWAY Region 6 Reverse-Delta rollback).
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TOOB_TEST_ONEWAY_RDELTA
#define TOOB_TEST_ONEWAY_RDELTA 0
#endif

/* Self-contained generated_boot_config.h matching ESP32-C6 4 MB layout */
#define GENERATED_BOOT_CONFIG_H
#define BOOT_LAYOUT_H
#define TOOB_CUSTOM_SLOT_CAPS 1

#define CHIP_FLASH_WRITE_ALIGNMENT       4U
#define CHIP_FLASH_BASE_ADDR             0x00000000U
#define CHIP_FLASH_XIP_BASE              0x42000000U
#define CHIP_FLASH_TOTAL_SIZE            0x00200000U
#define CHIP_FLASH_MAX_SECTOR_SIZE       4096U
#define CHIP_FLASH_ERASED_BYTE           0xFFU

#define CHIP_STAGE0_ABS_ADDR             0x00040000U
#define CHIP_STAGE0_SIZE                 0x00008000U
#define CHIP_STAGE1A_ABS_ADDR            0x00048000U
#define CHIP_STAGE1A_SIZE                0x00020000U
#define CHIP_STAGE1B_ABS_ADDR            0x00068000U
#define CHIP_STAGE1B_SIZE                0x00020000U
#define CHIP_APP_SLOT_ABS_ADDR           0x00090000U
#define CHIP_APP_SLOT_SIZE               0x00060000U
#define CHIP_STAGING_SLOT_ABS_ADDR       0x000F0000U
#define CHIP_STAGING_SLOT_SIZE           0x00060000U
#define CHIP_SCRATCH_SLOT_ABS_ADDR       0x00000000U
#define CHIP_SCRATCH_SLOT_SIZE           0x00000000U
#define CHIP_RECOVERY_OS_ABS_ADDR        0x00150000U
#define CHIP_RECOVERY_OS_SIZE            0x00008000U
#define CHIP_NETCORE_SLOT_ABS_ADDR       0x00000000U
#define CHIP_NETCORE_SLOT_SIZE           0x00000000U
#define CHIP_WAL_ABS_ADDR                0x00158000U
#define CHIP_WAL_SIZE                    0x00004000U
#define CHIP_KDM_QUORUM_ABS_ADDR         0x0015C000U
#define CHIP_KDM_QUORUM_SIZE             0x00003000U
#define CHIP_CLOUD_CMD_SLOT_ABS_ADDR     0x0015F000U
#define CHIP_CLOUD_CMD_SLOT_SIZE         0x00001000U
#define CHIP_MAILBOX_ABS_ADDR            0x00160000U
#define CHIP_MAILBOX_SIZE                0x00002000U
#define CHIP_MAILBOX_SLOT_SIZE           0x00001000U
#define CHIP_FORENSIC_SLOT_ABS_ADDR      0x00162000U
#define CHIP_FORENSIC_SLOT_SIZE          0x00001000U

#define TOOB_WAL_SECTORS                 4U
#define TOOB_WAL_SECTOR_ADDRS            { 0x00158000U, 0x00159000U, 0x0015A000U, 0x0015B000U }
#define TOOB_WAL_SECTOR_SIZES            { 4096U, 4096U, 4096U, 4096U }

#define BOOT_CRYPTO_ARENA_SIZE           8192U
#define BOOT_WDT_TIMEOUT_MS              5000U
#define BOOT_CONFIG_MAX_RETRIES          3U
#define BOOT_CONFIG_MAX_RECOVERY_RETRIES 5U
#define BOOT_CONFIG_EDGE_UNATTENDED_MODE 1
#define BOOT_CONFIG_BACKOFF_BASE_S       10U
#define BOOT_STAGE1_SVN                  0U

#define TOOB_DEVICE_PRODUCT_ID           0x0042U
#define TOOB_DEVICE_VENDOR_ID            0x0001U
#define TOOB_DEVICE_HW_REV               1U
#define TOOB_PQC_ENABLED                 0

#define TOOB_TRANSPORT_SWAPSCRATCH       1
#define TOOB_TRANSPORT_ONEWAY            2
#define TOOB_TRANSPORT_SWAPMOVE          3
#define TOOB_TRANSPORT_POINTER           4
#define TOOB_TRANSPORT_SWAPOFFSET        5

#define TOOB_ONEWAY_BACKUP_NONE          0
#define TOOB_ONEWAY_BACKUP_FULL          1
#define TOOB_ONEWAY_BACKUP_REVERSE_DELTA 2

#if TOOB_TEST_ONEWAY_RDELTA
#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_ONEWAY
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_REVERSE_DELTA
#else
#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_POINTER
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_NONE
#endif

#define HEATSHRINK_DYNAMIC_ALLOC             0
#define HEATSHRINK_STATIC_INPUT_BUFFER_SIZE  128
#define HEATSHRINK_STATIC_WINDOW_BITS        8
#define HEATSHRINK_STATIC_LOOKAHEAD_BITS     4

/* Pull in production C bootloader modules + Heatshrink */
#include "boot_types.h"
#include "crypto_monocypher.h"
#include "crypto_sha256.h"
#if TOOB_PQC_ENABLED
#include "crypto_pqc.h"
#endif
#include "../../common/lib/heatshrink/heatshrink_decoder.c"

#include "../../toobloader/core/utils/boot_crc32.c"
#include "../../toobloader/core/utils/boot_delay.c"
#include "../../toobloader/core/utils/boot_diag.c"
#include "../../toobloader/core/utils/boot_energy.c"
#include "../../toobloader/core/utils/boot_identity.c"
#include "../../toobloader/core/utils/boot_merkle.c"
#include "../../toobloader/core/utils/boot_secure_zeroize_host.c"

#include "../../toobloader/core/boot_rstore.c"
#include "../../toobloader/core/boot_cloud_cmd.c"
#include "../../toobloader/core/boot_confirm.c"
#include "../../toobloader/core/boot_decomp.c"
#include "../../toobloader/core/boot_delta.c"
#include "../../toobloader/core/boot_effect.c"
#include "../../toobloader/core/boot_journal.c"
#include "../../toobloader/core/boot_mailbox.c"
#include "../../toobloader/core/boot_multiimage.c"
#include "../../toobloader/core/boot_rollback.c"
#include "../../toobloader/core/boot_swap.c"
#include "../../toobloader/core/boot_tbm1.c"
#include "../../toobloader/core/boot_transport.c"
#include "../../toobloader/core/boot_transport_oneway.c"
#include "../../toobloader/core/boot_transport_pointer.c"
#include "../../toobloader/core/boot_verify.c"
#include "../../toobloader/core/boot_state.c"

_Noreturn void boot_panic(const boot_platform_t *p, boot_status_t r) {
  (void)p;
  fprintf(stderr, "FATAL boot_panic(0x%08X)\n", (unsigned)r);
  abort();
}

_Noreturn void boot_terminal_halt(const boot_platform_t *p, boot_status_t r,
                                  uint16_t site) {
  (void)p;
  fprintf(stderr, "FATAL boot_terminal_halt(0x%08X, site=%u)\n", (unsigned)r,
          (unsigned)site);
  abort();
}

/* =========================================================================
 * Strict NOR Flash Simulator + Mock HALs
 * ========================================================================= */

static uint8_t s_flash[CHIP_FLASH_TOTAL_SIZE];
static uint32_t s_write_ops = 0U;
static uint32_t s_fail_at_write_op = 0U;
static reset_reason_t s_reset_reason = RESET_REASON_POWER_ON;
static uint32_t s_hw_active_slot = 0U;
static uint32_t s_otp_svn = 0U;
static uint8_t s_dslc_state = 0x00U;

static void sim_reset_boot_globals(void) {
  wal_initialized = false;
  tmr_defer_enabled = false;
  tmr_dirty = false;
  journal_key_valid = false;
}

static void sim_flash_format(void) {
  memset(s_flash, 0xFF, sizeof(s_flash));
  s_write_ops = 0U;
  s_fail_at_write_op = 0U;
  s_reset_reason = RESET_REASON_POWER_ON;
  s_hw_active_slot = 0U;
  s_otp_svn = 0U;
  s_dslc_state = 0x00U;
  sim_reset_boot_globals();
}

static boot_status_t sim_flash_init(void) { return BOOT_OK; }
static void sim_flash_deinit(void) {}

static boot_status_t sim_flash_read(uint32_t addr, void *buf, size_t len) {
  if (!buf || addr > sizeof(s_flash) || len > sizeof(s_flash) - addr) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  memcpy(buf, &s_flash[addr], len);
  return BOOT_OK;
}

static boot_status_t sim_flash_write(uint32_t addr, const void *buf,
                                     size_t len) {
  if (!buf || addr > sizeof(s_flash) || len > sizeof(s_flash) - addr) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
      (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
    return BOOT_ERR_FLASH_ALIGN;
  }
  s_write_ops++;
  if (s_fail_at_write_op != 0U && s_write_ops == s_fail_at_write_op) {
    return BOOT_ERR_FLASH_HW;
  }
  const uint8_t *src = (const uint8_t *)buf;
  for (size_t i = 0; i < len; i++) {
    /* Enforce real NOR flash physics: 0->1 requires erase_sector first! */
    if ((~s_flash[addr + i] & src[i]) != 0U) {
      fprintf(stderr, "NOR violation at 0x%08X+%zu: cur=0x%02X new=0x%02X\n",
              (unsigned)addr, i, s_flash[addr + i], src[i]);
      return BOOT_ERR_FLASH_NOT_ERASED;
    }
    s_flash[addr + i] &= src[i];
  }
  return BOOT_OK;
}

static boot_status_t sim_flash_erase_sector(uint32_t addr) {
  if ((addr % 4096U) != 0U || addr + 4096U > sizeof(s_flash)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  memset(&s_flash[addr], 0xFF, 4096U);
  return BOOT_OK;
}

static boot_status_t sim_flash_get_sector_size(uint32_t addr,
                                               size_t *size_out) {
  if (!size_out || addr >= sizeof(s_flash)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  *size_out = 4096U;
  return BOOT_OK;
}

static boot_status_t sim_flash_get_supply_mv(uint32_t *mv_out) {
  *mv_out = 3300U;
  return BOOT_OK;
}

static const flash_hal_t s_flash_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_flash_init,
    .deinit = sim_flash_deinit,
    .read = sim_flash_read,
    .write = sim_flash_write,
    .erase_sector = sim_flash_erase_sector,
    .get_sector_size = sim_flash_get_sector_size,
    .get_supply_mv = sim_flash_get_supply_mv,
    .max_sector_size = 4096U,
    .total_size = CHIP_FLASH_TOTAL_SIZE,
    .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
    .erased_value = 0xFFU,
};

static boot_status_t sim_wdt_init(uint32_t ms) {
  (void)ms;
  return BOOT_OK;
}
static void sim_wdt_kick(void) {}
static void sim_wdt_deinit(void) {}
static void sim_wdt_suspend(void) {}
static void sim_wdt_resume(void) {}

static const wdt_hal_t s_wdt_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_wdt_init,
    .kick = sim_wdt_kick,
    .deinit = sim_wdt_deinit,
    .suspend_for_critical_section = sim_wdt_suspend,
    .resume = sim_wdt_resume,
};

static boot_status_t sim_clock_init(void) { return BOOT_OK; }
static void sim_clock_deinit(void) {}
static uint32_t sim_clock_tick(void) { return 100U; }
static reset_reason_t sim_clock_reset_reason(void) { return s_reset_reason; }

static const clock_hal_t s_clock_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_clock_init,
    .deinit = sim_clock_deinit,
    .get_tick_ms = sim_clock_tick,
    .get_reset_reason = sim_clock_reset_reason,
};

static boot_status_t sim_confirm_init(void) { return BOOT_OK; }
static void sim_confirm_deinit(void) {}
static bool sim_confirm_check(uint64_t expected_nonce) {
  (void)expected_nonce;
  return false;
}
static boot_status_t sim_confirm_clear(void) { return BOOT_OK; }

static const confirm_hal_t s_confirm_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_confirm_init,
    .deinit = sim_confirm_deinit,
    .check_ok = sim_confirm_check,
    .clear = sim_confirm_clear,
};

static boot_status_t sim_crypto_random(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 17U + 3U));
  }
  return BOOT_OK;
}

/* RFC 8032 Test Vector 1 public key (matches tbm1pack -dev-key) */
static boot_status_t sim_crypto_read_pubkey(uint8_t *key, size_t key_len,
                                            uint8_t key_index) {
  static const uint8_t k_tv1_pub[32] = {
      0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
      0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
      0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
  if (!key || key_len != 32U || key_index != 0U) {
    return BOOT_ERR_NOT_FOUND;
  }
  memcpy(key, k_tv1_pub, 32U);
  return BOOT_OK;
}

static boot_status_t sim_crypto_read_uid(uint8_t *buf, size_t max_len,
                                         size_t *out_len) {
  size_t n = (max_len < 16U) ? max_len : 16U;
  memset(buf, 0x3CU, n);
  *out_len = n;
  return BOOT_OK;
}

static boot_status_t sim_crypto_read_dslc(uint8_t *buf, size_t *len) {
  if (!buf || !len || *len == 0U) {
    return BOOT_ERR_INVALID_ARG;
  }
  buf[0] = s_dslc_state;
  *len = 1U;
  return BOOT_OK;
}

static boot_status_t sim_crypto_read_device_secret(uint8_t *secret_out,
                                                   size_t max_len,
                                                   size_t *actual_len) {
  static const uint8_t k_huk[32] = {
      0x21U, 0x32U, 0x43U, 0x54U, 0x65U, 0x76U, 0x87U, 0x98U,
      0xA9U, 0xBAU, 0xCBU, 0xDCU, 0xEDU, 0xFEU, 0x0FU, 0x10U,
      0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
      0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U
  };
  if (!secret_out || !actual_len || max_len < sizeof(k_huk)) {
    return BOOT_ERR_INVALID_ARG;
  }
  memcpy(secret_out, k_huk, sizeof(k_huk));
  *actual_len = sizeof(k_huk);
  return BOOT_OK;
}

static boot_status_t sim_crypto_read_monotonic(uint32_t *ctr) {
  *ctr = s_otp_svn;
  return BOOT_OK;
}

static boot_status_t sim_crypto_advance_monotonic(void) {
  s_otp_svn++;
  return BOOT_OK;
}

static const crypto_hal_t s_crypto_hal = TOOB_CRYPTO_HAL_V3(
    crypto_monocypher_init, crypto_monocypher_deinit, crypto_sha256_init,
    crypto_sha256_update, crypto_sha256_finish,
    crypto_monocypher_verify_signature, crypto_sha256_get_ctx_size,
    .verify_signature_ph = crypto_monocypher_verify_signature_ph,
#if TOOB_PQC_ENABLED
    .verify_pqc = crypto_ml_dsa_65_verify_pqc,
    .is_pqc_enforced = crypto_ml_dsa_65_is_pqc_enforced,
#else
    .verify_pqc = NULL,
    .is_pqc_enforced = NULL,
#endif
    .has_hw_acceleration = false);

static const entropy_hal_t s_entropy_hal = TOOB_ENTROPY_HAL_V3(
    NULL, NULL, sim_crypto_random, .is_hardware_trng = false);

static const keystore_hal_t s_keystore_hal = TOOB_KEYSTORE_HAL_V3(
    NULL, NULL, sim_crypto_read_pubkey, sim_crypto_read_dslc, NULL,
    .read_chip_uid = sim_crypto_read_uid,
    .read_monotonic_counter = sim_crypto_read_monotonic,
    .advance_monotonic_counter = sim_crypto_advance_monotonic,
    .read_device_secret = sim_crypto_read_device_secret);

#if !TOOB_TEST_ONEWAY_RDELTA
static boot_status_t sim_xip_remap_commit(uint32_t phys_addr) {
  if (phys_addr == CHIP_APP_SLOT_ABS_ADDR) {
    s_hw_active_slot = 0U;
    return BOOT_OK;
  }
  if (phys_addr == CHIP_STAGING_SLOT_ABS_ADDR) {
    s_hw_active_slot = 1U;
    return BOOT_OK;
  }
  return BOOT_ERR_INVALID_ARG;
}

static boot_status_t sim_get_active_slot(uint32_t *out_slot) {
  *out_slot = s_hw_active_slot;
  return BOOT_OK;
}

static const slot_caps_t s_active_caps = TOOB_SLOT_CAPS_XIP_REMAP(
    2U, sim_xip_remap_commit, sim_get_active_slot,
    .commit_persistence = SLOT_COMMIT_VOLATILE);
#else
static const slot_caps_t s_active_caps = TOOB_SLOT_CAPS_FIXED(1U);
#endif

const slot_caps_t *boot_get_slot_caps(void) { return &s_active_caps; }

static const boot_platform_t s_platform = {
    .flash = &s_flash_hal,
    .confirm = &s_confirm_hal,
    .crypto = &s_crypto_hal,
    .clock = &s_clock_hal,
    .wdt = &s_wdt_hal,
    .slot_caps = &s_active_caps,
    .entropy = &s_entropy_hal,
    .keystore = &s_keystore_hal,
};

/* =========================================================================
 * File Loader Helper
 * ========================================================================= */

static uint8_t *load_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "Failed to open fixture: %s\n", path);
    abort();
  }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  assert(sz > 0);
  uint8_t *buf = (uint8_t *)malloc((size_t)sz);
  assert(buf != NULL);
  assert(fread(buf, 1, (size_t)sz, f) == (size_t)sz);
  fclose(f);
  *out_len = (size_t)sz;
  return buf;
}

static uint32_t read_trailer_tbm1_off(const uint8_t *bundle, size_t len) {
  assert(len >= sizeof(toob_tbm1_trailer_locator_t));
  toob_tbm1_trailer_locator_t loc;
  memcpy(&loc, bundle + len - sizeof(loc), sizeof(loc));
  assert(loc.magic == TOOB_TBM1_TRAILER_MAGIC);
  return loc.tbm1_off;
}

static const uint32_t k_seal_key[4] = {0x13579BDFU, 0x2468ACE0U, 0xCAFEBABEU,
                                       0x0DDC0FFEU};
static uint8_t s_arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));

#if !TOOB_TEST_ONEWAY_RDELTA

static void test_sdvm_direct_and_brownout_resume(const uint8_t *v1,
                                                 size_t v1_len,
                                                 const uint8_t *v2,
                                                 size_t v2_len,
                                                 const uint8_t *tds1_raw,
                                                 size_t tds1_len) {
  printf("[1] Testing Go TDS1 -> C SDVM roundtrip + sector brownout resume...\n");

  sim_flash_format();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;

  memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
  const uint32_t delta_addr = CHIP_STAGING_SLOT_ABS_ADDR + 0x10000U;
  memcpy(&s_flash[delta_addr], tds1_raw, tds1_len);

  wal_entry_payload_t txn;
  memset(&txn, 0, sizeof(txn));
  txn.magic = WAL_ENTRY_MAGIC;
  txn.intent = WAL_INTENT_UPDATE_PENDING;
  txn.offset = CHIP_STAGING_SLOT_ABS_ADDR;

  s_write_ops = 0U;
  boot_status_t st = boot_delta_apply(
      &s_platform, delta_addr, tds1_len, CHIP_STAGING_SLOT_ABS_ADDR,
      CHIP_STAGING_SLOT_SIZE, CHIP_APP_SLOT_ABS_ADDR, v1_len, &txn, s_arena,
      sizeof(s_arena));
  assert(st == BOOT_OK);
  assert(memcmp(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], v2, v2_len) == 0);
  printf("    [PASS] Clean SDVM roundtrip bit-identical (%zu bytes)\n", v2_len);

  /* Record write op count so we test crash + resume across EVERY write op after sector 1! */
  uint32_t baseline_writes = s_write_ops;
  assert(baseline_writes >= 4U);

  for (uint32_t crash_op = 1U; crash_op <= baseline_writes; crash_op++) {
    sim_flash_format();
    assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
    memcpy(&s_flash[delta_addr], tds1_raw, tds1_len);

    wal_entry_payload_t init_txn;
    memset(&init_txn, 0, sizeof(init_txn));
    init_txn.magic = WAL_ENTRY_MAGIC;
    init_txn.intent = WAL_INTENT_UPDATE_PENDING;
    init_txn.offset = CHIP_STAGING_SLOT_ABS_ADDR;
    assert(boot_journal_append(&s_platform, &init_txn) == BOOT_OK);

    s_write_ops = 0U;
    s_fail_at_write_op = crash_op;

    wal_entry_payload_t run_txn = init_txn;
    st = boot_delta_apply(&s_platform, delta_addr, tds1_len,
                          CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE,
                          CHIP_APP_SLOT_ABS_ADDR, v1_len, &run_txn, s_arena,
                          sizeof(s_arena));
    assert(st != BOOT_OK);

    /* Simulate reboot: reconstruct WAL checkpoint and resume to completion */
    s_fail_at_write_op = 0U;
    sim_reset_boot_globals();
    assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
    wal_entry_payload_t resumed_txn;
    memset(&resumed_txn, 0, sizeof(resumed_txn));
    assert(boot_journal_reconstruct_txn(&s_platform, &resumed_txn, NULL, NULL) == BOOT_OK);

    st = boot_delta_apply(&s_platform, delta_addr, tds1_len,
                          CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE,
                          CHIP_APP_SLOT_ABS_ADDR, v1_len, &resumed_txn, s_arena,
                          sizeof(s_arena));
    assert(st == BOOT_OK);
    assert(memcmp(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], v2, v2_len) == 0);
  }
  printf("    [PASS] Exhaustive brownout resume across %u write ops bit-identical\n",
         baseline_writes - 1U);

  /* Negative Test A: Wrong base_fingerprint -> BOOT_ERR_DOWNGRADE */
  sim_flash_format();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
  memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
  s_flash[CHIP_APP_SLOT_ABS_ADDR + 32U] ^= 0x55U; /* Mutate base byte */
  memcpy(&s_flash[delta_addr], tds1_raw, tds1_len);
  memset(&txn, 0, sizeof(txn));
  txn.intent = WAL_INTENT_UPDATE_PENDING;
  st = boot_delta_apply(&s_platform, delta_addr, tds1_len,
                        CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE,
                        CHIP_APP_SLOT_ABS_ADDR, v1_len, &txn, s_arena,
                        sizeof(s_arena));
  assert(st == BOOT_ERR_DOWNGRADE);
  printf("    [PASS] Ghost-base mismatch rejected with BOOT_ERR_DOWNGRADE\n");

  /* Negative Test B: Trailing unparsed byte -> BOOT_ERR_VERIFY */
  sim_flash_format();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
  memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
  memcpy(&s_flash[delta_addr], tds1_raw, tds1_len);
  s_flash[delta_addr + tds1_len] = 0xAAU;
  memset(&txn, 0, sizeof(txn));
  txn.intent = WAL_INTENT_UPDATE_PENDING;
  st = boot_delta_apply(&s_platform, delta_addr, tds1_len + 1U,
                        CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE,
                        CHIP_APP_SLOT_ABS_ADDR, v1_len, &txn, s_arena,
                        sizeof(s_arena));
  assert(st == BOOT_ERR_VERIFY);
  printf("    [PASS] Trailing garbage byte rejected with BOOT_ERR_VERIFY\n");
}

static void test_pointer_zerocopy_trailer_delta_e2e(
    const uint8_t *v1, size_t v1_len, const uint8_t *v2, size_t v2_len,
    const uint8_t *delta_trailer_bundle, size_t bundle_len) {
  printf("[2] Testing scratch-less Zero-Copy POINTER + TrailerLayout + TDS1 E2E...\n");

  uint32_t tbm1_off = read_trailer_tbm1_off(delta_trailer_bundle, bundle_len);

  /* Subtest 2A: Tamper staged TDS1 header base_fingerprint vs signed TBM1 -> rejected before erase! */
  sim_flash_format();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
  wal_tmr_payload_t tmr;
  memset(&tmr, 0, sizeof(tmr));
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.app_svn = 1U;
  s_otp_svn = 1U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(boot_journal_flush_tmr(&s_platform) == BOOT_OK);

  memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
  memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], delta_trailer_bundle, bundle_len);
  /* Read data_off of images[0] from TBM1 trailer and flip 1 bit of TDS1 base_fingerprint + fix TDS1 CRC */
  const tbm1_header_t *thdr =
      (const tbm1_header_t *)(delta_trailer_bundle + tbm1_off);
  uint32_t tds_off = thdr->images[0].data_off;
  toob_tds_header_t tampered_tds;
  memcpy(&tampered_tds, &s_flash[CHIP_STAGING_SLOT_ABS_ADDR + tds_off],
         sizeof(tampered_tds));
  tampered_tds.base_fingerprint[0] ^= 0x01U;
  tampered_tds.header_crc32 = compute_boot_crc32(
      (const uint8_t *)&tampered_tds,
      offsetof(toob_tds_header_t, header_crc32));
  memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR + tds_off], &tampered_tds,
         sizeof(tampered_tds));

  wal_entry_payload_t pending;
  memset(&pending, 0, sizeof(pending));
  pending.magic = WAL_ENTRY_MAGIC;
  pending.intent = WAL_INTENT_UPDATE_PENDING;
  pending.offset = CHIP_STAGING_SLOT_ABS_ADDR + tbm1_off;
  assert(boot_journal_append(&s_platform, &pending) == BOOT_OK);

  sim_reset_boot_globals();
  boot_target_config_t target_cfg;
  memset(&target_cfg, 0, sizeof(target_cfg));
  boot_status_t st = boot_state_run(&s_platform, &target_cfg, k_seal_key,
                                    s_arena, sizeof(s_arena));
  assert(st == BOOT_OK);
  /* Update must be rejected cleanly; Slot 0 (v1) remains active! */
  assert(target_cfg.active_slot == 0U);
  assert(target_cfg.proof.image_addr == CHIP_APP_SLOT_ABS_ADDR);
  printf("    [PASS] Tampered staged TDS1 base_fingerprint caught by signed TBM1 descriptor\n");

  /* Subtest 2B: Valid TrailerLayout TDS1 update with mid-SDVM brownout + clean resume! */
  sim_flash_format();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
  memset(&tmr, 0, sizeof(tmr));
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.app_svn = 1U;
  s_otp_svn = 1U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(boot_journal_flush_tmr(&s_platform) == BOOT_OK);

  memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
  memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], delta_trailer_bundle, bundle_len);
  assert(boot_journal_append(&s_platform, &pending) == BOOT_OK);

  /* Inject brownout mid-SDVM after sector 2 WAL checkpoint */
  sim_reset_boot_globals();
  s_write_ops = 0U;
  s_fail_at_write_op = 5U;
  memset(&target_cfg, 0, sizeof(target_cfg));
  st = boot_state_run(&s_platform, &target_cfg, k_seal_key, s_arena,
                      sizeof(s_arena));
  assert(st != BOOT_OK);

  /* Reboot cleanly: pipeline resumes SDVM, Merkle-verifies, flips XIP remap to Slot 1! */
  s_fail_at_write_op = 0U;
  sim_reset_boot_globals();
  memset(&target_cfg, 0, sizeof(target_cfg));
  st = boot_state_run(&s_platform, &target_cfg, k_seal_key, s_arena,
                      sizeof(s_arena));
  assert(st == BOOT_OK);
  if (target_cfg.active_slot != 1U) {
    fprintf(stderr, "Subtest 2B diag: active_slot=%u update_res=%u reject=%u last_err=0x%08X\n",
            (unsigned)target_cfg.active_slot,
            (unsigned)toob_diag_state.last_update_outcome,
            (unsigned)toob_diag_state.last_update_reject,
            (unsigned)toob_diag_state.last_error_code);
  }
  assert(target_cfg.active_slot == 1U);
  assert(target_cfg.is_tentative_boot == true);
  assert(target_cfg.proof.image_addr == CHIP_STAGING_SLOT_ABS_ADDR);
  assert(target_cfg.proof.image_size == v2_len);
  assert(memcmp(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], v2, v2_len) == 0);
  assert(memcmp(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len) == 0);
  printf("    [PASS] Scratch-less Zero-Copy POINTER + TDS1 TrailerLayout E2E + brownout resume passed!\n");
}

#else /* TOOB_TEST_ONEWAY_RDELTA */

static void test_oneway_reverse_delta_e2e(const uint8_t *v1, size_t v1_len,
                                          const uint8_t *v2, size_t v2_len,
                                          const uint8_t *bundle,
                                          size_t bundle_len, bool is_trailer) {
  printf("[ONEWAY+RDELTA] Testing Apply + Tentative Crash + Reverse-Delta Rollback (trailer=%d)...\n",
         is_trailer ? 1 : 0);

  uint32_t manifest_off =
      is_trailer ? read_trailer_tbm1_off(bundle, bundle_len) : 0U;

  /* 1. Pre-flight protection check: corrupt staged Reverse-Delta magic -> oneway_apply
   *    must abort BEFORE erasing CHIP_APP_SLOT_ABS_ADDR! */
  sim_flash_format();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
  wal_tmr_payload_t tmr;
  memset(&tmr, 0, sizeof(tmr));
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.app_svn = 1U;
  s_otp_svn = 1U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(boot_journal_flush_tmr(&s_platform) == BOOT_OK);

  memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
  memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], bundle, bundle_len);

  const tbm1_header_t *thdr = (const tbm1_header_t *)(bundle + manifest_off);
  const tbm1_region_t *rreg =
      tbm1_find_region(thdr, TBM1_REGION_REVERSE_DELTA);
  assert(rreg != NULL);
  tbm1_rdelta_desc_t rdesc;
  memcpy(&rdesc, (const uint8_t *)thdr + rreg->off, sizeof(rdesc));
  /* Corrupt Reverse-Delta TDS1 magic in Staging */
  s_flash[CHIP_STAGING_SLOT_ABS_ADDR + rdesc.data_off] ^= 0xFFU;

  wal_entry_payload_t pending;
  memset(&pending, 0, sizeof(pending));
  pending.magic = WAL_ENTRY_MAGIC;
  pending.intent = WAL_INTENT_UPDATE_PENDING;
  pending.offset = CHIP_STAGING_SLOT_ABS_ADDR + manifest_off;
  assert(boot_journal_append(&s_platform, &pending) == BOOT_OK);

  sim_reset_boot_globals();
  boot_target_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  boot_status_t st =
      boot_state_run(&s_platform, &cfg, k_seal_key, s_arena, sizeof(s_arena));
  assert(st == BOOT_OK);
  /* App slot MUST still hold untouched v1! */
  assert(memcmp(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len) == 0);
  printf("    [PASS] Corrupted Reverse-Delta caught pre-flight before touching App slot\n");

  /* 2. Full Apply -> v2 deployed -> Tentative Watchdog Crash -> Mid-Rollback Brownout -> Rollback to v1! */
  sim_flash_format();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  s_dslc_state = 0x01U;
  memset(&tmr, 0, sizeof(tmr));
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.app_svn = 1U;
  s_otp_svn = 1U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(boot_journal_flush_tmr(&s_platform) == BOOT_OK);

  memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len);
  memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], bundle, bundle_len);
  assert(boot_journal_append(&s_platform, &pending) == BOOT_OK);

  sim_reset_boot_globals();
  memset(&cfg, 0, sizeof(cfg));
  st = boot_state_run(&s_platform, &cfg, k_seal_key, s_arena, sizeof(s_arena));
  assert(st == BOOT_OK);
  assert(cfg.is_tentative_boot == true);
  assert(memcmp(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v2, v2_len) == 0);
  printf("    [PASS] ONEWAY deployed v2 (%zu bytes) into App slot\n", v2_len);

  /* Tentative boot crashes (Watchdog reset) AND brownout hits mid-Reverse-Delta rollback! */
  s_reset_reason = RESET_REASON_WATCHDOG;
  sim_reset_boot_globals();
  s_write_ops = 0U;
  s_fail_at_write_op = 6U; /* Fail mid-reverse-delta stream after sector 1 WAL checkpoint */
  memset(&cfg, 0, sizeof(cfg));
  st = boot_state_run(&s_platform, &cfg, k_seal_key, s_arena, sizeof(s_arena));
  assert(st != BOOT_OK);

  /* Reboot cleanly after mid-rollback brownout -> resumes Reverse-Delta and restores v1! */
  s_fail_at_write_op = 0U;
  s_reset_reason = RESET_REASON_BROWNOUT;
  sim_reset_boot_globals();
  memset(&cfg, 0, sizeof(cfg));
  st = boot_state_run(&s_platform, &cfg, k_seal_key, s_arena, sizeof(s_arena));
  assert(st == BOOT_OK);
  assert(cfg.boot_recovery_os == false);
  assert(cfg.is_tentative_boot == false);
  assert(cfg.proof.image_size == v1_len);
  assert(memcmp(&s_flash[CHIP_APP_SLOT_ABS_ADDR], v1, v1_len) == 0);
  printf("    [PASS] Reverse-Delta rollback + mid-rollback brownout resume restored v1 bit-for-bit!\n");
}

#endif

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr,
            "usage: %s <v1.toob> <v2.toob> <fixture3> <fixture4>\n", argv[0]);
    return 2;
  }

  size_t v1_len = 0, v2_len = 0, f3_len = 0, f4_len = 0;
  uint8_t *v1 = load_file(argv[1], &v1_len);
  uint8_t *v2 = load_file(argv[2], &v2_len);
  uint8_t *f3 = load_file(argv[3], &f3_len);
  uint8_t *f4 = load_file(argv[4], &f4_len);

#if !TOOB_TEST_ONEWAY_RDELTA
  test_sdvm_direct_and_brownout_resume(v1, v1_len, v2, v2_len, f3, f3_len);
  test_pointer_zerocopy_trailer_delta_e2e(v1, v1_len, v2, v2_len, f4, f4_len);
#else
  test_oneway_reverse_delta_e2e(v1, v1_len, v2, v2_len, f3, f3_len, false);
  test_oneway_reverse_delta_e2e(v1, v1_len, v2, v2_len, f4, f4_len, true);
#endif

  free(v1);
  free(v2);
  free(f3);
  free(f4);
  printf("\nALL TDS1 HOST SIL TESTS PASSED!\n");
  return 0;
}
