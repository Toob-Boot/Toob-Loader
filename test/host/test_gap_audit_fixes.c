/**
 * @file test_gap_audit_fixes.c
 * @brief Host-SIL Regression Suite for Formal Verification Gap Audit Fixes
 *        (CRIT-29..30, HIGH-26..30, MED-25..27, LOW-12).
 */

#include <assert.h>
#ifdef _WIN32
#define __USE_MINGW_SETJMP_NON_SEH
#endif
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GENERATED_BOOT_CONFIG_H
#define BOOT_LAYOUT_H
#define TOOB_CUSTOM_SLOT_CAPS 1

#define CHIP_FLASH_WRITE_ALIGNMENT       4U
#define CHIP_FLASH_BASE_ADDR             0x00000000U
#define CHIP_FLASH_TOTAL_SIZE            0x00080000U
#define CHIP_FLASH_MAX_SECTOR_SIZE       0x00001000U
#define CHIP_FLASH_ERASED_BYTE           0xFFU

#define CHIP_STAGE0_ABS_ADDR             0x00000000U
#define CHIP_STAGE0_SIZE                 0x00002000U
#define CHIP_STAGE1A_ABS_ADDR            0x00002000U
#define CHIP_STAGE1A_SIZE                0x00004000U
#define CHIP_STAGE1B_ABS_ADDR            0x00006000U
#define CHIP_STAGE1B_SIZE                0x00004000U
#define CHIP_APP_SLOT_ABS_ADDR           0x00010000U
#define CHIP_APP_SLOT_SIZE               0x00008000U
#define CHIP_STAGING_SLOT_ABS_ADDR       0x00020000U
#define CHIP_STAGING_SLOT_SIZE           0x0000C000U
#define CHIP_SCRATCH_SLOT_ABS_ADDR       0x00030000U
#define CHIP_SCRATCH_SLOT_SIZE           0x00008000U
#define CHIP_RECOVERY_OS_ABS_ADDR        0x00040000U
#define CHIP_RECOVERY_OS_SIZE            0x00004000U
#define CHIP_WAL_ABS_ADDR                0x00044000U
#define CHIP_WAL_SIZE                    0x00004000U
#define CHIP_KDM_QUORUM_ABS_ADDR         0x00048000U
#define CHIP_KDM_QUORUM_SIZE             0x00003000U
#define CHIP_CLOUD_CMD_SLOT_ABS_ADDR     0x0004B000U
#define CHIP_CLOUD_CMD_SLOT_SIZE         0x00001000U
#define CHIP_MAILBOX_ABS_ADDR            0x0004C000U
#define CHIP_MAILBOX_SLOT_SIZE           0x00001000U
#define CHIP_MAILBOX_SIZE                0x00002000U
#define CHIP_FORENSIC_SLOT_ABS_ADDR      0x0004E000U
#define CHIP_FORENSIC_SLOT_SIZE          0x00001000U
#define CHIP_NETCORE_SLOT_ABS_ADDR       0x00050000U
#define CHIP_NETCORE_SLOT_SIZE           0x00004000U

#define TOOB_WAL_SECTORS                 4U
#define TOOB_WAL_SECTOR_ADDRS            { 0x00044000U, 0x00045000U, 0x00046000U, 0x00047000U }
#define TOOB_WAL_SECTOR_SIZES            { 4096U, 4096U, 4096U, 4096U }

#define TOOB_TRANSPORT_SWAPSCRATCH       1
#define TOOB_TRANSPORT_ONEWAY            2
#define TOOB_TRANSPORT_SWAPMOVE          3
#define TOOB_TRANSPORT_POINTER           4
#define TOOB_TRANSPORT_SWAPOFFSET        5
#define TOOB_ONEWAY_BACKUP_NONE          0
#define TOOB_ONEWAY_BACKUP_FULL          1
#define TOOB_ONEWAY_BACKUP_REVERSE_DELTA 2

#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_POINTER
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_NONE

#define BOOT_CRYPTO_ARENA_SIZE           8192U
#define BOOT_WDT_TIMEOUT_MS              5000U
#define BOOT_UART_BAUDRATE               115200U
#define BOOT_CONFIG_MAX_RETRIES          3U
#define BOOT_CONFIG_MAX_RECOVERY_RETRIES 5U
#define BOOT_CONFIG_EDGE_UNATTENDED_MODE 1
#define BOOT_CONFIG_BACKOFF_BASE_S       10U
#define BOOT_STAGE1_SVN                  1U

#define TOOB_DEVICE_PRODUCT_ID           0x0042U
#define TOOB_DEVICE_VENDOR_ID            0x0001U
#define TOOB_DEVICE_HW_REV               1U
#ifndef TOOB_PQC_ENABLED
#define TOOB_PQC_ENABLED                 0
#endif

#define HEATSHRINK_DYNAMIC_ALLOC             0
#define HEATSHRINK_STATIC_INPUT_BUFFER_SIZE  128
#define HEATSHRINK_STATIC_WINDOW_BITS        8
#define HEATSHRINK_STATIC_LOOKAHEAD_BITS     4

#include "boot_types.h"
#include "crypto_monocypher.h"
#include "crypto_sha256.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "sha256.h"
#include "toob_mailbox_wire.h"

#include "../../toobloader/core/utils/boot_crc32.c"
#include "../../toobloader/core/utils/boot_cobs.c"
#include "../../toobloader/core/utils/boot_delay.c"
#include "../../toobloader/core/utils/boot_diag.c"
#include "../../toobloader/core/utils/boot_energy.c"
#include "../../toobloader/core/utils/boot_identity.c"
#include "../../toobloader/core/utils/boot_merkle.c"
#include "../../toobloader/core/utils/boot_secure_zeroize_host.c"

#include "../../toobloader/core/boot_platform_bringup.c"
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
#include "../../toobloader/core/boot_transport_swapmove.c"
#include "../../toobloader/core/boot_transport_swapscratch.c"
#include "../../toobloader/core/boot_verify.c"
#include "../../toobloader/core/boot_state.c"
#include "../../toobloader/core/boot_main.c"

/* Include Stage 0 modules into the same test harness */
#include "stage0_crypto.h"
#include "../../toobloader/stage0/stage0_boot_pointer.c"
#include "../../toobloader/stage0/stage0_otp.c"
#include "../../toobloader/stage0/stage0_hash.c"
#include "../../toobloader/stage0/stage0_verify.c"
#include "../../toobloader/stage0/stage0_tentative.c"

static jmp_buf s_panic_env;
static bool s_expect_panic = false;
static boot_status_t s_last_panic = BOOT_OK;

_Noreturn void boot_terminal_halt(const boot_platform_t *p, boot_status_t r,
                                  uint16_t site) {
  (void)p;
  (void)site;
  s_last_panic = r;
  if (s_expect_panic) {
    longjmp(s_panic_env, 1);
  }
  fprintf(stderr, "Unexpected boot_terminal_halt(0x%08X)\n", (unsigned)r);
  abort();
}

_Noreturn void boot_panic(const boot_platform_t *p, boot_status_t r) {
  boot_terminal_halt(p, r, 0U);
}

_Noreturn void boot_provisioning_run(const boot_platform_t *p, uint8_t *arena,
                                     size_t arena_len) {
  (void)p;
  (void)arena;
  (void)arena_len;
  abort();
}

const boot_platform_t *boot_platform_init(void);

#define toob_handoff_state s0_unused_handoff_state
#define boot_panic s0_unused_boot_panic
#define boot_terminal_halt s0_unused_terminal_halt
#define toob_ecc_trap s0_unused_ecc_trap
#define main stage0_entry_main
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#include "../../toobloader/stage0/stage0_main.c"
#pragma GCC diagnostic pop
#undef main
#undef toob_ecc_trap
#undef boot_terminal_halt
#undef boot_panic
#undef toob_handoff_state

/* Include Recovery OS flash port (namespacing its standalone entry stubs) */
#include "libtoob.h"
int recovery_main(void) { return 0; }
#define boot_main rec_entry_boot_main
#define boot_panic rec_unused_boot_panic
#define boot_terminal_halt rec_unused_terminal_halt
#define toob_ecc_trap rec_unused_ecc_trap
#define boot_secure_zeroize rec_unused_zeroize
#include "../../recovery/recovery_port.c"
#undef boot_secure_zeroize
#undef toob_ecc_trap
#undef boot_terminal_halt
#undef boot_panic
#undef boot_main

/* ============================================================================
 * Mock Hardware State
 * ============================================================================ */
static uint8_t s_flash[CHIP_FLASH_TOTAL_SIZE];
static reset_reason_t s_reset_reason = RESET_REASON_POWER_ON;
static uint32_t s_hw_active_slot = 0U;
static uint32_t s_otp_svn = 0U;
static uint8_t s_dslc_state = 0x00U;
static uint8_t s_otp_key_count = 1U;
static bool s_fail_flash_read = false;
static bool s_fail_sector_size = false;
static size_t s_override_sector_size = 4096U;

#if TOOB_PQC_ENABLED
static uint8_t s_pqc_pinned_hash[32];
static bool s_pqc_enforced_flag = false;
#endif

static const uint8_t k_tv1_pub[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
    0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
    0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};

static void sim_reset_globals(void) {
  wal_initialized = false;
  tmr_defer_enabled = false;
  tmr_dirty = false;
  journal_key_valid = false;
  boot_platform_mark_down();
}

static void sim_format_all(void) {
  memset(s_flash, 0xFF, sizeof(s_flash));
  memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
  s_reset_reason = RESET_REASON_POWER_ON;
  s_hw_active_slot = 0U;
  s_otp_svn = 0U;
  s_dslc_state = 0x00U;
  s_otp_key_count = 1U;
  s_fail_flash_read = false;
  s_fail_sector_size = false;
  s_override_sector_size = 4096U;
#if TOOB_PQC_ENABLED
  s_pqc_enforced_flag = false;
  memset(s_pqc_pinned_hash, 0, sizeof(s_pqc_pinned_hash));
#endif
  sim_reset_globals();
}

static boot_status_t sim_flash_init(void) { return BOOT_OK; }
static void sim_flash_deinit(void) {}

static boot_status_t sim_flash_read(uint32_t addr, void *buf, size_t len) {
  if (s_fail_flash_read) {
    return BOOT_ERR_FLASH_HW;
  }
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
  const uint8_t *src = (const uint8_t *)buf;
  for (size_t i = 0U; i < len; i++) {
    if ((~s_flash[addr + i] & src[i]) != 0U) {
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
  if (s_fail_sector_size || !size_out || addr >= sizeof(s_flash)) {
    return BOOT_ERR_FLASH_HW;
  }
  *size_out = s_override_sector_size;
  return BOOT_OK;
}

static boot_status_t sim_flash_get_supply_mv(uint32_t *mv_out) {
  *mv_out = 3300U;
  return BOOT_OK;
}

static flash_hal_t s_flash_hal = {
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
    .max_erase_cycles = 100000U,
    .erased_value = 0xFFU,
};

static boot_status_t sim_wdt_init(uint32_t ms) {
  (void)ms;
  return BOOT_OK;
}
static void sim_wdt_kick(void) {}
static void sim_wdt_deinit(void) {}

static const wdt_hal_t s_wdt_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_wdt_init,
    .kick = sim_wdt_kick,
    .deinit = sim_wdt_deinit,
};

static boot_status_t sim_clock_init(void) { return BOOT_OK; }
static void sim_clock_deinit(void) {}
static uint32_t sim_clock_tick(void) { return 42U; }
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

static boot_status_t sim_entropy_random(uint8_t *buf, size_t len) {
  for (size_t i = 0U; i < len; i++) {
    buf[i] = (uint8_t)(0x5AU ^ (uint8_t)(i * 29U + 7U));
  }
  return BOOT_OK;
}

static boot_status_t sim_read_pubkey(uint8_t *key, size_t key_len,
                                     uint8_t key_index) {
  if (!key || key_len != 32U || key_index >= s_otp_key_count) {
    return BOOT_ERR_NOT_FOUND;
  }
  memcpy(key, k_tv1_pub, 32U);
  return BOOT_OK;
}

static boot_status_t sim_read_dslc(uint8_t *buf, size_t *len) {
  if (!buf || !len || *len == 0U) {
    return BOOT_ERR_INVALID_ARG;
  }
  buf[0] = s_dslc_state;
  *len = 1U;
  return BOOT_OK;
}

static boot_status_t sim_write_dslc(const uint8_t *val, size_t len) {
  if (!val || len == 0U) {
    return BOOT_ERR_INVALID_ARG;
  }
  s_dslc_state |= val[0];
  return BOOT_OK;
}

static boot_status_t sim_read_uid(uint8_t *buf, size_t max_len,
                                  size_t *out_len) {
  size_t n = (max_len < 16U) ? max_len : 16U;
  memset(buf, 0x77U, n);
  *out_len = n;
  return BOOT_OK;
}

static boot_status_t sim_read_monotonic(uint32_t *ctr) {
  *ctr = s_otp_svn;
  return BOOT_OK;
}

static boot_status_t sim_advance_monotonic(void) {
  s_otp_svn++;
  return BOOT_OK;
}

static boot_status_t sim_read_device_secret(uint8_t *secret_out, size_t max_len,
                                            size_t *actual_len) {
  static const uint8_t k_huk[32] = {
      0x61U, 0x72U, 0x83U, 0x94U, 0xA5U, 0xB6U, 0xC7U, 0xD8U,
      0xE9U, 0xFAU, 0x0BU, 0x1CU, 0x2DU, 0x3EU, 0x4FU, 0x50U,
      0x0FU, 0x1EU, 0x2DU, 0x3CU, 0x4BU, 0x5AU, 0x69U, 0x78U,
      0x87U, 0x96U, 0xA5U, 0xB4U, 0xC3U, 0xD2U, 0xE1U, 0xF0U
  };
  if (!secret_out || !actual_len || max_len < sizeof(k_huk)) {
    return BOOT_ERR_INVALID_ARG;
  }
  memcpy(secret_out, k_huk, sizeof(k_huk));
  *actual_len = sizeof(k_huk);
  return BOOT_OK;
}

#if TOOB_PQC_ENABLED
static boot_status_t sim_verify_pqc(const uint8_t *message, size_t msg_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const uint8_t *pubkey, size_t pubkey_len) {
  if (!message || msg_len == 0U || !sig || sig_len == 0U || !pubkey ||
      pubkey_len == 0U) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_OK;
}

static bool sim_is_pqc_enforced(void) { return s_pqc_enforced_flag; }

static boot_status_t sim_read_pqc_pubkey_hash(uint8_t out_hash[32],
                                              uint8_t key_index) {
  if (!out_hash || key_index >= s_otp_key_count) {
    return BOOT_ERR_NOT_FOUND;
  }
  memcpy(out_hash, s_pqc_pinned_hash, 32U);
  return BOOT_OK;
}
#endif

static const crypto_hal_t s_crypto_hal = TOOB_CRYPTO_HAL_V3(
    crypto_monocypher_init, crypto_monocypher_deinit, crypto_sha256_init,
    crypto_sha256_update, crypto_sha256_finish,
    crypto_monocypher_verify_signature, crypto_sha256_get_ctx_size,
    .verify_signature_ph = crypto_monocypher_verify_signature_ph,
#if TOOB_PQC_ENABLED
    .verify_pqc = sim_verify_pqc,
    .is_pqc_enforced = sim_is_pqc_enforced,
#else
    .verify_pqc = NULL,
    .is_pqc_enforced = NULL,
#endif
    .has_hw_acceleration = false);

static const entropy_hal_t s_entropy_hal = TOOB_ENTROPY_HAL_V3(
    NULL, NULL, sim_entropy_random, .is_hardware_trng = false);

static const keystore_hal_t s_keystore_hal = TOOB_KEYSTORE_HAL_V3(
    NULL, NULL, sim_read_pubkey, sim_read_dslc, sim_write_dslc,
    .read_chip_uid = sim_read_uid,
    .read_monotonic_counter = sim_read_monotonic,
    .advance_monotonic_counter = sim_advance_monotonic,
    .read_device_secret = sim_read_device_secret,
#if TOOB_PQC_ENABLED
    .read_pqc_pubkey_hash = sim_read_pqc_pubkey_hash,
#endif
);

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

static const slot_caps_t s_slot_caps = TOOB_SLOT_CAPS_XIP_REMAP(
    2U, sim_xip_remap_commit, sim_get_active_slot,
    .commit_persistence = SLOT_COMMIT_VOLATILE);

const slot_caps_t *boot_get_slot_caps(void) { return &s_slot_caps; }

static boot_platform_t s_platform = {
    .flash = &s_flash_hal,
    .confirm = &s_confirm_hal,
    .crypto = &s_crypto_hal,
    .clock = &s_clock_hal,
    .wdt = &s_wdt_hal,
    .slot_caps = &s_slot_caps,
    .entropy = &s_entropy_hal,
    .keystore = &s_keystore_hal,
};

const boot_platform_t *boot_platform_init(void) { return &s_platform; }

/* ============================================================================
 * Helper: Build Ed25519-Ph signed Stage 1 image in flash
 * ============================================================================ */
static void write_signed_stage1(uint32_t bank_addr, uint32_t entry_off,
                                uint32_t svn, bool include_svn_magic,
                                uint8_t fill_byte) {
  uint8_t payload[512];
  memset(payload, fill_byte, sizeof(payload));

  toob_image_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TOOB_MAGIC_HEADER;
  hdr.image_size = (uint32_t)sizeof(payload);
  hdr.entry_point = entry_off;
  if (include_svn_magic) {
    hdr.s1.svn_magic = TOOB_STAGE1_SVN_MAGIC;
    hdr.s1.stage1_svn = svn;
  }

  uint8_t signed_msg[sizeof(hdr) + sizeof(payload)];
  memcpy(signed_msg, &hdr, sizeof(hdr));
  memcpy(signed_msg + sizeof(hdr), payload, sizeof(payload));

  uint8_t digest[32];
  uint8_t sha_ctx[256] __attribute__((aligned(8)));
  size_t dlen = sizeof(digest);
  assert(crypto_sha256_init(sha_ctx, sizeof(sha_ctx)) == BOOT_OK);
  assert(crypto_sha256_update(sha_ctx, signed_msg, sizeof(signed_msg)) == BOOT_OK);
  assert(crypto_sha256_finish(sha_ctx, digest, &dlen) == BOOT_OK);

  uint8_t sk[64];
  uint8_t pk[32];
  crypto_ed25519_key_pair(sk, pk, (uint8_t[32]){
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60});

  uint8_t sig[64];
  crypto_ed25519_sign(sig, sk, digest, sizeof(digest));

  memcpy(&s_flash[bank_addr], signed_msg, sizeof(signed_msg));
  memcpy(&s_flash[bank_addr + sizeof(signed_msg)], sig, sizeof(sig));
}

static void write_signed_slot_image_ex(uint32_t slot_addr, uint32_t img_size,
                                       uint32_t entry_off, uint8_t fill_byte,
                                       uint8_t key_index) {
  assert(img_size >= (uint32_t)(sizeof(toob_image_header_t) +
                                sizeof(toob_img_sig_trailer_t)));
  assert(img_size <= 4096U);

  uint8_t img[4096];
  memset(img, fill_byte, img_size);

  toob_image_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TOOB_MAGIC_HEADER;
  hdr.image_size = img_size;
  hdr.entry_point = entry_off;
  memcpy(img, &hdr, sizeof(hdr));

  uint32_t signed_len = img_size - (uint32_t)sizeof(toob_img_sig_trailer_t);
  uint8_t digest[32];
  uint8_t sha_ctx[256] __attribute__((aligned(8)));
  size_t dlen = sizeof(digest);
  assert(crypto_sha256_init(sha_ctx, sizeof(sha_ctx)) == BOOT_OK);
  assert(crypto_sha256_update(sha_ctx, img, signed_len) == BOOT_OK);
  assert(crypto_sha256_finish(sha_ctx, digest, &dlen) == BOOT_OK);

  uint8_t sk[64];
  uint8_t pk[32];
  crypto_ed25519_key_pair(sk, pk, (uint8_t[32]){
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60});

  toob_img_sig_trailer_t trailer;
  memset(&trailer, 0, sizeof(trailer));
  trailer.magic = TOOB_IMG_SIG_MAGIC;
  trailer.key_index = key_index;
  trailer.flags = TOOB_IMG_SIG_FLAG_SHA256;
  trailer.reserved = 0U;
  crypto_ed25519_sign(trailer.sig_ed25519, sk, digest, sizeof(digest));
  memcpy(img + signed_len, &trailer, sizeof(trailer));

  memcpy(&s_flash[slot_addr], img, img_size);
}

static void write_signed_slot_image(uint32_t slot_addr, uint32_t img_size,
                                    uint32_t entry_off, uint8_t fill_byte,
                                    uint8_t key_index) {
  assert(entry_off >= (uint32_t)sizeof(toob_image_header_t) &&
         entry_off < img_size - (uint32_t)sizeof(toob_img_sig_trailer_t));
  write_signed_slot_image_ex(slot_addr, img_size, entry_off, fill_byte, key_index);
}

static void init_wal_factory_to_deployed(uint32_t target_epoch) {
  s_dslc_state = 0x00U;
  s_otp_svn = 0U;
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  wal_tmr_payload_t tmr;
  while (s_otp_svn < target_epoch) {
    s_otp_svn++;
    assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
    assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  }
  s_dslc_state = 0x01U;
}

/* ============================================================================
 * 1. CRIT-29, HIGH-26, HIGH-28, HIGH-30: Stage 0 Security & Quorum Tests
 * ============================================================================ */
static void test_stage0_security_and_quorum(void) {
  printf("[1/6] Testing Stage 0 CRIT-29 (SVN), HIGH-26 (XIP bounds), HIGH-28 (2-of-3 Quorum), HIGH-30 (Hash fail-closed)...\n");

  sim_format_all();
  g_platform = &s_platform;

  /* HIGH-26: stage0_compute_xip_entry bounds & alignment */
  uint32_t target_pc = 0U;
  assert(!stage0_compute_xip_entry(CHIP_STAGE1A_ABS_ADDR, 512U, 0U, &target_pc));
  assert(!stage0_compute_xip_entry(CHIP_STAGE1A_ABS_ADDR, 512U, 16U, &target_pc));
  assert(!stage0_compute_xip_entry(CHIP_STAGE1A_ABS_ADDR, 512U, 20U + 512U, &target_pc));
  assert(!stage0_compute_xip_entry(CHIP_STAGE1A_ABS_ADDR, 512U, 0x22U, &target_pc));
  assert(!stage0_compute_xip_entry(0xFFFFFFF0U, 512U, 0x100U, &target_pc));
  assert(stage0_compute_xip_entry(CHIP_STAGE1A_ABS_ADDR, 512U, 0x100U, &target_pc));
  assert(target_pc == CHIP_STAGE1A_ABS_ADDR + 0x100U);

  /* HIGH-30: stage0_hash_compute fail-closed on flash failure & overflow */
  uint8_t digest[32];
  memset(digest, 0xAA, sizeof(digest));
  assert(stage0_hash_compute(&s_platform, 0xFFFFFF00U, 0x200U, digest) ==
         BOOT_ERR_INVALID_ARG);
  s_fail_flash_read = true;
  memset(digest, 0xAA, sizeof(digest));
  assert(stage0_hash_compute(&s_platform, CHIP_STAGE1A_ABS_ADDR, 64U, digest) ==
         BOOT_ERR_FLASH_HW);
  for (size_t i = 0U; i < sizeof(digest); i++) {
    assert(digest[i] == 0U);
  }
  s_fail_flash_read = false;

  /* HIGH-28: 2-of-3 WAL TMR quorum resists single-sector high-seq spoof */
  init_wal_factory_to_deployed(0U);
  wal_tmr_payload_t tmr;
  memset(&tmr, 0, sizeof(tmr));
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.active_stage1_bank = 0U;
  tmr.stage1_svn = 3U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);

  /* Spoof sector 0 alone with seq=999, bank=1, stage1_svn=0 + valid CRC! */
  wal_sector_header_aligned_t spoof;
  memcpy(&spoof, &s_flash[CHIP_WAL_ABS_ADDR], sizeof(spoof));
  spoof.data.sequence_id = 999U;
  spoof.data.tmr_data.active_stage1_bank = 1U;
  spoof.data.tmr_data.stage1_svn = 0U;
  spoof.data.header_crc32 = compute_boot_crc32(
      (const uint8_t *)&spoof.data,
      offsetof(wal_sector_header_t, header_crc32));
  memset(&s_flash[CHIP_WAL_ABS_ADDR], 0xFF, 4096U);
  memcpy(&s_flash[CHIP_WAL_ABS_ADDR], &spoof, sizeof(spoof));

  uint32_t wal_svn = 0U;
  uint32_t chosen_bank = stage0_read_wal_boot_meta(&s_platform, &wal_svn);
  assert(chosen_bank == CHIP_STAGE1A_ABS_ADDR);
  assert(wal_svn == 3U);

  /* CRIT-29: Bank A has downgraded SVN=2 (<3) -> rejected; Bank B has SVN=3 -> accepted! */
  write_signed_stage1(CHIP_STAGE1A_ABS_ADDR, 0x100U, 2U, true, 0x11U);
  write_signed_stage1(CHIP_STAGE1B_ABS_ADDR, 0x100U, 3U, true, 0x22U);

  boot_proof_t proof;
  memset(&proof, 0, sizeof(proof));
  assert(!stage0_try_boot_bank(&s_platform, CHIP_STAGE1A_ABS_ADDR, 0x01U, 3U, &proof));
  assert(stage0_try_boot_bank(&s_platform, CHIP_STAGE1B_ABS_ADDR, 0x01U, 3U, &proof));
  assert(proof.svn == 3U);

  /* CRIT-29: Bank without TBS1 magic (img_svn=0) rejected when svn_floor >= 1! */
  write_signed_stage1(CHIP_STAGE1B_ABS_ADDR, 0x100U, 0U, false, 0x22U);
  assert(!stage0_try_boot_bank(&s_platform, CHIP_STAGE1B_ABS_ADDR, 0x01U, 1U, &proof));
  printf("      PASS\n");
}

/* ============================================================================
 * 2. MED-25 + toob_confirm_boot(): Tentative Rollback & Confirm .noinit Sync
 * ============================================================================ */
static void test_tentative_handoff_and_confirm_sync(void) {
  printf("[2/6] Testing MED-25 Stage 0 tentative CRC/SOFTWARE reset + toob_confirm_boot() .noinit sync...\n");

  sim_format_all();
  g_platform = &s_platform;
  init_wal_factory_to_deployed(0U);

  /* Corrupt CRC in .noinit -> Stage 0 must NOT flip bank even on WATCHDOG reset */
  toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
  toob_handoff_state.magic = TOOB_STATE_TENTATIVE;
  toob_handoff_state.boot_nonce = 0x1122334455667788ULL;
  toob_handoff_state.crc32_trailer = 0xDEADBEEFU;
  s_reset_reason = RESET_REASON_WATCHDOG;
  assert(stage0_evaluate_tentative(&s_platform, CHIP_STAGE1B_ABS_ADDR) ==
         CHIP_STAGE1B_ABS_ADDR);

  /* Valid CRC + TENTATIVE + RESET_REASON_SOFTWARE -> flips bank AND zeroizes handoff! */
  memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
  toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
  toob_handoff_state.magic = TOOB_STATE_TENTATIVE;
  toob_handoff_state.boot_nonce = 0x1122334455667788ULL;
  toob_handoff_state.crc32_trailer = compute_boot_crc32(
      (const uint8_t *)&toob_handoff_state,
      offsetof(toob_handoff_t, crc32_trailer));
  s_reset_reason = RESET_REASON_SOFTWARE;
  assert(stage0_evaluate_tentative(&s_platform, CHIP_STAGE1B_ABS_ADDR) ==
         CHIP_STAGE1A_ABS_ADDR);
  assert(toob_handoff_state.magic == 0U);
  assert(toob_handoff_state.boot_nonce == 0ULL);

  /* Valid tentative boot -> OS calls toob_confirm_boot() -> .noinit becomes COMMITTED ->
   * subsequent RESET_REASON_SOFTWARE reboot does NOT roll back! */
  toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
  toob_handoff_state.magic = TOOB_STATE_TENTATIVE;
  toob_handoff_state.boot_nonce = 0xCAFEBABE12345678ULL;
  toob_handoff_state.crc32_trailer = compute_boot_crc32(
      (const uint8_t *)&toob_handoff_state,
      offsetof(toob_handoff_t, crc32_trailer));

  assert(toob_confirm_boot() == TOOB_OK);
  assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
  assert(stage0_evaluate_tentative(&s_platform, CHIP_STAGE1B_ABS_ADDR) ==
         CHIP_STAGE1B_ABS_ADDR);
  printf("      PASS\n");
}

/* ============================================================================
 * 3. CRIT-30 & HIGH-27: Multi-Image Bitmap Guard & Flash CRC32 Stream Guards
 * ============================================================================ */
static void test_multiimage_and_crc32_guards(void) {
  printf("[3/6] Testing CRIT-30 (component_id < 32) & HIGH-27 (boot_crc32_flash_stream guards)...\n");

  sim_format_all();
  uint8_t arena[1024];
  uint32_t crc = 0xFFFFFFFFU;

  assert(boot_crc32_flash_stream(NULL, 0U, 16U, &crc, arena, sizeof(arena)) ==
         BOOT_ERR_INVALID_ARG);
  assert(boot_crc32_flash_stream(&s_platform, 0U, 16U, NULL, arena, sizeof(arena)) ==
         BOOT_ERR_INVALID_ARG);
  assert(boot_crc32_flash_stream(&s_platform, 0U, 0U, &crc, NULL, 0U) == BOOT_OK);
  assert(crc == 0x00000000U);
  assert(boot_crc32_flash_stream(&s_platform, 0U, 16U, &crc, arena, 0U) ==
         BOOT_ERR_INVALID_ARG);
  assert(boot_crc32_flash_stream(&s_platform, 0xFFFFFFF8U, 16U, &crc, arena,
                                 sizeof(arena)) == BOOT_ERR_INVALID_ARG);

  init_wal_factory_to_deployed(0U);
  boot_component_t bad_comp;
  memset(&bad_comp, 0, sizeof(bad_comp));
  bad_comp.component_id = 32U;
  bad_comp.image_size = 64U;
  bad_comp.target_addr = CHIP_NETCORE_SLOT_ABS_ADDR;

  boot_allowed_region_t wl[1] = {{CHIP_NETCORE_SLOT_ABS_ADDR, CHIP_NETCORE_SLOT_SIZE}};
  wal_entry_payload_t txn;
  memset(&txn, 0, sizeof(txn));
  txn.transfer_bitmap[1] = 0xA5A5A5A5U;

  assert(boot_multiimage_apply(&s_platform, CHIP_STAGING_SLOT_ABS_ADDR, &bad_comp,
                               1U, wl, 1U, &txn, arena, sizeof(arena)) ==
         BOOT_ERR_INVALID_ARG);
  assert(txn.transfer_bitmap[1] == 0xA5A5A5A5U);
  printf("      PASS\n");
}

/* ============================================================================
 * 4. MED-26 & LOW-12: libtoob OTA Trim, Glitch-Safe Hash & Recovery Port
 * ============================================================================ */
static void test_ota_trim_and_recovery_port(void) {
  printf("[4/6] Testing MED-26 (toob_ota_trim_total_size, recovery_port erase) & LOW-12...\n");

  sim_format_all();
  g_platform = &s_platform;

  /* MED-26: recovery_port fails fast when get_sector_size fails or returns 0 */
  s_fail_sector_size = true;
  assert(toob_os_flash_erase(CHIP_STAGING_SLOT_ABS_ADDR, 4096U) == TOOB_ERR_FLASH);
  s_fail_sector_size = false;
  s_override_sector_size = 0U;
  assert(toob_os_flash_erase(CHIP_STAGING_SLOT_ABS_ADDR, 4096U) == TOOB_ERR_FLASH);
  s_override_sector_size = 4096U;

  toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
  toob_handoff_state.magic = TOOB_STATE_COMMITTED;
  toob_handoff_state.active_slot = 0U;
  toob_handoff_state.crc32_trailer = compute_boot_crc32(
      (const uint8_t *)&toob_handoff_state,
      offsetof(toob_handoff_t, crc32_trailer));

  uint8_t sample[600];
  memset(sample, 0x3CU, sizeof(sample));
  uint8_t bad_sha[32];
  memset(bad_sha, 0x99U, sizeof(bad_sha));

  toob_ota_ctx_t ota;
  assert(toob_ota_begin(&ota, CHIP_STAGING_SLOT_SIZE, bad_sha) == TOOB_OK);
  assert(toob_ota_process_chunk(&ota, sample, 400U) == TOOB_OK);

  assert(toob_ota_trim_total_size(NULL, 600U) == TOOB_ERR_INVALID_ARG);
  assert(toob_ota_trim_total_size(&ota, 0U) == TOOB_ERR_INVALID_ARG);
  assert(toob_ota_trim_total_size(&ota, 399U) == TOOB_ERR_INVALID_ARG);
  assert(toob_ota_trim_total_size(&ota, CHIP_STAGING_SLOT_SIZE + 1U) ==
         TOOB_ERR_INVALID_ARG);

  assert(toob_ota_trim_total_size(&ota, 600U) == TOOB_OK);
  assert(toob_ota_process_chunk(&ota, sample + 400U, 200U) == TOOB_OK);
  assert(toob_ota_finalize(&ota) == TOOB_ERR_VERIFY);
  printf("      PASS\n");
}

/* ============================================================================
 * 5. HIGH-29, MED-27, LOW-12: boot_main Entry/Erase Guards & TBM1/Delta Guards
 * ============================================================================ */
static void test_core_bounds_and_overflow_guards(void) {
  printf("[5/6] Testing HIGH-29 (boot_main entry bounds), MED-27 (delta/TBM1 overflow), LOW-12 (proof & erase)...\n");

  sim_format_all();

  const uint32_t key[4] = {1U, 2U, 3U, 4U};
  boot_proof_t pr = {.image_addr = CHIP_APP_SLOT_ABS_ADDR,
                     .image_size = 4096U,
                     .entry_point = 0x100U,
                     .svn = 1U};
  boot_proof_seal(&pr, key);
  assert(boot_proof_verify(&pr, key) == BOOT_OK);
  pr.seal[1] ^= 1U;
  assert(boot_proof_verify(&pr, key) == BOOT_ERR_VERIFY);

  boot_target_config_t out_cfg;
  s_flash_hal.max_erase_cycles = 3U;
  assert(boot_main(&s_platform, &out_cfg, key) == BOOT_ERR_INVALID_ARG);
  s_flash_hal.max_erase_cycles = 100000U;

  init_wal_factory_to_deployed(0U);
  s_flash_hal.max_erase_cycles = 2U;
  wal_tmr_payload_t tmr;
  memset(&tmr, 0, sizeof(tmr));
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.app_svn = 9U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_ERR_COUNTER_EXHAUSTED);
  s_flash_hal.max_erase_cycles = 100000U;

  /* MED-27: boot_delta_apply rejects instr_count * sizeof(toob_tds_instr_t) > UINT32_MAX cleanly */
  toob_tds_header_t huge_tds;
  memset(&huge_tds, 0, sizeof(huge_tds));
  huge_tds.magic = TOOB_TDS_MAGIC;
  huge_tds.expected_target_size = 4096U;
  huge_tds.instr_count = 0x20000001U;
  huge_tds.literal_block_offset = 64U;
  huge_tds.header_crc32 = compute_boot_crc32(
      (const uint8_t *)&huge_tds, offsetof(toob_tds_header_t, header_crc32));
  memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], &huge_tds, sizeof(huge_tds));

  uint8_t arena[2048];
  wal_entry_payload_t txn;
  memset(&txn, 0, sizeof(txn));
  assert(boot_delta_apply(&s_platform, CHIP_STAGING_SLOT_ABS_ADDR, 4096U,
                          CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE,
                          CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, &txn,
                          arena, sizeof(arena)) == BOOT_ERR_INVALID_ARG);

  /* HIGH-29: boot_main rejects TSIG-signed App with entry_point == 0 and entry_point >= image_size! */
  sim_format_all();
  init_wal_factory_to_deployed(0U);
  write_signed_slot_image_ex(CHIP_APP_SLOT_ABS_ADDR, 512U, 0U, 0x11U, 0U);

  s_expect_panic = true;
  s_last_panic = BOOT_OK;
  if (setjmp(s_panic_env) == 0) {
    (void)boot_main(&s_platform, &out_cfg, key);
  }
  s_expect_panic = false;
  assert(s_last_panic == BOOT_ERR_FLASH_BOUNDS);

  sim_format_all();
  init_wal_factory_to_deployed(0U);
  write_signed_slot_image_ex(CHIP_APP_SLOT_ABS_ADDR, 512U, 512U, 0x11U, 0U);
  s_expect_panic = true;
  s_last_panic = BOOT_OK;
  if (setjmp(s_panic_env) == 0) {
    (void)boot_main(&s_platform, &out_cfg, key);
  }
  s_expect_panic = false;
  assert(s_last_panic == BOOT_ERR_FLASH_BOUNDS);
  printf("      PASS\n");
}

/* ============================================================================
 * 6. CRIT-29 + FV-10: Stage-1 Self-Update Tentative Rollback & Confirm Ratify
 * ============================================================================ */
static void test_stage1_self_update_lifecycle(void) {
  printf("[6/6] Testing Stage-1 self-update tentative hold -> crash rollback -> confirm ratification...\n");

  sim_format_all();
  g_platform = &s_platform;

  write_signed_stage1(CHIP_STAGE1A_ABS_ADDR, 0x100U, 1U, true, 0x11U);
  write_signed_stage1(CHIP_STAGE1B_ABS_ADDR, 0x100U, 2U, true, 0x22U);

  write_signed_slot_image(CHIP_APP_SLOT_ABS_ADDR, 256U, 0x20U, 0x11U, 0U);
  write_signed_slot_image(CHIP_STAGING_SLOT_ABS_ADDR, 256U, 0x20U, 0x22U, 0U);

  init_wal_factory_to_deployed(0U);
  wal_tmr_payload_t tmr;
  memset(&tmr, 0, sizeof(tmr));
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.active_stage1_bank = 1U;
  tmr.stage1_svn = 1U;
  tmr.active_app_slot = 1U;
  tmr.boot_failure_counter = BOOT_CONFIG_MAX_RETRIES;
  tmr.active_nonce_lo = 0x12345678U;
  tmr.active_nonce_hi = 0x9ABCDEF0U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  s_hw_active_slot = 1U;

  wal_entry_payload_t commit_txn;
  memset(&commit_txn, 0, sizeof(commit_txn));
  commit_txn.magic = WAL_ENTRY_MAGIC;
  commit_txn.intent = WAL_INTENT_TXN_COMMIT;
  assert(boot_journal_append(&s_platform, &commit_txn) == BOOT_OK);

  sim_reset_globals();
  s_reset_reason = RESET_REASON_WATCHDOG;
  uint8_t arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));
  boot_target_config_t out_cfg;
  const uint32_t seal_key[4] = {0x11U, 0x22U, 0x33U, 0x44U};
  assert(boot_state_run(&s_platform, &out_cfg, seal_key, arena, sizeof(arena)) ==
         BOOT_OK);
  assert(out_cfg.active_slot == 0U);
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(tmr.active_stage1_bank == 0U);
  assert(tmr.stage1_svn == 1U);

  /* Now simulate tentative boot of Stage 1B (SVN=2) that SUCCEEDS and confirms! */
  tmr.active_stage1_bank = 1U;
  tmr.active_app_slot = 1U;
  tmr.active_nonce_lo = 0xCAFEBABEU;
  tmr.active_nonce_hi = 0x01020304U;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  s_hw_active_slot = 1U;
  commit_txn.intent = WAL_INTENT_TXN_COMMIT;
  assert(boot_journal_append(&s_platform, &commit_txn) == BOOT_OK);

  toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
  toob_handoff_state.magic = TOOB_STATE_TENTATIVE;
  toob_handoff_state.active_slot = 1U;
  toob_handoff_state.boot_nonce = ((uint64_t)0x01020304U << 32U) | 0xCAFEBABEU;
  toob_handoff_state.crc32_trailer = compute_boot_crc32(
      (const uint8_t *)&toob_handoff_state,
      offsetof(toob_handoff_t, crc32_trailer));
  assert(toob_confirm_boot() == TOOB_OK);

  sim_reset_globals();
  s_reset_reason = RESET_REASON_SOFTWARE;
  assert(boot_state_run(&s_platform, &out_cfg, seal_key, arena, sizeof(arena)) ==
         BOOT_OK);
  assert(out_cfg.is_tentative_boot == false);
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(tmr.active_stage1_bank == 1U);
  assert(tmr.stage1_svn == 2U);
  printf("      PASS\n");
}

static void write_signed_cloud_cmd(const uint8_t cloud_sk[64],
                                   toob_cloud_cmd_t cmd, uint32_t counter_min,
                                   uint32_t issued_at) {
  uint8_t dev_id[32];
  assert(boot_derive_device_id(&s_platform, dev_id) == BOOT_OK);

  toob_cloud_cmd_hdr_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TOOB_CLOUD_CMD_MAGIC;
  hdr.version = TOOB_CLOUD_CMD_VERSION;
  hdr.command = (uint8_t)cmd;
  hdr.counter_min = counter_min;
  hdr.issued_at = issued_at;
  hdr.params_len = 0U;
  hdr.total_len = TOOB_CLOUD_CMD_MIN_SIZE;
  memcpy(hdr.device_id, dev_id, sizeof(dev_id));
  hdr.crc32 = compute_boot_crc32((const uint8_t *)&hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);

  uint8_t env[TOOB_CLOUD_CMD_MIN_SIZE];
  memcpy(env, &hdr, sizeof(hdr));
  crypto_ed25519_sign(env + sizeof(hdr), cloud_sk, env, sizeof(hdr));

  memset(&s_flash[CHIP_CLOUD_CMD_SLOT_ABS_ADDR], 0xFF, CHIP_CLOUD_CMD_SLOT_SIZE);
  memcpy(&s_flash[CHIP_CLOUD_CMD_SLOT_ABS_ADDR], env, sizeof(env));
}

__attribute__((noinline)) static void
run_state_with_panic_trap(boot_target_config_t *out_cfg,
                          const uint32_t seal_key[4], uint8_t *arena,
                          size_t arena_len) {
  s_expect_panic = true;
  s_last_panic = BOOT_OK;
  if (setjmp(s_panic_env) == 0) {
    (void)boot_state_run(&s_platform, out_cfg, seal_key, arena, arena_len);
  }
  s_expect_panic = false;
}

static void test_rocq_audit_fixes_w5(void) {
  printf("[7/7] Testing Rocq W5 fixes: HIGH-31 (mailbox lock), LOW-13 (force_update lock), HIGH-32 (wipe lock), MED-28 (TMR reload)...\n");

  sim_format_all();
  g_platform = &s_platform;

  write_signed_slot_image(CHIP_APP_SLOT_ABS_ADDR, 256U, 0x20U, 0x11U, 0U);

  /* Provision Root-signed KDM into quorum store */
  uint8_t root_sk[64];
  uint8_t root_pk[32];
  crypto_ed25519_key_pair(root_sk, root_pk, (uint8_t[32]){
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60});
  assert(memcmp(root_pk, k_tv1_pub, 32U) == 0);

  uint8_t cloud_sk[64];
  uint8_t cloud_pk[32];
  crypto_ed25519_key_pair(cloud_sk, cloud_pk, (uint8_t[32]){
      0x42, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
      0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
      0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01});

  toob_kdm_t kdm;
  memset(&kdm, 0, sizeof(kdm));
  kdm.sequence_number = 1U;
  memcpy(kdm.new_cloud_pubkey, cloud_pk, sizeof(cloud_pk));
  crypto_ed25519_sign(kdm.signature_ed25519, root_sk, (const uint8_t *)&kdm,
                      offsetof(toob_kdm_t, signature_ed25519));
  assert(boot_rstore_write(&s_platform, &kdm_rstore_desc, &kdm) == BOOT_OK);

  /* Initialize WAL and lock the device */
  init_wal_factory_to_deployed(0U);
  wal_entry_payload_t lock_txn;
  memset(&lock_txn, 0, sizeof(lock_txn));
  lock_txn.magic = WAL_ENTRY_MAGIC;
  lock_txn.intent = WAL_INTENT_DEVICE_LOCKED;
  assert(boot_journal_append(&s_platform, &lock_txn) == BOOT_OK);

  /* 1. HIGH-31: Unauthenticated OS mailbox MUST NOT overwrite WAL_INTENT_DEVICE_LOCKED */
  toob_mailbox_t mbx;
  memset(&mbx, 0, sizeof(mbx));
  mbx.magic = TOOB_MAILBOX_MAGIC;
  mbx.version = TOOB_MAILBOX_VERSION;
  mbx.request = TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED;
  mbx.seq = 5U;
  mbx.tbm1_addr = CHIP_STAGING_SLOT_ABS_ADDR;
  mbx.crc32 = compute_boot_crc32((const uint8_t *)&mbx, TOOB_MAILBOX_CRC_LEN);
  memcpy(&s_flash[CHIP_MAILBOX_ABS_ADDR], &mbx, sizeof(mbx));

  assert(boot_mailbox_consume(&s_platform) == BOOT_OK);
  wal_entry_payload_t check_txn;
  memset(&check_txn, 0, sizeof(check_txn));
  assert(boot_journal_reconstruct_txn(&s_platform, &check_txn, NULL, NULL) ==
         BOOT_OK);
  assert(check_txn.intent == (uint32_t)WAL_INTENT_DEVICE_LOCKED);
  wal_tmr_payload_t tmr;
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(tmr.last_mbx_request_id == 5U);

  /* 2. LOW-13: TOOB_CMD_FORCE_UPDATE while locked consumes slot & advances counter,
   *    leaves WAL_INTENT_DEVICE_LOCKED intact, and halts with BOOT_ERR_DEVICE_LOCKED */
  write_signed_cloud_cmd(cloud_sk, TOOB_CMD_FORCE_UPDATE, 1U, 100U);
  sim_reset_globals();
  uint8_t arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));
  boot_target_config_t out_cfg;
  const uint32_t seal_key[4] = {0xAAU, 0xBBU, 0xCCU, 0xDDU};
  run_state_with_panic_trap(&out_cfg, seal_key, arena, sizeof(arena));
  assert(s_last_panic == BOOT_ERR_DEVICE_LOCKED);
  assert(s_otp_svn == 1U);
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(tmr.last_accepted_issued_at == 100U);
  assert(boot_journal_reconstruct_txn(&s_platform, &check_txn, NULL, NULL) ==
         BOOT_OK);
  assert(check_txn.intent == (uint32_t)WAL_INTENT_DEVICE_LOCKED);

  /* 3. HIGH-32: TOOB_CMD_WIPE while locked clears open_txn.intent in RAM & WAL so
   *    Step 2.7 succeeds without false panic and sets target_out->wipe_requested */
  write_signed_cloud_cmd(cloud_sk, TOOB_CMD_WIPE, 2U, 200U);
  sim_reset_globals();
  assert(boot_state_run(&s_platform, &out_cfg, seal_key, arena, sizeof(arena)) ==
         BOOT_OK);
  assert(out_cfg.wipe_requested == true);
  assert(s_otp_svn == 2U);
  assert(boot_journal_reconstruct_txn(&s_platform, &check_txn, NULL, NULL) ==
         BOOT_OK);
  assert(check_txn.intent == (uint32_t)WAL_INTENT_NONE);
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(tmr.last_accepted_issued_at == 200U);

  /* 4. MED-28: Reload current_tmr after handle_cloud_cmd so subsequent TMR
   *    mutations (Step 3 EV_CRASH + Step 5 flush) preserve last_accepted_issued_at */
  write_signed_cloud_cmd(cloud_sk, TOOB_CMD_UNLOCK, 3U, 300U);
  sim_reset_globals();
  s_reset_reason = RESET_REASON_WATCHDOG;
  assert(boot_state_run(&s_platform, &out_cfg, seal_key, arena, sizeof(arena)) ==
         BOOT_OK);
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  assert(tmr.boot_failure_counter == 1U);
  assert(tmr.last_accepted_issued_at == 300U);

  printf("      PASS\n");
}

static void stage_signed_trailer_tbm1(uint32_t slot_base, uint32_t svn,
                                      uint32_t build_num, uint16_t maj,
                                      uint16_t min, uint16_t pat,
                                      bool corrupt_payload_after_sign) {
  uint8_t img[512];
  memset(img, (uint8_t)(0x40U + (svn & 0x0FU)), sizeof(img));
  toob_image_header_t app_hdr;
  memset(&app_hdr, 0, sizeof(app_hdr));
  app_hdr.magic = TOOB_MAGIC_HEADER;
  app_hdr.image_size = (uint32_t)sizeof(img);
  app_hdr.entry_point = 0x40U;
  memcpy(img, &app_hdr, sizeof(app_hdr));

  uint8_t sk[64];
  uint8_t pk[32];
  crypto_ed25519_key_pair(sk, pk, (uint8_t[32]){
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60});

  uint32_t tsig_signed_len =
      (uint32_t)(sizeof(img) - sizeof(toob_img_sig_trailer_t));
  uint8_t tsig_digest[32];
  uint8_t sha_ctx[256] __attribute__((aligned(8)));
  size_t dlen = sizeof(tsig_digest);
  assert(crypto_sha256_init(sha_ctx, sizeof(sha_ctx)) == BOOT_OK);
  assert(crypto_sha256_update(sha_ctx, img, tsig_signed_len) == BOOT_OK);
  assert(crypto_sha256_finish(sha_ctx, tsig_digest, &dlen) == BOOT_OK);

  toob_img_sig_trailer_t tsig;
  memset(&tsig, 0, sizeof(tsig));
  tsig.magic = TOOB_IMG_SIG_MAGIC;
  tsig.key_index = 0U;
  tsig.flags = TOOB_IMG_SIG_FLAG_SHA256;
  tsig.reserved = 0U;
  crypto_ed25519_sign(tsig.sig_ed25519, sk, tsig_digest, sizeof(tsig_digest));
  memcpy(img + tsig_signed_len, &tsig, sizeof(tsig));

  uint8_t chunk_hash[32];
  dlen = sizeof(chunk_hash);
  assert(crypto_sha256_init(sha_ctx, sizeof(sha_ctx)) == BOOT_OK);
  assert(crypto_sha256_update(sha_ctx, img, sizeof(img)) == BOOT_OK);
  assert(crypto_sha256_finish(sha_ctx, chunk_hash, &dlen) == BOOT_OK);

  if (corrupt_payload_after_sign) {
    img[sizeof(toob_image_header_t) + 8U] ^= 0xFFU;
  }

  uint8_t tbm1_block[TBM1_FIXED_LEN + 32U + TBM1_SIG_LEN] __attribute__((aligned(8)));
  memset(tbm1_block, 0, sizeof(tbm1_block));
  tbm1_header_t *th = (tbm1_header_t *)tbm1_block;
  th->magic = TBM1_MAGIC;
  th->version_major = TBM1_VERSION_MAJOR;
  th->version_minor = TBM1_VERSION_MINOR;
  th->fixed_len = TBM1_FIXED_LEN;
  th->total_len = (uint32_t)sizeof(tbm1_block);
  th->flags_critical = TBM1_CRIT_TRAILER_LAYOUT;
  th->vendor_id = TOOB_DEVICE_VENDOR_ID;
  th->product_id = TOOB_DEVICE_PRODUCT_ID;
  th->hw_rev_min = TOOB_DEVICE_HW_REV;
  th->hw_rev_max = TOOB_DEVICE_HW_REV;
  th->key_index = 0U;
  th->image_count = 1U;
  th->boot_retry_limit = BOOT_CONFIG_MAX_RETRIES;
  th->min_reader_major = TBM1_VERSION_MAJOR;
  th->min_reader_minor = TBM1_VERSION_MINOR;
  th->svn = svn;
  th->build_number = build_num;
  th->fw_ver_major = maj;
  th->fw_ver_minor = min;
  th->fw_ver_patch = pat;
  memset(th->sbom_digest, (int)(0xA0U + svn), sizeof(th->sbom_digest));

  th->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
  th->regions[0].off = TBM1_FIXED_LEN;
  th->regions[0].len = 32U;

  th->images[0].target_slot = TBM1_SLOT_APP;
  th->images[0].compression_alg = TBM1_COMP_NONE;
  th->images[0].delta_alg = TBM1_DELTA_NONE;
  th->images[0].data_off = 0U;
  th->images[0].stored_size = (uint32_t)sizeof(img);
  th->images[0].installed_size = (uint32_t)sizeof(img);
  th->images[0].chunk_size = 4096U;
  th->images[0].num_chunks = 1U;
  th->images[0].ver_major = maj;
  th->images[0].ver_minor = min;
  th->images[0].ver_patch = pat;

  th->fixed_crc32 = compute_boot_crc32(tbm1_block, TBM1_CRC_LEN);
  memcpy(tbm1_block + TBM1_FIXED_LEN, chunk_hash, 32U);

  crypto_ed25519_sign(tbm1_block + TBM1_FIXED_LEN + 32U, sk,
                      tbm1_block, TBM1_FIXED_LEN + 32U);

  uint32_t tbm1_off = 4096U;
  memset(&s_flash[slot_base], 0xFF, 8192U);
  memcpy(&s_flash[slot_base], img, sizeof(img));
  memcpy(&s_flash[slot_base + tbm1_off], tbm1_block, sizeof(tbm1_block));

  wal_entry_payload_t upd;
  memset(&upd, 0, sizeof(upd));
  upd.magic = WAL_ENTRY_MAGIC;
  upd.intent = WAL_INTENT_UPDATE_PENDING;
  upd.offset = slot_base + tbm1_off;
  assert(boot_journal_append(&s_platform, &upd) == BOOT_OK);
}

static void test_tdr1_perfection_fixes(void) {
  printf("[8/8] Testing TDR1-01..07: reader_major/minor, WAL_TMR_VERSION_8 persistence & rollback atomicity, commit-point discipline...\n");

  sim_format_all();
  g_platform = &s_platform;
  write_signed_slot_image(CHIP_APP_SLOT_ABS_ADDR, 512U, 0x40U, 0x33U, 0U);
  init_wal_factory_to_deployed(1U);
  sim_reset_globals();

  boot_target_config_t out_cfg;
  const uint32_t seal_key[4] = {0xA1U, 0xB2U, 0xC3U, 0xD4U};

  /* 1. Cold boot: reader_major=2, reader_minor=1, monotonic_counter=1 */
  assert(boot_main(&s_platform, &out_cfg, seal_key) == BOOT_OK);
  assert(toob_diag_state.reader_major == TBM1_VERSION_MAJOR);
  assert(toob_diag_state.reader_minor == TBM1_VERSION_MINOR);
  assert(toob_diag_state.monotonic_counter == 1U);
  assert(toob_diag_state.last_update_outcome == 0U);
  assert(toob_handoff_state.boot_failure_count == 0U);

  /* 2. Stage valid OTA v1.2.3 (svn=2, build=202) into Slot 1 -> tentative boot */
  sim_reset_globals();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  stage_signed_trailer_tbm1(CHIP_STAGING_SLOT_ABS_ADDR, 2U, 202U, 1U, 2U, 3U, false);

  sim_reset_globals();
  assert(boot_main(&s_platform, &out_cfg, seal_key) == BOOT_OK);
  assert(out_cfg.is_tentative_boot == true);
  assert(out_cfg.active_slot == 1U);
  assert(toob_diag_state.last_update_outcome == 1U);
  assert(toob_diag_state.current_svn == 2U);
  assert(toob_diag_state.build_number == 202U);
  assert(toob_diag_state.fw_ver_major == 1U);
  assert(toob_diag_state.fw_ver_minor == 2U);
  assert(toob_diag_state.fw_ver_patch == 3U);

  /* Confirm & warm-reboot WITHOUT an update -> WAL_TMR_VERSION_8 preserves identity! */
  assert(toob_confirm_boot() == TOOB_OK);
  sim_reset_globals();
  s_reset_reason = RESET_REASON_SOFTWARE;
  assert(boot_main(&s_platform, &out_cfg, seal_key) == BOOT_OK);
  assert(out_cfg.is_tentative_boot == false);
  assert(toob_diag_state.last_update_outcome == 0U);
  assert(toob_diag_state.current_svn == 2U);
  assert(toob_diag_state.build_number == 202U);
  assert(toob_diag_state.fw_ver_major == 1U);
  assert(toob_diag_state.fw_ver_minor == 2U);
  assert(toob_diag_state.fw_ver_patch == 3U);
  assert(toob_diag_state.monotonic_counter == 1U);
  assert(toob_diag_state.reader_major == TBM1_VERSION_MAJOR);
  assert(toob_diag_state.reader_minor == TBM1_VERSION_MINOR);

  /* 3. TDR1-03 Commit-Point Discipline: valid Ed25519 signature for v9.9.9 (svn=3, build=999)
   *    but corrupted Merkle payload in inactive Slot 0 -> rejected (outcome=2) WITHOUT
   *    contaminating installed v1.2.3 (svn=2, build=202) telemetry! */
  sim_reset_globals();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  stage_signed_trailer_tbm1(CHIP_APP_SLOT_ABS_ADDR, 3U, 999U, 9U, 9U, 9U, true);

  sim_reset_globals();
  s_reset_reason = RESET_REASON_SOFTWARE;
  assert(boot_main(&s_platform, &out_cfg, seal_key) == BOOT_OK);
  assert(out_cfg.active_slot == 1U);
  assert(toob_diag_state.last_update_outcome == 2U);
  assert(toob_diag_state.current_svn == 2U);
  assert(toob_diag_state.build_number == 202U);
  assert(toob_diag_state.fw_ver_major == 1U);
  assert(toob_diag_state.fw_ver_minor == 2U);
  assert(toob_diag_state.fw_ver_patch == 3U);

  /* 4. TDR1-02 + TDR1-06 Rollback Atomicity: stage valid v3.4.5 (svn=3, build=305) into Slot 0,
   *    boot tentatively, then simulate WDT crash -> reverts to Slot 1 (v1.2.3, build=202) with
   *    outcome=3 (reverted), fallback_occurred=1, edge_recovery_events=1, boot_failure_count=1! */
  sim_reset_globals();
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  stage_signed_trailer_tbm1(CHIP_APP_SLOT_ABS_ADDR, 3U, 305U, 3U, 4U, 5U, false);

  sim_reset_globals();
  s_reset_reason = RESET_REASON_SOFTWARE;
  assert(boot_main(&s_platform, &out_cfg, seal_key) == BOOT_OK);
  assert(out_cfg.is_tentative_boot == true);
  assert(out_cfg.active_slot == 0U);
  assert(toob_diag_state.build_number == 305U);
  assert(toob_diag_state.fw_ver_major == 3U);

  sim_reset_globals();
  s_reset_reason = RESET_REASON_WATCHDOG;
  assert(boot_main(&s_platform, &out_cfg, seal_key) == BOOT_OK);
  assert(out_cfg.is_tentative_boot == false);
  assert(out_cfg.active_slot == 1U);
  assert(toob_diag_state.last_update_outcome == 3U);
  assert(toob_diag_state.fallback_occurred == 1U);
  assert(toob_diag_state.edge_recovery_events == 1U);
  assert(toob_handoff_state.boot_failure_count == 1U);
  assert(toob_diag_state.current_svn == 3U);
  assert(toob_diag_state.build_number == 202U);
  assert(toob_diag_state.fw_ver_major == 1U);
  assert(toob_diag_state.fw_ver_minor == 2U);
  assert(toob_diag_state.fw_ver_patch == 3U);

  /* 5. TDR1-07 Saturating verify_time & .noinit read-back CRC seal */
  boot_diag_init();
  boot_diag_add_verify_time(UINT32_MAX - 5U);
  boot_diag_add_verify_time(100U);
  assert(boot_diag_seal() == BOOT_OK);
  assert(toob_diag_state.verify_time_ms == UINT32_MAX);

  printf("      PASS\n");
}

static uint8_t s_cobs_rx_fifo[128];
static size_t s_cobs_rx_head = 0U;
static size_t s_cobs_rx_tail = 0U;

static boot_status_t sim_cobs_console_init(uint32_t baud) {
  (void)baud;
  return BOOT_OK;
}
static void sim_cobs_console_deinit(void) {}
static void sim_cobs_console_putchar(char c) { (void)c; }
static void sim_cobs_console_flush(void) {}
static boot_status_t sim_cobs_console_getchar(uint8_t *out, uint32_t timeout_ms) {
  (void)timeout_ms;
  if (!out || s_cobs_rx_tail >= s_cobs_rx_head) {
    return BOOT_ERR_TIMEOUT;
  }
  *out = s_cobs_rx_fifo[s_cobs_rx_tail++];
  return BOOT_OK;
}

static const console_hal_t s_cobs_console_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_cobs_console_init,
    .deinit = sim_cobs_console_deinit,
    .putchar = sim_cobs_console_putchar,
    .getchar = sim_cobs_console_getchar,
    .flush = sim_cobs_console_flush,
};

static void test_wave1_wave2_security_regressions(void) {
  printf("[9/9] Testing Wave-1/Wave-2 security regressions (CRIT-68..71, HIGH-102/114, MED-91, Stage0/TBM1/Delta)...\n");
  uint8_t arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));
  const uint32_t seal_key[4] = {0xDEADBEEFU, 0xCAFEBABEU, 0x12345678U, 0x9ABCDEF0U};

  /* (a) CRIT-68/71: Unsigned App, Recovery, and Rollback images rejected with BOOT_ERR_VERIFY */
  {
    sim_format_all();
    g_platform = &s_platform;
    init_wal_factory_to_deployed(0U);

    toob_image_header_t unsigned_hdr;
    memset(&unsigned_hdr, 0, sizeof(unsigned_hdr));
    unsigned_hdr.magic = TOOB_MAGIC_HEADER;
    unsigned_hdr.image_size = 256U;
    unsigned_hdr.entry_point = 0x20U;
    memset(&s_flash[CHIP_APP_SLOT_ABS_ADDR], 0x5AU, 256U);
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], &unsigned_hdr, sizeof(unsigned_hdr));
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &unsigned_hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* Undersized image < sizeof(hdr) + sizeof(toob_img_sig_trailer_t) also fails */
    unsigned_hdr.image_size = 64U;
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], &unsigned_hdr, sizeof(unsigned_hdr));
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &unsigned_hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_INVALID_ARG);

    /* Unsigned Rollback backup in staging slot rejected */
    unsigned_hdr.image_size = 256U;
    memset(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], 0x6BU, 256U);
    memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], &unsigned_hdr, sizeof(unsigned_hdr));
    assert(boot_verify_slot_image(&s_platform, CHIP_STAGING_SLOT_ABS_ADDR,
                                  CHIP_STAGING_SLOT_SIZE, &unsigned_hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* Unsigned Recovery OS rejected when falling back from erased App slot */
    memset(&s_flash[CHIP_APP_SLOT_ABS_ADDR], 0xFF, 256U);
    memset(&s_flash[CHIP_RECOVERY_OS_ABS_ADDR], 0x7CU, 256U);
    memcpy(&s_flash[CHIP_RECOVERY_OS_ABS_ADDR], &unsigned_hdr, sizeof(unsigned_hdr));
    boot_target_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    sim_reset_globals();
    assert(boot_state_run(&s_platform, &cfg, seal_key, arena, sizeof(arena)) == BOOT_ERR_VERIFY);
  }

  /* (b) CRIT-68: Tampered TSIG trailer fields, payload, zero sig, and key-index downgrade rejected */
  {
    sim_format_all();
    g_platform = &s_platform;
    write_signed_slot_image(CHIP_APP_SLOT_ABS_ADDR, 256U, 0x20U, 0x33U, 0U);
    toob_image_header_t hdr;
    memcpy(&hdr, &s_flash[CHIP_APP_SLOT_ABS_ADDR], sizeof(hdr));
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_OK);

    const uint32_t tsig_off = hdr.image_size - (uint32_t)sizeof(toob_img_sig_trailer_t);
    uint8_t saved_img[256];
    memcpy(saved_img, &s_flash[CHIP_APP_SLOT_ABS_ADDR], sizeof(saved_img));

    /* Tampered signature byte */
    s_flash[CHIP_APP_SLOT_ABS_ADDR + tsig_off + 8U] ^= 0x01U;
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* Tampered TSIG magic */
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], saved_img, sizeof(saved_img));
    s_flash[CHIP_APP_SLOT_ABS_ADDR + tsig_off] ^= 0xFFU;
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* Invalid TSIG flags */
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], saved_img, sizeof(saved_img));
    s_flash[CHIP_APP_SLOT_ABS_ADDR + tsig_off + 5U] = 0x02U;
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* Non-zero TSIG reserved bytes */
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], saved_img, sizeof(saved_img));
    s_flash[CHIP_APP_SLOT_ABS_ADDR + tsig_off + 6U] = 0x01U;
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* All-zero Ed25519 signature */
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], saved_img, sizeof(saved_img));
    memset(&s_flash[CHIP_APP_SLOT_ABS_ADDR + tsig_off + 8U], 0, 64U);
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* Tampered signed payload */
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], saved_img, sizeof(saved_img));
    s_flash[CHIP_APP_SLOT_ABS_ADDR + 32U] ^= 0x80U;
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* Revoked key_index=0 once OTP slot 1 is populated */
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], saved_img, sizeof(saved_img));
    s_otp_key_count = 2U;
    assert(boot_verify_slot_image(&s_platform, CHIP_APP_SLOT_ABS_ADDR,
                                  CHIP_APP_SLOT_SIZE, &hdr,
                                  arena, sizeof(arena)) == BOOT_ERR_DOWNGRADE);
    s_otp_key_count = 1U;
  }

  /* (c) CRIT-70: PQC pubkey hash mismatch rejected when TOOB_PQC_ENABLED */
  {
    sim_format_all();
    g_platform = &s_platform;
    uint8_t sk[64];
    uint8_t pk[32];
    crypto_ed25519_key_pair(sk, pk, (uint8_t[32]){
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
        0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
        0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60});

    uint8_t man[256];
    memset(man, 0x21U, sizeof(man));
#if TOOB_PQC_ENABLED
    const size_t pqc_pub_off = 64U;
    const size_t pqc_sig_off = 96U;
    for (size_t i = 0U; i < 32U; i++) {
      man[pqc_pub_off + i] = (uint8_t)(0x40U + i);
      man[pqc_sig_off + i] = (uint8_t)(0x80U + i);
    }
    uint8_t ctx[256] __attribute__((aligned(8)));
    size_t dlen = sizeof(s_pqc_pinned_hash);
    assert(crypto_sha256_init(ctx, sizeof(ctx)) == BOOT_OK);
    assert(crypto_sha256_update(ctx, man + pqc_pub_off, 32U) == BOOT_OK);
    assert(crypto_sha256_finish(ctx, s_pqc_pinned_hash, &dlen) == BOOT_OK);
    s_pqc_enforced_flag = true;
#endif
    memcpy(arena, man, sizeof(man));
    crypto_ed25519_sign(arena + sizeof(man), sk, man, sizeof(man));

    boot_verify_envelope_t env;
    memset(&env, 0, sizeof(env));
    env.manifest_flash_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    env.manifest_size = sizeof(man);
    env.signature_ed25519 = arena + sizeof(man);
    env.key_index = 0U;
#if TOOB_PQC_ENABLED
    env.pqc_hybrid_active = true;
    env.pubkey_pqc = arena + pqc_pub_off;
    env.pubkey_pqc_len = 32U;
    env.signature_pqc = arena + pqc_sig_off;
    env.signature_pqc_len = 32U;
#endif
    assert(boot_verify_manifest_envelope(&s_platform, &env, arena, sizeof(arena)) == BOOT_OK);

#if TOOB_PQC_ENABLED
    /* Attacker substitutes rogue PQC pubkey while holding valid Ed25519 signature */
    man[pqc_pub_off] ^= 0x01U;
    memcpy(arena, man, sizeof(man));
    crypto_ed25519_sign(arena + sizeof(man), sk, man, sizeof(man));
    assert(boot_verify_manifest_envelope(&s_platform, &env, arena, sizeof(arena)) ==
           BOOT_ERR_VERIFY);
#endif
  }

  /* (d) CRIT-69: Blank WAL on deployed device (dslc != 0 or efuse_epoch > 0) refuses init */
  {
    sim_format_all();
    s_dslc_state = 0x01U;
    s_otp_svn = 0U;
    assert(boot_journal_init(&s_platform) == BOOT_ERR_VERIFY);

    sim_format_all();
    s_dslc_state = 0x00U;
    s_otp_svn = 1U;
    assert(boot_journal_init(&s_platform) == BOOT_ERR_VERIFY);
  }

  /* (e) HIGH-102: Legacy WAL header rejected with BOOT_ERR_ABI_MISMATCH */
  {
    sim_format_all();
    wal_sector_header_v1_t legacy;
    memset(&legacy, 0, sizeof(legacy));
    legacy.sector_magic = WAL_ABI_VERSION_MAGIC_LEGACY;
    legacy.sequence_id = 1U;
    legacy.erase_count = 1U;
    legacy.tmr_data.app_svn = 1U;
    legacy.header_crc32 = compute_boot_crc32(
        (const uint8_t *)&legacy, offsetof(wal_sector_header_v1_t, header_crc32));
    memcpy(&s_flash[CHIP_WAL_ABS_ADDR], &legacy, sizeof(legacy));
    s_dslc_state = 0x01U;
    assert(boot_journal_init(&s_platform) == BOOT_ERR_ABI_MISMATCH);
  }

  /* (f) HIGH-114: COBS RX overflow drains until 0x00 delimiter before accepting next frame */
  {
    boot_platform_t cobs_plat = s_platform;
    cobs_plat.console = &s_cobs_console_hal;
    s_cobs_rx_head = 0U;
    s_cobs_rx_tail = 0U;

    /* 24-byte overflowing garbage frame (> 16-byte rx_buf) + 0x00 delimiter */
    for (size_t i = 0U; i < 24U; i++) {
      s_cobs_rx_fifo[s_cobs_rx_head++] = (uint8_t)(0x41U + (i & 0x0FU));
    }
    s_cobs_rx_fifo[s_cobs_rx_head++] = 0x00U;
    /* Followed immediately by valid COBS-encoded {0x11, 0x22, 0x33} */
    s_cobs_rx_fifo[s_cobs_rx_head++] = 0x04U;
    s_cobs_rx_fifo[s_cobs_rx_head++] = 0x11U;
    s_cobs_rx_fifo[s_cobs_rx_head++] = 0x22U;
    s_cobs_rx_fifo[s_cobs_rx_head++] = 0x33U;
    s_cobs_rx_fifo[s_cobs_rx_head++] = 0x00U;

    uint8_t rx_buf[16];
    memset(rx_buf, 0xCC, sizeof(rx_buf));
    size_t rx_len = 0U;
    assert(boot_cobs_recv_frame(&cobs_plat, rx_buf, sizeof(rx_buf), &rx_len) == BOOT_OK);
    assert(rx_len == 4U);
    assert(rx_buf[0] == 0x04U && rx_buf[1] == 0x11U && rx_buf[2] == 0x22U && rx_buf[3] == 0x33U);
    size_t dec_len = 0U;
    assert(boot_cobs_decode_in_place(rx_buf, rx_len, &dec_len) == BOOT_OK);
    assert(dec_len == 3U);
    assert(rx_buf[0] == 0x11U && rx_buf[1] == 0x22U && rx_buf[2] == 0x33U);
  }

  /* (g) MED-91: Mailbox seq RFC-1982 wrap-around 0xFFFFFFFF -> 0x00000001 (seq=0 invalid) */
  {
    assert(mbx_seq_is_newer(1U, 0xFFFFFFFFU) == true);
    assert(mbx_seq_is_newer(0xFFFFFFFFU, 1U) == false);
    assert(mbx_seq_is_newer(0U, 0xFFFFFFFFU) == false);
    assert(mbx_seq_is_newer(0x7FFFFFFEU, 0xFFFFFFFFU) == true);

    sim_format_all();
    init_wal_factory_to_deployed(0U);
    wal_tmr_payload_t tmr;
    assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
    tmr.last_mbx_request_id = 0xFFFFFFFEU;
    tmr.active_nonce_lo = 0xCAFE0002U;
    tmr.active_nonce_hi = 0xCAFE0001U;
    assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);

    toob_mailbox_t mbx0;
    memset(&mbx0, 0, sizeof(mbx0));
    mbx0.magic = TOOB_MAILBOX_MAGIC;
    mbx0.version = TOOB_MAILBOX_VERSION;
    mbx0.request = TOOB_REQ_UPDATE_PENDING;
    mbx0.seq = 0xFFFFFFFFU;
    mbx0.tbm1_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    mbx0.crc32 = compute_boot_crc32((const uint8_t *)&mbx0, TOOB_MAILBOX_CRC_LEN);
    memcpy(&s_flash[CHIP_MAILBOX_ABS_ADDR], &mbx0, sizeof(mbx0));

    toob_mailbox_t mbx1;
    memset(&mbx1, 0, sizeof(mbx1));
    mbx1.magic = TOOB_MAILBOX_MAGIC;
    mbx1.version = TOOB_MAILBOX_VERSION;
    mbx1.request = TOOB_REQ_CONFIRM;
    mbx1.seq = 1U;
    mbx1.nonce = 0xCAFE0001CAFE0002ULL;
    mbx1.crc32 = compute_boot_crc32((const uint8_t *)&mbx1, TOOB_MAILBOX_CRC_LEN);
    memcpy(&s_flash[CHIP_MAILBOX_ABS_ADDR + CHIP_MAILBOX_SLOT_SIZE], &mbx1, sizeof(mbx1));

    assert(boot_mailbox_consume(&s_platform) == BOOT_OK);
    assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
    assert(tmr.last_mbx_request_id == 1U);
    wal_entry_payload_t rec_txn;
    memset(&rec_txn, 0, sizeof(rec_txn));
    assert(boot_journal_reconstruct_txn(&s_platform, &rec_txn, NULL, NULL) == BOOT_OK);
    assert(rec_txn.intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT);
  }

  /* (h) TBM1/delta/rdelta boundary/alignment hardening & Stage-0 non-overlap / efuse_epoch check */
  {
    /* TBM1 precheck/region/rdelta alignment & ordering */
    uint8_t raw_tbm1[1024] __attribute__((aligned(8)));
    memset(raw_tbm1, 0, sizeof(raw_tbm1));
    assert(tbm1_precheck(raw_tbm1 + 1U, sizeof(raw_tbm1) - 1U) == TBM1_BAD_ALIGN);

    tbm1_header_t *th = (tbm1_header_t *)raw_tbm1;
    const uint32_t rdelta_len = (uint32_t)sizeof(tbm1_rdelta_desc_t);
    th->magic = TBM1_MAGIC;
    th->version_major = TBM1_VERSION_MAJOR;
    th->version_minor = TBM1_VERSION_MINOR;
    th->fixed_len = TBM1_FIXED_LEN;
    th->total_len = TBM1_FIXED_LEN + 32U + 4U + rdelta_len + TBM1_SIG_LEN;
    th->vendor_id = TOOB_DEVICE_VENDOR_ID;
    th->product_id = TOOB_DEVICE_PRODUCT_ID;
    th->hw_rev_min = 1U;
    th->hw_rev_max = 1U;
    th->image_count = 1U;
    th->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
    th->regions[0].off = TBM1_FIXED_LEN;
    th->regions[0].len = 32U;
    th->regions[1].region_id = TBM1_REGION_REVERSE_DELTA;
    th->regions[1].off = TBM1_FIXED_LEN + 32U + 4U; /* Deliberate 4B misalignment */
    th->regions[1].len = rdelta_len;
    th->images[0].target_slot = TBM1_SLOT_APP;
    th->images[0].compression_alg = TBM1_COMP_NONE;
    th->images[0].delta_alg = TBM1_DELTA_NONE;
    th->images[0].data_off = 0U;
    th->images[0].stored_size = 512U;
    th->images[0].installed_size = 512U;
    th->images[0].chunk_size = 4096U;
    th->images[0].num_chunks = 1U;
    th->fixed_crc32 = compute_boot_crc32(raw_tbm1, TBM1_CRC_LEN);

    uint32_t out_off[TBM1_MAX_IMAGES];
    assert(tbm1_validate(raw_tbm1, sizeof(raw_tbm1), 65536U, out_off) == TBM1_BAD_REGION_ALIGN);

    /* Align rdelta region to 8 bytes, but test overlapping rdelta->data_off and restored_size==0 */
    th->regions[1].off = TBM1_FIXED_LEN + 32U;
    th->total_len = TBM1_FIXED_LEN + 32U + rdelta_len + TBM1_SIG_LEN;
    tbm1_rdelta_desc_t *rd = (tbm1_rdelta_desc_t *)(raw_tbm1 + th->regions[1].off);
    rd->target_slot = TBM1_SLOT_APP;
    rd->delta_alg = TBM1_DELTA_TDS1;
    rd->data_off = 256U; /* Overlaps images[0] [0..512) */
    rd->stored_size = 128U;
    rd->restored_size = 512U;
    th->fixed_crc32 = compute_boot_crc32(raw_tbm1, TBM1_CRC_LEN);
    assert(tbm1_validate(raw_tbm1, sizeof(raw_tbm1), 65536U, out_off) == TBM1_BAD_PAYLOAD_LAYOUT);

    rd->data_off = 512U;
    rd->restored_size = 0U;
    th->fixed_crc32 = compute_boot_crc32(raw_tbm1, TBM1_CRC_LEN);
    assert(tbm1_validate(raw_tbm1, sizeof(raw_tbm1), 65536U, out_off) == TBM1_BAD_RDELTA);

    /* Delta boundary hardening: bad literal_block_offset & out-of-bounds expect_lit */
    sim_format_all();
    init_wal_factory_to_deployed(0U);
    toob_tds_header_t bad_tds;
    memset(&bad_tds, 0, sizeof(bad_tds));
    bad_tds.magic = TOOB_TDS_MAGIC;
    bad_tds.base_size = 512U;
    bad_tds.expected_target_size = 512U;
    bad_tds.instr_count = 2U;
    bad_tds.literal_block_offset = 16U; /* Mismatch vs sizeof(hdr) + 2*sizeof(instr) */
    bad_tds.header_crc32 = compute_boot_crc32(
        (const uint8_t *)&bad_tds, offsetof(toob_tds_header_t, header_crc32));
    memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], &bad_tds, sizeof(bad_tds));
    wal_entry_payload_t dtxn;
    memset(&dtxn, 0, sizeof(dtxn));
    assert(boot_delta_apply(&s_platform, CHIP_STAGING_SLOT_ABS_ADDR, 256U,
                            CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE,
                            CHIP_APP_SLOT_ABS_ADDR, 512U, &dtxn,
                            arena, sizeof(arena)) == BOOT_ERR_VERIFY);

    /* expect_lit > delta_max_size -> BOOT_ERR_FLASH_BOUNDS */
    bad_tds.instr_count = 32U;
    bad_tds.literal_block_offset =
        (uint32_t)sizeof(toob_tds_header_t) +
        (32U * (uint32_t)sizeof(toob_tds_instr_t));
    bad_tds.header_crc32 = compute_boot_crc32(
        (const uint8_t *)&bad_tds, offsetof(toob_tds_header_t, header_crc32));
    memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], &bad_tds, sizeof(bad_tds));
    assert(boot_delta_apply(&s_platform, CHIP_STAGING_SLOT_ABS_ADDR, 128U,
                            CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE,
                            CHIP_APP_SLOT_ABS_ADDR, 512U, &dtxn,
                            arena, sizeof(arena)) == BOOT_ERR_FLASH_BOUNDS);

    /* Stage-0 non-overlap copy / RAM range checks & decoupled efuse_epoch vs stage1_svn */
    assert(stage0_ranges_overlap(0x20001000U, 0x100U, 0x20001080U, 0x100U) == true);
    assert(stage0_ranges_overlap(0x20001000U, 0x100U, 0x20001100U, 0x100U) == false);
    assert(stage0_ranges_overlap((uintptr_t)(UINTPTR_MAX - 16U), 32U, 0x1000U, 0x100U) == true);
    assert(stage0_is_target_ram_safe(0x20000000U, 0U) == false);
    assert(stage0_is_target_ram_safe(0xFFFFFFF0U, 32U) == false);
    assert(stage0_is_ram_range_valid(0x20000002U, 16U) == false);

    sim_format_all();
    init_wal_factory_to_deployed(0U);
    wal_tmr_payload_t tmr;
    assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
    tmr.active_stage1_bank = 0U;
    tmr.stage1_svn = 2U;
    assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
    /* Advancing efuse_epoch (cloud/rescue counter) must NOT brick valid Stage-1 SVN=2 */
    s_otp_svn = 4U;
    uint32_t floor_svn = 0U;
    (void)stage0_read_wal_boot_meta(&s_platform, &floor_svn);
    assert(floor_svn == 2U);
    write_signed_stage1(CHIP_STAGE1A_ABS_ADDR, 0x100U, 2U, true, 0x11U);
    write_signed_stage1(CHIP_STAGE1B_ABS_ADDR, 0x100U, 1U, true, 0x22U);
    boot_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    assert(stage0_try_boot_bank(&s_platform, CHIP_STAGE1A_ABS_ADDR, 0x01U, floor_svn, &proof) == true);
    assert(proof.svn == 2U);
    assert(stage0_try_boot_bank(&s_platform, CHIP_STAGE1B_ABS_ADDR, 0x01U, floor_svn, &proof) == false);
  }

  printf("      PASS\n");
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("=== Running Gap Audit Fixes Host-SIL Regression Suite ===\n");
  test_stage0_security_and_quorum();
  test_tentative_handoff_and_confirm_sync();
  test_multiimage_and_crc32_guards();
  test_ota_trim_and_recovery_port();
  test_core_bounds_and_overflow_guards();
  test_stage1_self_update_lifecycle();
  test_rocq_audit_fixes_w5();
  test_tdr1_perfection_fixes();
  test_wave1_wave2_security_regressions();
  printf("=== ALL 9 GAP AUDIT FIX SUITES PASSED! ===\n");
  return 0;
}
