/**
 * @file test_rocq_oracle.c
 * @brief 1:1 Host-SIL Equivalence Oracle Coupling Rocq Formal Semantics to Production Core C17
 *
 * Executes every state-transition vector exported from Rocq (`BootOracleGen.v`,
 * proven sound by `all_oracle_vectors_sound`) against the real, unmocked
 * `toobloader/core/` C implementation (`boot_main` + `boot_state_run` +
 * `boot_journal` + `boot_verify` + `boot_rollback` + `boot_mailbox` +
 * `boot_cloud_cmd` + `boot_transport_oneway`) and asserts 0 mismatches across
 * all 12 observable post-boot output fields:
 *   1. Outcome kind (`Boot_App`, `Enter_Recovery_PartitionOS`, `SerialRescuePanic`)
 *   2. Terminal error code (`BOOT_OK`, `VERIFY`, `INVALID_ARG`, `NOT_FOUND`, `DEVICE_LOCKED`, `RECOVERY_REQUESTED`)
 *   3. Tentative handoff flag (`target.is_tentative_boot`)
 *   4. Post-boot active application payload identity (`0`, `10`, `20`, `30`)
 *   5. Post-boot `tmr.boot_failure_counter`
 *   6. Post-boot `tmr.recovery_failure_counter`
 *   7. Post-boot `tmr.active_nonce != 0`
 *   8. Reconstructed post-boot WAL transaction intent (`0..7`)
 *   9. Post-boot `tmr.app_svn`
 *  10. Post-boot hardware monotonic counter `otp_min_svn`
 *  11. Post-boot `tmr.last_accepted_issued_at` (`MED-28` anti-replay watermark)
 *  12. Post-boot `toob_handoff_state.wipe_requested` (`HIGH-32` factory-wipe flag)
 */

#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Compile-Time Hardware Geometry (Uniform 4 KB NOR + ONEWAY Full Backup)
 * ============================================================================ */
#define GENERATED_BOOT_CONFIG_H
#define BOOT_LAYOUT_H
#define TOOB_CUSTOM_SLOT_CAPS 1

#define TOOB_TRANSPORT_SWAPSCRATCH       1
#define TOOB_TRANSPORT_ONEWAY            2
#define TOOB_TRANSPORT_SWAPMOVE          3
#define TOOB_TRANSPORT_POINTER           4
#define TOOB_TRANSPORT_SWAPOFFSET        5

#define TOOB_ONEWAY_BACKUP_NONE          0
#define TOOB_ONEWAY_BACKUP_FULL          1
#define TOOB_ONEWAY_BACKUP_REVERSE_DELTA 2

#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_ONEWAY
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_FULL

#define CHIP_FLASH_BASE_ADDR             0x00000000U
#define CHIP_FLASH_XIP_BASE              0x08000000U
#define CHIP_FLASH_ERASED_BYTE           0xFFU
#define CHIP_FLASH_WRITE_ALIGNMENT       8U
#define CHIP_FLASH_TOTAL_SIZE            0x00080000U
#define CHIP_FLASH_MAX_SECTOR_SIZE       0x00001000U
#define CHIP_MMU_PAGE_SIZE               65536U

#define CHIP_STAGE0_ABS_ADDR             0x00000000U
#define CHIP_STAGE0_SIZE                 0x00002000U
#define CHIP_STAGE1A_ABS_ADDR            0x00002000U
#define CHIP_STAGE1A_SIZE                0x00002000U
#define CHIP_STAGE1B_ABS_ADDR            0x00004000U
#define CHIP_STAGE1B_SIZE                0x00002000U
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
#define CHIP_NETCORE_SLOT_ABS_ADDR       0x00000000U
#define CHIP_NETCORE_SLOT_SIZE           0x00000000U

#define TOOB_WAL_SECTORS                 4U
#define TOOB_WAL_SECTOR_ADDRS            { 0x00044000U, 0x00045000U, 0x00046000U, 0x00047000U }
#define TOOB_WAL_SECTOR_SIZES            { 4096U, 4096U, 4096U, 4096U }

/* Matches `default_boot_config := mkBootConfig 3 5 7` in BootModel.v */
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

#define HEATSHRINK_DYNAMIC_ALLOC             0
#define HEATSHRINK_STATIC_INPUT_BUFFER_SIZE  128
#define HEATSHRINK_STATIC_WINDOW_BITS        8
#define HEATSHRINK_STATIC_LOOKAHEAD_BITS     4

/* ============================================================================
 * Named Oracle Domain Constants (REG-040 Zero Magic Literals)
 * ============================================================================ */
enum {
  ORACLE_SECTOR_BYTES          = 4096U,
  ORACLE_IMAGE_BYTES           = 4096U,
  ORACLE_STG_BUNDLE_BYTES      = 12288U,
  ORACLE_STG_CFG_COUNT         = 9U,
  ORACLE_SUITE_COUNT           = 5U,
  ORACLE_ED25519_PK_BYTES      = 32U,
  ORACLE_ED25519_SK_BYTES      = 64U,
  ORACLE_ED25519_SEED_BYTES    = 32U,
  ORACLE_SHA256_BYTES          = 32U,
  ORACLE_UID_BYTES             = 16U,
  ORACLE_SUPPLY_MV             = 3300U,
  ORACLE_LOW_SUPPLY_MV         = 2500U,
  ORACLE_MAX_ERASE_CYCLES      = 100000U,
  ORACLE_ERASE_TIME_US         = 45000U,
  ORACLE_WRITE_TIME_US         = 50U,
  ORACLE_ENTRY_POINT_OFFSET    = 0x0100U,
  ORACLE_HW_REV_MAX            = 10U,
  ORACLE_FW_VER_MAJOR          = 2U,
  ORACLE_BUILD_NUM_BASE        = 100U,
  ORACLE_BUILD_APP_V2          = 102U,
  ORACLE_BUILD_STG_V3          = 103U,
  ORACLE_STG_CFG_BAD_SIG       = 4U,
  ORACLE_STG_CFG_VALID_V3      = 8U,
  ORACLE_OUTCOME_APPLIED       = 1U,
  ORACLE_OUTCOME_REJECTED      = 2U,
  ORACLE_OUTCOME_REVERTED      = 3U,
  ORACLE_OUTCOME_DEFERRED      = 4U,
  ORACLE_DSLC_PROVISIONED      = 0x01U,
  ORACLE_KDM_QUORUM_SLOTS      = 3U,
  ORACLE_KDM_SEQ_INIT          = 1U,
  ORACLE_KDM_RSTORE_MAGIC      = 0x4B444D51U,
  ORACLE_BASELINE_OTP_SVN      = 1U,
  ORACLE_BASELINE_TMR_SVN      = 1U,
  ORACLE_BASELINE_MBX_SEQ      = 1U,
  ORACLE_BASELINE_CLOUD_ISSUED = 10U,
  ORACLE_INIT_CHAIN_COUNT      = 1U,
  ORACLE_KEY_INDEX_REVOKED     = 0U,
  ORACLE_KEY_INDEX_ACTIVE      = 1U,
  ORACLE_PAYLOAD_ID_CORRUPT    = 0U,
  ORACLE_PAYLOAD_ID_BKUP_V1    = 10U,
  ORACLE_PAYLOAD_ID_APP_V2     = 20U,
  ORACLE_PAYLOAD_ID_STG_V3     = 30U,
  ORACLE_PAYLOAD_ID_RECOVERY   = 99U,
  ORACLE_SVN_DOWNGRADE         = 0U,
  ORACLE_SVN_BKUP_V1           = 1U,
  ORACLE_SVN_APP_V2            = 2U,
  ORACLE_SVN_STG_V3            = 3U,
  ORACLE_NONCE_ACTIVE          = 7U,
  ORACLE_NONCE_MISMATCH        = 5U,
  ORACLE_MBX_FRESH_SEQ         = 2U,
  ORACLE_MBX_STALE_SEQ         = 1U,
  ORACLE_CLOUD_FRESH_COUNTER    = 2U,
  ORACLE_CLOUD_STALE_COUNTER    = 1U,
  ORACLE_CLOUD_NOP_COUNTER      = 3U,
  ORACLE_CLOUD_MAX_CAP_COUNTER  = 5U,
  ORACLE_CLOUD_OVER_CAP_COUNTER = 6U,
  ORACLE_CLOUD_FRESH_ISSUED_AT  = 20U,
  ORACLE_CLOUD_STALE_ISSUED_AT  = 10U,
  ORACLE_MAX_REPORTED_DIFFS     = 16U
};

enum {
  ORACLE_COL_SUITE       = 0,
  ORACLE_COL_SLOT_CFG    = 1,
  ORACLE_COL_STG_CFG     = 2,
  ORACLE_COL_WAL_INTENT  = 3,
  ORACLE_COL_CONFIRM_CFG = 4,
  ORACLE_COL_RETRY_CNT   = 5,
  ORACLE_COL_REC_RETRY   = 6,
  ORACLE_COL_RESET       = 7,
  ORACLE_COL_MBX_CFG     = 8,
  ORACLE_COL_CLOUD_CFG   = 9,
  ORACLE_COL_TAMPER_CFG  = 10,
  ORACLE_COL_OUT_KIND    = 11,
  ORACLE_COL_OUT_ERR     = 12,
  ORACLE_COL_OUT_TENT    = 13,
  ORACLE_COL_OUT_APP_ID  = 14,
  ORACLE_COL_OUT_BF      = 15,
  ORACLE_COL_OUT_RF      = 16,
  ORACLE_COL_OUT_NONCE   = 17,
  ORACLE_COL_OUT_WAL     = 18,
  ORACLE_COL_OUT_TMR_SVN = 19,
  ORACLE_COL_OUT_OTP_SVN = 20,
  ORACLE_COL_OUT_ISSUED  = 21,
  ORACLE_COL_OUT_WIPE    = 22
};

enum {
  ORACLE_OUT_BOOT_APP      = 0U,
  ORACLE_OUT_RECOVERY_OS   = 1U,
  ORACLE_OUT_SERIAL_RESCUE = 2U
};

enum {
  ORACLE_ERR_OK            = 0U,
  ORACLE_ERR_VERIFY        = 1U,
  ORACLE_ERR_INVALID_ARG   = 2U,
  ORACLE_ERR_NOT_FOUND     = 3U,
  ORACLE_ERR_DEVICE_LOCKED = 4U,
  ORACLE_ERR_REC_REQUESTED = 5U,
  ORACLE_ERR_UNMAPPED      = 255U
};

enum {
  ORACLE_WI_NONE             = 0U,
  ORACLE_WI_UPDATE_PENDING   = 1U,
  ORACLE_WI_TXN_COMMIT       = 2U,
  ORACLE_WI_CONFIRM_COMMIT   = 3U,
  ORACLE_WI_RECOVERY_RESOLVE = 4U,
  ORACLE_WI_TXN_ROLLBACK     = 5U,
  ORACLE_WI_ROLLBACK_PENDING = 6U,
  ORACLE_WI_DEVICE_LOCKED    = 7U
};

enum {
  ORACLE_TAMPER_CLEAN       = 0U,
  ORACLE_TAMPER_TMR_MAC_BAD = 1U,
  ORACLE_TAMPER_WAL_MAC_BAD = 2U,
  ORACLE_TAMPER_AUX_MAC_BAD = 3U
};

/* ============================================================================
 * Production Core Modules (Single-TU White-Box Inclusion — Zero Mocks)
 * ============================================================================ */
#include "boot_types.h"
#include "crypto_monocypher.h"
#include "crypto_sha256.h"
#include "monocypher-ed25519.h"
#include "sha256.h"
#include "heatshrink_encoder.h"
#include "heatshrink_decoder.h"
#include "toob_mailbox_wire.h"

#include "../../toobloader/core/utils/boot_crc32.c"
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

#include "rocq_oracle_vectors.h"

/* ============================================================================
 * Simulated Hardware State & Panic Trap
 * ============================================================================ */
static uint8_t s_flash[CHIP_FLASH_TOTAL_SIZE];
static uint8_t s_base_flash[CHIP_FLASH_TOTAL_SIZE];

static uint8_t s_root_sk_0[ORACLE_ED25519_SK_BYTES];
static uint8_t s_root_pk_0[ORACLE_ED25519_PK_BYTES];
static uint8_t s_root_sk_1[ORACLE_ED25519_SK_BYTES];
static uint8_t s_root_pk_1[ORACLE_ED25519_PK_BYTES];
static uint8_t s_cloud_sk[ORACLE_ED25519_SK_BYTES];
static uint8_t s_cloud_pk[ORACLE_ED25519_PK_BYTES];

static uint32_t s_otp_svn = ORACLE_BASELINE_OTP_SVN;
static uint32_t s_supply_mv = ORACLE_SUPPLY_MV;
static uint64_t s_rtc_confirm_nonce = 0ULL;
static reset_reason_t s_reset_reason = RESET_REASON_POWER_ON;
static uint32_t s_tick_ms = 0U;
static uint32_t s_rng_state = 0x9E3779B9U;

static jmp_buf s_panic_jmp;
static volatile boot_status_t s_panic_reason = BOOT_OK;

static const uint32_t k_seal_key[4] = {
    0xA55AA55AU, 0x3C6EF372U, 0x9E3779B9U, 0xBB67AE85U
};

_Noreturn void boot_terminal_halt(const boot_platform_t *p, boot_status_t r,
                                  uint16_t site) {
  (void)p;
  fprintf(stderr, "FATAL: unexpected boot_terminal_halt(0x%08X, site=%u)\n",
          (unsigned)r, (unsigned)site);
  abort();
}

_Noreturn void boot_panic(const boot_platform_t *p, boot_status_t r) {
  (void)p;
  s_panic_reason = r;
  longjmp(s_panic_jmp, 1);
}

_Noreturn void boot_provisioning_run(const boot_platform_t *p, uint8_t *arena,
                                     size_t arena_len) {
  (void)p;
  (void)arena;
  (void)arena_len;
  fprintf(stderr, "FATAL: unexpected boot_provisioning_run\n");
  abort();
}

/* ============================================================================
 * Physical NOR Flash & Peripheral HAL Implementations
 * ============================================================================ */
static boot_status_t sim_flash_init(void) { return BOOT_OK; }
static void sim_flash_deinit(void) {}

static boot_status_t sim_flash_get_sector_size(uint32_t addr, size_t *out_sz) {
  if (out_sz == NULL || addr >= CHIP_FLASH_TOTAL_SIZE) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  *out_sz = ORACLE_SECTOR_BYTES;
  return BOOT_OK;
}

static boot_status_t sim_flash_read(uint32_t addr, void *buf, size_t len) {
  if (buf == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (addr > CHIP_FLASH_TOTAL_SIZE || len > (CHIP_FLASH_TOTAL_SIZE - addr)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  if (len > 0U) {
    memcpy(buf, &s_flash[addr], len);
  }
  return BOOT_OK;
}

static boot_status_t sim_flash_write(uint32_t addr, const void *buf,
                                     size_t len) {
  if (buf == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
      (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
    return BOOT_ERR_FLASH_ALIGN;
  }
  if (addr > CHIP_FLASH_TOTAL_SIZE || len > (CHIP_FLASH_TOTAL_SIZE - addr)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  const uint8_t *src = (const uint8_t *)buf;
  for (size_t i = 0U; i < len; i++) {
    /* Enforce physical NOR flash 1 -> 0 monotonicity */
    if ((uint8_t)(~s_flash[addr + i] & src[i]) != 0U) {
      return BOOT_ERR_FLASH_HW;
    }
    s_flash[addr + i] &= src[i];
  }
  return BOOT_OK;
}

static boot_status_t sim_flash_erase_sector(uint32_t addr) {
  if ((addr % ORACLE_SECTOR_BYTES) != 0U ||
      addr > (CHIP_FLASH_TOTAL_SIZE - ORACLE_SECTOR_BYTES)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  memset(&s_flash[addr], CHIP_FLASH_ERASED_BYTE, ORACLE_SECTOR_BYTES);
  return BOOT_OK;
}

static boot_status_t sim_flash_get_supply_mv(uint32_t *mv_out) {
  if (mv_out == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  *mv_out = s_supply_mv;
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
    .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
    .total_size = CHIP_FLASH_TOTAL_SIZE,
    .max_erase_cycles = ORACLE_MAX_ERASE_CYCLES,
    .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
    .erased_value = CHIP_FLASH_ERASED_BYTE,
    .erase_time_us_max = ORACLE_ERASE_TIME_US,
    .write_time_us_page = ORACLE_WRITE_TIME_US,
};

static boot_status_t sim_clock_init(void) { return BOOT_OK; }
static void sim_clock_deinit(void) {}
static uint32_t sim_clock_tick(void) {
  s_tick_ms += 1U;
  return s_tick_ms;
}
static reset_reason_t sim_clock_reset_reason(void) { return s_reset_reason; }

static const clock_hal_t s_clock_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_clock_init,
    .deinit = sim_clock_deinit,
    .get_tick_ms = sim_clock_tick,
    .get_reset_reason = sim_clock_reset_reason,
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

static boot_status_t sim_confirm_init(void) { return BOOT_OK; }
static void sim_confirm_deinit(void) {}
static bool sim_confirm_check_ok(uint64_t expected_nonce) {
  if (expected_nonce == 0ULL) {
    return false;
  }
  if ((s_rtc_confirm_nonce ^ expected_nonce) == 0ULL) {
    s_rtc_confirm_nonce = 0ULL;
    return true;
  }
  return false;
}
static boot_status_t sim_confirm_clear(void) {
  s_rtc_confirm_nonce = 0ULL;
  return BOOT_OK;
}

static const confirm_hal_t s_confirm_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_confirm_init,
    .deinit = sim_confirm_deinit,
    .check_ok = sim_confirm_check_ok,
    .clear = sim_confirm_clear,
};

static boot_status_t sim_crypto_random(uint8_t *buf, size_t len) {
  if (buf == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  for (size_t i = 0U; i < len; i++) {
    s_rng_state ^= s_rng_state << 13U;
    s_rng_state ^= s_rng_state >> 17U;
    s_rng_state ^= s_rng_state << 5U;
    buf[i] = (uint8_t)(s_rng_state & 0xFFU);
  }
  if (len >= sizeof(uint64_t)) {
    uint64_t nz = 0ULL;
    memcpy(&nz, buf, sizeof(nz));
    if (nz == 0ULL) {
      buf[0] = 0xA5U;
    }
  }
  return BOOT_OK;
}

/**
 * Keystore slot layout matching `baseline_otp := mkOTPEpoch 1 1` in BootOracleGen.v:
 *   - Slot 0 (`s_root_pk_0`): eFuse Root Key 0 (revoked for TBM1 because Slot 1 exists;
 *     used by `boot_cloud_cmd.c` to verify KDM quorum delegation).
 *   - Slot 1 (`s_root_pk_1`): Active firmware TBM1 signing key (`next_idx = 2` -> NOT_FOUND).
 *   - Slot >= 2: `BOOT_ERR_NOT_FOUND`.
 */
static boot_status_t sim_read_pubkey(uint8_t *key, size_t key_len,
                                     uint8_t key_index) {
  if (key == NULL || key_len < ORACLE_ED25519_PK_BYTES) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (key_index == ORACLE_KEY_INDEX_REVOKED) {
    memcpy(key, s_root_pk_0, ORACLE_ED25519_PK_BYTES);
    return BOOT_OK;
  }
  if (key_index == ORACLE_KEY_INDEX_ACTIVE) {
    memcpy(key, s_root_pk_1, ORACLE_ED25519_PK_BYTES);
    return BOOT_OK;
  }
  return BOOT_ERR_NOT_FOUND;
}

static boot_status_t sim_read_uid(uint8_t *buf, size_t max_len,
                                  size_t *out_len) {
  static const uint8_t k_uid[ORACLE_UID_BYTES] = {
      0x5BU, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
      0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU
  };
  if (buf == NULL || out_len == NULL || max_len < sizeof(k_uid)) {
    return BOOT_ERR_INVALID_ARG;
  }
  memcpy(buf, k_uid, sizeof(k_uid));
  *out_len = sizeof(k_uid);
  return BOOT_OK;
}

static boot_status_t sim_read_dslc(uint8_t *buf, size_t *len) {
  if (buf == NULL || len == NULL || *len < 1U) {
    return BOOT_ERR_INVALID_ARG;
  }
  buf[0] = ORACLE_DSLC_PROVISIONED;
  *len = 1U;
  return BOOT_OK;
}

static boot_status_t sim_read_monotonic(uint32_t *ctr) {
  if (ctr == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  *ctr = s_otp_svn;
  return BOOT_OK;
}

static boot_status_t sim_advance_monotonic(void) {
  s_otp_svn++;
  return BOOT_OK;
}

static const crypto_hal_t s_crypto_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init = crypto_monocypher_init,
    .deinit = crypto_monocypher_deinit,
    .hash_init = crypto_sha256_init,
    .hash_update = crypto_sha256_update,
    .hash_finish = crypto_sha256_finish,
    .get_hash_ctx_size = crypto_sha256_get_ctx_size,
    .verify_signature = crypto_monocypher_verify_signature,
    .verify_signature_ph = crypto_monocypher_verify_signature_ph,
    .verify_pqc = NULL,
    .is_pqc_enforced = NULL,
};

static const entropy_hal_t s_entropy_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .random = sim_crypto_random,
    .is_hardware_trng = true,
};

static const keystore_hal_t s_keystore_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .read_pubkey = sim_read_pubkey,
    .read_chip_uid = sim_read_uid,
    .read_dslc = sim_read_dslc,
    .read_monotonic_counter = sim_read_monotonic,
    .advance_monotonic_counter = sim_advance_monotonic,
};

static const slot_caps_t s_active_caps = TOOB_SLOT_CAPS_FIXED(
    1U,
    .has_scratch = true,
    .scratch_size = CHIP_SCRATCH_SLOT_SIZE);

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

/* ============================================================================
 * Pre-Built Slot Payloads & Staging Bundles
 * ============================================================================ */
static uint8_t s_img_bkup_v1[ORACLE_IMAGE_BYTES];
static uint8_t s_img_app_v2[ORACLE_IMAGE_BYTES];
static uint8_t s_img_stg_v3[ORACLE_IMAGE_BYTES];
static uint8_t s_img_recovery[ORACLE_IMAGE_BYTES];
static uint8_t s_stg_bundles[ORACLE_STG_CFG_COUNT][ORACLE_STG_BUNDLE_BYTES];
static uint8_t s_device_id[ORACLE_SHA256_BYTES];

static void sha256_buf(const uint8_t *data, size_t len,
                       uint8_t out[ORACLE_SHA256_BYTES]) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, out);
}

static void build_raw_slot_image(uint8_t out[ORACLE_IMAGE_BYTES],
                                 uint8_t payload_tag) {
  for (size_t i = 0U; i < ORACLE_IMAGE_BYTES; i++) {
    out[i] = (uint8_t)(payload_tag ^ (uint8_t)((i * 29U + 0x3CU) & 0xFFU));
  }
  toob_image_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TOOB_MAGIC_HEADER;
  hdr.image_size = ORACLE_IMAGE_BYTES;
  hdr.entry_point = ORACLE_ENTRY_POINT_OFFSET;
  memcpy(out, &hdr, sizeof(hdr));
}

static void build_staging_bundle(uint8_t bundle[ORACLE_STG_BUNDLE_BYTES],
                                 uint32_t cfg) {
  memset(bundle, CHIP_FLASH_ERASED_BYTE, ORACLE_STG_BUNDLE_BYTES);
  if (cfg == 0U) {
    return;
  }

  /* Decode 2x2x2 cube over (sig_ok, svn_ok, key_ok) for cfg in 1..8 */
  const uint32_t cube = cfg - 1U;
  const bool sig_ok = (cfg >= 5U);
  const uint32_t svn = ((cube & 2U) != 0U) ? ORACLE_SVN_STG_V3 : ORACLE_SVN_DOWNGRADE;
  const uint8_t key_idx =
      ((cube & 1U) != 0U) ? ORACLE_KEY_INDEX_ACTIVE : ORACLE_KEY_INDEX_REVOKED;

  memcpy(bundle, s_img_stg_v3, ORACLE_IMAGE_BYTES);

  const uint32_t tbm1_off = ORACLE_SECTOR_BYTES;
  const uint32_t hashes_off = TBM1_FIXED_LEN;
  const uint32_t hashes_len = ORACLE_SHA256_BYTES;
  const uint32_t total_tbm1_len = TBM1_FIXED_LEN + hashes_len + TBM1_SIG_LEN;

  uint8_t *tbm1_buf = bundle + tbm1_off;
  memset(tbm1_buf, 0, total_tbm1_len);

  tbm1_header_t *hdr = (tbm1_header_t *)tbm1_buf;
  hdr->magic = TBM1_MAGIC;
  hdr->version_major = TBM1_VERSION_MAJOR;
  hdr->version_minor = TBM1_VERSION_MINOR;
  hdr->fixed_len = TBM1_FIXED_LEN;
  hdr->total_len = total_tbm1_len;
  hdr->flags_critical = TBM1_CRIT_TRAILER_LAYOUT;
  hdr->vendor_id = TOOB_DEVICE_VENDOR_ID;
  hdr->product_id = TOOB_DEVICE_PRODUCT_ID;
  hdr->hw_rev_min = 0U;
  hdr->hw_rev_max = ORACLE_HW_REV_MAX;
  hdr->key_index = key_idx;
  hdr->image_count = 1U;
  hdr->boot_retry_limit = BOOT_CONFIG_MAX_RETRIES;
  hdr->min_reader_major = TBM1_VERSION_MAJOR;
  hdr->svn = svn;
  hdr->build_number = ORACLE_BUILD_NUM_BASE + svn;
  hdr->fw_ver_major = ORACLE_FW_VER_MAJOR;
  hdr->fw_ver_minor = (uint16_t)svn;

  hdr->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
  hdr->regions[0].off = hashes_off;
  hdr->regions[0].len = hashes_len;

  hdr->images[0].image_type = 0U;
  hdr->images[0].target_slot = TBM1_SLOT_APP;
  hdr->images[0].compression_alg = TBM1_COMP_NONE;
  hdr->images[0].delta_alg = TBM1_DELTA_NONE;
  hdr->images[0].data_off = 0U;
  hdr->images[0].stored_size = ORACLE_IMAGE_BYTES;
  hdr->images[0].installed_size = ORACLE_IMAGE_BYTES;
  hdr->images[0].chunk_size = ORACLE_IMAGE_BYTES;
  hdr->images[0].num_chunks = 1U;
  hdr->images[0].ver_major = ORACLE_FW_VER_MAJOR;
  hdr->images[0].ver_minor = (uint16_t)svn;

  hdr->fixed_crc32 = compute_boot_crc32(tbm1_buf, TBM1_CRC_LEN);
  sha256_buf(s_img_stg_v3, ORACLE_IMAGE_BYTES, tbm1_buf + hashes_off);

  const uint8_t *sk =
      (key_idx == ORACLE_KEY_INDEX_ACTIVE) ? s_root_sk_1 : s_root_sk_0;
  uint8_t *sig_ptr = tbm1_buf + total_tbm1_len - TBM1_SIG_LEN;
  crypto_ed25519_sign(sig_ptr, sk, tbm1_buf, total_tbm1_len - TBM1_SIG_LEN);
  if (!sig_ok) {
    sig_ptr[0] ^= 0xFFU;
  }
}

static void sim_reset_sram_globals(reset_reason_t reason) {
  active_wal_index = 0U;
  memset(&current_active_header, 0, sizeof(current_active_header));
  memset(&persisted_tmr_data, 0, sizeof(persisted_tmr_data));
  wal_initialized = false;
  tmr_defer_enabled = false;
  tmr_dirty = false;
  cached_write_offset = 0U;
  memset(journal_key, 0, sizeof(journal_key));
  journal_key_valid = false;
  boot_platform_mark_down();

  memset(crypto_arena, 0, sizeof(crypto_arena));
  memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
  memset(&toob_diag_state, 0, sizeof(toob_diag_state));
  s_supply_mv = ORACLE_SUPPLY_MV;
  s_reset_reason = reason;
  s_rng_state = 0x9E3779B9U ^ ((uint32_t)reason * 0x85EBCA6BU);
}

static void init_oracle_fixtures(void) {
  uint8_t seed0[ORACLE_ED25519_SEED_BYTES];
  uint8_t seed1[ORACLE_ED25519_SEED_BYTES];
  uint8_t seed_cloud[ORACLE_ED25519_SEED_BYTES];

  for (size_t i = 0U; i < ORACLE_ED25519_SEED_BYTES; i++) {
    seed0[i] = (uint8_t)(0x10U + i);
    seed1[i] = (uint8_t)(0x50U + i);
    seed_cloud[i] = (uint8_t)(0x90U + i);
  }
  crypto_ed25519_key_pair(s_root_sk_0, s_root_pk_0, seed0);
  crypto_ed25519_key_pair(s_root_sk_1, s_root_pk_1, seed1);
  crypto_ed25519_key_pair(s_cloud_sk, s_cloud_pk, seed_cloud);

  build_raw_slot_image(s_img_bkup_v1, ORACLE_PAYLOAD_ID_BKUP_V1);
  build_raw_slot_image(s_img_app_v2, ORACLE_PAYLOAD_ID_APP_V2);
  build_raw_slot_image(s_img_stg_v3, ORACLE_PAYLOAD_ID_STG_V3);
  build_raw_slot_image(s_img_recovery, ORACLE_PAYLOAD_ID_RECOVERY);

  for (uint32_t cfg = 0U; cfg < ORACLE_STG_CFG_COUNT; cfg++) {
    build_staging_bundle(s_stg_bundles[cfg], cfg);
  }

  memset(s_flash, CHIP_FLASH_ERASED_BYTE, sizeof(s_flash));
  memcpy(&s_flash[CHIP_RECOVERY_OS_ABS_ADDR], s_img_recovery, ORACLE_IMAGE_BYTES);

  assert(crypto_monocypher_init() == BOOT_OK);
  assert(boot_derive_device_id(&s_platform, s_device_id) == BOOT_OK);

  const uint32_t kdm_addrs[ORACLE_KDM_QUORUM_SLOTS] = {
      CHIP_KDM_QUORUM_ABS_ADDR,
      CHIP_KDM_QUORUM_ABS_ADDR + ORACLE_SECTOR_BYTES,
      CHIP_KDM_QUORUM_ABS_ADDR + (2U * ORACLE_SECTOR_BYTES)
  };
  const size_t kdm_sizes[ORACLE_KDM_QUORUM_SLOTS] = {
      ORACLE_SECTOR_BYTES, ORACLE_SECTOR_BYTES, ORACLE_SECTOR_BYTES
  };
  const boot_rstore_desc_t kdm_desc = {
      .slot_addrs = kdm_addrs,
      .slot_sizes = kdm_sizes,
      .slot_count = ORACLE_KDM_QUORUM_SLOTS,
      .record_size = sizeof(toob_kdm_t),
      .magic = ORACLE_KDM_RSTORE_MAGIC,
  };

  toob_kdm_t kdm;
  memset(&kdm, 0, sizeof(kdm));
  kdm.sequence_number = ORACLE_KDM_SEQ_INIT;
  memcpy(kdm.new_cloud_pubkey, s_cloud_pk, sizeof(s_cloud_pk));
  crypto_ed25519_sign(kdm.signature_ed25519, s_root_sk_0, (const uint8_t *)&kdm,
                      offsetof(toob_kdm_t, signature_ed25519));
  assert(boot_rstore_write(&s_platform, &kdm_desc, &kdm) == BOOT_OK);

  memcpy(s_base_flash, s_flash, sizeof(s_flash));
}

/* ============================================================================
 * Bijective Mapping Helpers (Rocq <-> C Production Types)
 * ============================================================================ */
static uint32_t decode_wal_to_c(uint32_t code) {
  switch (code) {
  case ORACLE_WI_NONE:             return (uint32_t)WAL_INTENT_NONE;
  case ORACLE_WI_UPDATE_PENDING:   return (uint32_t)WAL_INTENT_UPDATE_PENDING;
  case ORACLE_WI_TXN_COMMIT:       return (uint32_t)WAL_INTENT_TXN_COMMIT;
  case ORACLE_WI_CONFIRM_COMMIT:   return (uint32_t)WAL_INTENT_CONFIRM_COMMIT;
  case ORACLE_WI_RECOVERY_RESOLVE: return (uint32_t)WAL_INTENT_RECOVERY_RESOLVED;
  case ORACLE_WI_TXN_ROLLBACK:     return (uint32_t)WAL_INTENT_TXN_ROLLBACK;
  case ORACLE_WI_ROLLBACK_PENDING: return (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING;
  default:                         return (uint32_t)WAL_INTENT_DEVICE_LOCKED;
  }
}

static uint32_t encode_wal_from_c(uint32_t c_intent) {
  switch (c_intent) {
  case WAL_INTENT_NONE:                 return ORACLE_WI_NONE;
  case WAL_INTENT_UPDATE_PENDING:       return ORACLE_WI_UPDATE_PENDING;
  case WAL_INTENT_TXN_COMMIT:           return ORACLE_WI_TXN_COMMIT;
  case WAL_INTENT_CONFIRM_COMMIT:       return ORACLE_WI_CONFIRM_COMMIT;
  case WAL_INTENT_RECOVERY_RESOLVED:    return ORACLE_WI_RECOVERY_RESOLVE;
  case WAL_INTENT_TXN_ROLLBACK:         return ORACLE_WI_TXN_ROLLBACK;
  case WAL_INTENT_TXN_ROLLBACK_PENDING: return ORACLE_WI_ROLLBACK_PENDING;
  case WAL_INTENT_DEVICE_LOCKED:        return ORACLE_WI_DEVICE_LOCKED;
  default:                              return ORACLE_ERR_UNMAPPED;
  }
}

static reset_reason_t decode_reset_to_c(uint32_t code) {
  switch (code) {
  case 0U: return RESET_REASON_POWER_ON;
  case 1U: return RESET_REASON_PIN_RESET;
  case 2U: return RESET_REASON_SOFTWARE;
  case 3U: return RESET_REASON_WATCHDOG;
  case 4U: return RESET_REASON_BROWNOUT;
  default: return RESET_REASON_HARD_FAULT;
  }
}

static uint32_t encode_status_to_oracle_err(boot_status_t st) {
  switch (st) {
  case BOOT_OK:                 return ORACLE_ERR_OK;
  case BOOT_ERR_VERIFY:         return ORACLE_ERR_VERIFY;
  case BOOT_ERR_INVALID_ARG:    return ORACLE_ERR_INVALID_ARG;
  case BOOT_ERR_NOT_FOUND:      return ORACLE_ERR_NOT_FOUND;
  case BOOT_ERR_DEVICE_LOCKED:  return ORACLE_ERR_DEVICE_LOCKED;
  case BOOT_RECOVERY_REQUESTED: return ORACLE_ERR_REC_REQUESTED;
  default:                      return ORACLE_ERR_UNMAPPED;
  }
}

static void materialize_mailbox_cfg(uint32_t mbx_cfg) {
  if (mbx_cfg == 0U) {
    return;
  }
  uint32_t seq = ORACLE_MBX_FRESH_SEQ;
  uint16_t req = TOOB_REQ_NONE;
  uint64_t nonce = 0ULL;
  uint32_t tbm1_addr = 0U;

  switch (mbx_cfg) {
  case 1U:
    req = TOOB_REQ_CONFIRM;
    nonce = ORACLE_NONCE_ACTIVE;
    break;
  case 2U:
    req = TOOB_REQ_CONFIRM;
    nonce = ORACLE_NONCE_MISMATCH;
    break;
  case 3U:
    req = TOOB_REQ_CONFIRM;
    nonce = 0ULL;
    break;
  case 4U:
    req = TOOB_REQ_UPDATE_PENDING;
    tbm1_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    break;
  case 5U:
    req = (uint16_t)(TOOB_REQ_CONFIRM | TOOB_REQ_UPDATE_PENDING);
    nonce = ORACLE_NONCE_ACTIVE;
    tbm1_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    break;
  case 6U:
    req = (uint16_t)(TOOB_REQ_RECOVERY_RESOLVED | TOOB_REQ_UPDATE_PENDING);
    tbm1_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    break;
  default:
    seq = ORACLE_MBX_STALE_SEQ;
    req = TOOB_REQ_UPDATE_PENDING;
    tbm1_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    break;
  }

  toob_mailbox_t mbx;
  memset(&mbx, 0, sizeof(mbx));
  mbx.magic = TOOB_MAILBOX_MAGIC;
  mbx.version = TOOB_MAILBOX_VERSION;
  mbx.request = req;
  mbx.seq = seq;
  mbx.tbm1_addr = tbm1_addr;
  mbx.nonce = nonce;
  mbx.crc32 = compute_boot_crc32((const uint8_t *)&mbx, TOOB_MAILBOX_CRC_LEN);
  memcpy(&s_flash[CHIP_MAILBOX_ABS_ADDR], &mbx, sizeof(mbx));
}

static void materialize_cloud_cfg(uint32_t cloud_cfg) {
  if (cloud_cfg == 0U) {
    return;
  }
  uint8_t cmd = (uint8_t)TOOB_CMD_KILLSWITCH;
  uint32_t ctr_min = ORACLE_CLOUD_FRESH_COUNTER;
  uint32_t issued_at = ORACLE_CLOUD_FRESH_ISSUED_AT;
  bool sig_ok = true;
  bool dev_ok = true;

  switch (cloud_cfg) {
  case 1U:
    cmd = (uint8_t)TOOB_CMD_KILLSWITCH;
    break;
  case 2U:
    cmd = (uint8_t)TOOB_CMD_UNLOCK;
    break;
  case 3U:
    cmd = (uint8_t)TOOB_CMD_FORCE_UPDATE;
    break;
  case 4U:
    cmd = (uint8_t)TOOB_CMD_KILLSWITCH;
    sig_ok = false;
    break;
  case 5U:
    cmd = (uint8_t)TOOB_CMD_KILLSWITCH;
    ctr_min = ORACLE_CLOUD_STALE_COUNTER;
    break;
  case 6U:
    cmd = (uint8_t)TOOB_CMD_UNLOCK;
    ctr_min = ORACLE_CLOUD_MAX_CAP_COUNTER;
    break;
  case 7U:
    cmd = (uint8_t)TOOB_CMD_UNLOCK;
    ctr_min = ORACLE_CLOUD_OVER_CAP_COUNTER;
    break;
  case 8U:
    cmd = (uint8_t)TOOB_CMD_UNLOCK;
    issued_at = ORACLE_CLOUD_STALE_ISSUED_AT;
    break;
  case 9U:
    cmd = (uint8_t)TOOB_CMD_UNLOCK;
    dev_ok = false;
    break;
  case 10U:
    cmd = (uint8_t)TOOB_CMD_NOP;
    ctr_min = ORACLE_CLOUD_NOP_COUNTER;
    break;
  default:
    cmd = (uint8_t)TOOB_CMD_WIPE;
    break;
  }

  uint8_t env[TOOB_CLOUD_CMD_MIN_SIZE];
  memset(env, 0, sizeof(env));

  toob_cloud_cmd_hdr_t *hdr = (toob_cloud_cmd_hdr_t *)env;
  hdr->magic = TOOB_CLOUD_CMD_MAGIC;
  hdr->version = TOOB_CLOUD_CMD_VERSION;
  hdr->command = cmd;
  hdr->flags = 0U;
  hdr->counter_min = ctr_min;
  hdr->issued_at = issued_at;
  hdr->params_len = 0U;
  hdr->total_len = TOOB_CLOUD_CMD_MIN_SIZE;
  memcpy(hdr->device_id, s_device_id, sizeof(hdr->device_id));
  if (!dev_ok) {
    hdr->device_id[0] ^= 0xFFU;
  }
  hdr->crc32 = compute_boot_crc32(env, TOOB_CLOUD_CMD_HDR_CRC_LEN);

  uint8_t *sig = env + TOOB_CLOUD_CMD_HDR_SIZE;
  crypto_ed25519_sign(sig, s_cloud_sk, env, TOOB_CLOUD_CMD_HDR_SIZE);
  if (!sig_ok) {
    sig[0] ^= 0xFFU;
  }
  memcpy(&s_flash[CHIP_CLOUD_CMD_SLOT_ABS_ADDR], env, sizeof(env));
}

/* Isolated non-inlined setjmp wrapper avoiding MinGW-w64 SEH unwind hazards */
static __attribute__((noinline)) int execute_boot_with_panic_trap(
    boot_target_config_t *target_out, boot_status_t *status_out) {
  s_panic_reason = BOOT_OK;
  if (setjmp(s_panic_jmp) != 0) {
    *status_out = s_panic_reason;
    return 1;
  }
  *status_out = boot_main(&s_platform, target_out, k_seal_key);
  return 0;
}

static uint32_t inspect_post_boot_app_id(void) {
  const uint8_t *app_ptr = &s_flash[CHIP_APP_SLOT_ABS_ADDR];
  if (memcmp(app_ptr, s_img_bkup_v1, ORACLE_IMAGE_BYTES) == 0) {
    return ORACLE_PAYLOAD_ID_BKUP_V1;
  }
  if (memcmp(app_ptr, s_img_app_v2, ORACLE_IMAGE_BYTES) == 0) {
    return ORACLE_PAYLOAD_ID_APP_V2;
  }
  if (memcmp(app_ptr, s_img_stg_v3, ORACLE_IMAGE_BYTES) == 0) {
    return ORACLE_PAYLOAD_ID_STG_V3;
  }
  return ORACLE_PAYLOAD_ID_CORRUPT;
}

static void inspect_post_boot_wal_and_tmr(wal_tmr_payload_t *out_tmr,
                                          uint32_t *out_wal_code) {
  if (wal_initialized) {
    assert(boot_journal_get_tmr(&s_platform, out_tmr) == BOOT_OK);
    wal_entry_payload_t txn;
    boot_status_t rs = boot_journal_reconstruct_txn(&s_platform, &txn, NULL, NULL);
    if (rs == BOOT_OK) {
      *out_wal_code = encode_wal_from_c(txn.intent);
    } else {
      *out_wal_code = ORACLE_WI_NONE;
    }
    return;
  }

  /* When TmrMacBad aborted boot_journal_init before setting wal_initialized,
   * inspect the persisted highest-sequence WAL sector directly from flash. */
  uint32_t best_seq = 0U;
  uint32_t best_idx = 0U;
  for (uint32_t i = 0U; i < TOOB_WAL_SECTORS; i++) {
    wal_sector_header_aligned_t hdr;
    memcpy(&hdr, &s_flash[wal_sector_addrs[i]], sizeof(hdr));
    if (hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_CURRENT &&
        hdr.data.sequence_id >= best_seq) {
      best_seq = hdr.data.sequence_id;
      best_idx = i;
    }
  }

  wal_sector_header_aligned_t win_hdr;
  memcpy(&win_hdr, &s_flash[wal_sector_addrs[best_idx]], sizeof(win_hdr));
  *out_tmr = win_hdr.data.tmr_data;

  wal_entry_aligned_t ent;
  memcpy(&ent,
         &s_flash[wal_sector_addrs[best_idx] + sizeof(wal_sector_header_aligned_t)],
         sizeof(ent));
  if (ent.data.magic == WAL_ENTRY_MAGIC) {
    *out_wal_code = encode_wal_from_c(ent.data.intent);
  } else {
    *out_wal_code = ORACLE_WI_NONE;
  }
}

/* ============================================================================
 * Exhaustive Vector Runner
 * ============================================================================ */
int main(void) {
  init_oracle_fixtures();

  uint32_t suite_counts[ORACLE_SUITE_COUNT] = {0U};
  uint32_t mismatches = 0U;

  for (uint32_t idx = 0U; idx < ROCQ_ORACLE_VECTOR_COUNT; idx++) {
    const uint16_t *row = k_rocq_oracle_vectors[idx];
    const uint32_t suite       = row[ORACLE_COL_SUITE];
    const uint32_t slot_cfg    = row[ORACLE_COL_SLOT_CFG];
    const uint32_t stg_cfg     = row[ORACLE_COL_STG_CFG];
    const uint32_t wal_code    = row[ORACLE_COL_WAL_INTENT];
    const uint32_t confirm_cfg = row[ORACLE_COL_CONFIRM_CFG];
    const uint32_t retry_cnt   = row[ORACLE_COL_RETRY_CNT];
    const uint32_t rec_retry   = row[ORACLE_COL_REC_RETRY];
    const uint32_t reset_code  = row[ORACLE_COL_RESET];
    const uint32_t mbx_cfg     = row[ORACLE_COL_MBX_CFG];
    const uint32_t cloud_cfg   = row[ORACLE_COL_CLOUD_CFG];
    const uint32_t tamper_cfg  = row[ORACLE_COL_TAMPER_CFG];

    if (suite < ORACLE_SUITE_COUNT) {
      suite_counts[suite]++;
    }

    /* 1. Restore clean baseline flash + baseline OTP epoch */
    memcpy(s_flash, s_base_flash, sizeof(s_flash));
    s_otp_svn = ORACLE_BASELINE_OTP_SVN;

    /* 2. Materialize App_Slot_0, Backup_Slot (Scratch), Staging_Slot, Mailbox, Cloud */
    if (slot_cfg == 0U || slot_cfg == 1U) {
      memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], s_img_app_v2, ORACLE_IMAGE_BYTES);
    }
    if (slot_cfg == 0U || slot_cfg == 2U) {
      memcpy(&s_flash[CHIP_SCRATCH_SLOT_ABS_ADDR], s_img_bkup_v1, ORACLE_IMAGE_BYTES);
    }
    if (stg_cfg < ORACLE_STG_CFG_COUNT && stg_cfg != 0U) {
      memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR], s_stg_bundles[stg_cfg],
             ORACLE_STG_BUNDLE_BYTES);
    }
    materialize_mailbox_cfg(mbx_cfg);
    materialize_cloud_cfg(cloud_cfg);

    /* 3. Decode confirmation quad (active_nonce, wal_expected_nonce, rtc_nonce) */
    uint64_t act_nonce = 0ULL;
    uint64_t wal_exp_nonce = 0ULL;
    uint64_t rtc_nonce = 0ULL;
    switch (confirm_cfg) {
    case 0U:
      break;
    case 1U:
      act_nonce = ORACLE_NONCE_ACTIVE;
      wal_exp_nonce = ORACLE_NONCE_MISMATCH;
      break;
    case 2U:
      act_nonce = ORACLE_NONCE_ACTIVE;
      wal_exp_nonce = ORACLE_NONCE_ACTIVE;
      break;
    default:
      act_nonce = ORACLE_NONCE_ACTIVE;
      wal_exp_nonce = ORACLE_NONCE_MISMATCH;
      rtc_nonce = ORACLE_NONCE_ACTIVE;
      break;
    }

    /* 4. Seed authentic TMR quorum + WAL entry through production boot_journal APIs */
    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    assert(boot_journal_init(&s_platform) == BOOT_OK);

    wal_tmr_payload_t init_tmr;
    assert(boot_journal_get_tmr(&s_platform, &init_tmr) == BOOT_OK);
    init_tmr.app_svn = ORACLE_BASELINE_TMR_SVN;
    init_tmr.stage1_svn = BOOT_STAGE1_SVN;
    init_tmr.boot_failure_counter = retry_cnt;
    init_tmr.recovery_failure_counter = rec_retry;
    init_tmr.active_nonce_lo = (uint32_t)(act_nonce & 0xFFFFFFFFULL);
    init_tmr.active_nonce_hi = (uint32_t)(act_nonce >> 32U);
    init_tmr.chain_entry_count = ORACLE_INIT_CHAIN_COUNT;
    init_tmr.last_mbx_request_id = ORACLE_BASELINE_MBX_SEQ;
    init_tmr.last_accepted_issued_at = ORACLE_BASELINE_CLOUD_ISSUED;
    assert(boot_journal_update_tmr(&s_platform, &init_tmr) == BOOT_OK);

    uint32_t aux_ent_addr = 0U;
    if (tamper_cfg == ORACLE_TAMPER_AUX_MAC_BAD) {
      aux_ent_addr = wal_sector_addrs[active_wal_index] + cached_write_offset;
      wal_entry_payload_t aux_entry;
      memset(&aux_entry, 0, sizeof(aux_entry));
      aux_entry.intent = (uint32_t)WAL_INTENT_CONFIRM_COMMIT;
      aux_entry.expected_nonce = ORACLE_NONCE_ACTIVE;
      assert(boot_journal_append(&s_platform, &aux_entry) == BOOT_OK);

      wal_entry_payload_t sb_accum;
      memset(&sb_accum, 0, sizeof(sb_accum));
      sb_accum.intent = (uint32_t)WAL_INTENT_NET_SEARCH_ACCUM;
      assert(boot_journal_append(&s_platform, &sb_accum) == BOOT_OK);

      wal_entry_payload_t sb_ckpt;
      memset(&sb_ckpt, 0, sizeof(sb_ckpt));
      sb_ckpt.intent = (uint32_t)WAL_INTENT_DOWNLOAD_CHECKPOINT;
      assert(boot_journal_append(&s_platform, &sb_ckpt) == BOOT_OK);
    }

    wal_entry_payload_t init_entry;
    memset(&init_entry, 0, sizeof(init_entry));
    init_entry.intent = decode_wal_to_c(wal_code);
    init_entry.expected_nonce = wal_exp_nonce;
    init_entry.offset = CHIP_STAGING_SLOT_ABS_ADDR;
    assert(boot_journal_append(&s_platform, &init_entry) == BOOT_OK);

    /* 5. Inject K4 MAC tamper (CRC-valid offline SPI forgery) if requested */
    if (tamper_cfg == ORACLE_TAMPER_TMR_MAC_BAD) {
      for (uint32_t i = 0U; i < TOOB_WAL_SECTORS; i++) {
        wal_sector_header_aligned_t hdr;
        memcpy(&hdr, &s_flash[wal_sector_addrs[i]], sizeof(hdr));
        if (hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_CURRENT) {
          hdr.data.tmr_data.chain_tag[0] ^= 0xFFU;
          hdr.data.header_crc32 = sector_hdr_crc(&hdr.data);
          memcpy(&s_flash[wal_sector_addrs[i]], &hdr, sizeof(hdr));
        }
      }
    } else if (tamper_cfg == ORACLE_TAMPER_WAL_MAC_BAD) {
      const uint32_t ent_addr = wal_sector_addrs[active_wal_index] +
                                cached_write_offset -
                                (uint32_t)sizeof(wal_entry_aligned_t);
      wal_entry_aligned_t ent;
      memcpy(&ent, &s_flash[ent_addr], sizeof(ent));
      ent.data.transfer_bitmap[4] ^= 0xFFFFFFFFU;
      ent.data.crc32_trailer = entry_crc(&ent.data);
      memcpy(&s_flash[ent_addr], &ent, sizeof(ent));
    } else if (tamper_cfg == ORACLE_TAMPER_AUX_MAC_BAD) {
      wal_entry_aligned_t ent;
      memcpy(&ent, &s_flash[aux_ent_addr], sizeof(ent));
      ent.data.transfer_bitmap[4] ^= 0xFFFFFFFFU;
      ent.data.crc32_trailer = entry_crc(&ent.data);
      memcpy(&s_flash[aux_ent_addr], &ent, sizeof(ent));
    }

    /* 6. Simulate MCU reset into Stage 1 entry (`boot_main`) */
    const reset_reason_t rst = decode_reset_to_c(reset_code);
    sim_reset_sram_globals(rst);
    s_rtc_confirm_nonce = rtc_nonce;

    boot_target_config_t target;
    memset(&target, 0, sizeof(target));
    boot_status_t ret_status = BOOT_OK;
    const int panicked = execute_boot_with_panic_trap(&target, &ret_status);

    /* 7. Extract all 10 post-boot observables */
    uint32_t got_kind = ORACLE_OUT_BOOT_APP;
    uint32_t got_err = ORACLE_ERR_OK;
    uint32_t got_tent = 0U;

    if (panicked != 0 || ret_status != BOOT_OK) {
      got_kind = ORACLE_OUT_SERIAL_RESCUE;
      got_err = encode_status_to_oracle_err(ret_status);
      got_tent = 0U;
    } else if (target.boot_recovery_os) {
      got_kind = ORACLE_OUT_RECOVERY_OS;
      got_err = ORACLE_ERR_OK;
      got_tent = 0U;
    } else {
      got_kind = ORACLE_OUT_BOOT_APP;
      got_err = ORACLE_ERR_OK;
      got_tent = target.is_tentative_boot ? 1U : 0U;
      if (target.proof.image_addr != CHIP_APP_SLOT_ABS_ADDR) {
        got_err = ORACLE_ERR_UNMAPPED;
      }
    }

    const uint32_t got_app_id = inspect_post_boot_app_id();
    wal_tmr_payload_t post_tmr;
    memset(&post_tmr, 0, sizeof(post_tmr));
    uint32_t got_wal = ORACLE_WI_NONE;
    inspect_post_boot_wal_and_tmr(&post_tmr, &got_wal);

    const uint32_t got_bf = post_tmr.boot_failure_counter;
    const uint32_t got_rf = post_tmr.recovery_failure_counter;
    const uint32_t got_nonce =
        ((post_tmr.active_nonce_lo | post_tmr.active_nonce_hi) != 0U) ? 1U : 0U;
    const uint32_t got_tmr_svn = post_tmr.app_svn;
    const uint32_t got_otp_svn = s_otp_svn;
    const uint32_t got_issued = post_tmr.last_accepted_issued_at;
    const uint32_t got_wipe = toob_handoff_state.wipe_requested;

    /* 8. Assert 1:1 equivalence against Rocq formal oracle vector */
    const bool match =
        (got_kind    == (uint32_t)row[ORACLE_COL_OUT_KIND]) &&
        (got_err     == (uint32_t)row[ORACLE_COL_OUT_ERR]) &&
        (got_tent    == (uint32_t)row[ORACLE_COL_OUT_TENT]) &&
        (got_app_id  == (uint32_t)row[ORACLE_COL_OUT_APP_ID]) &&
        (got_bf      == (uint32_t)row[ORACLE_COL_OUT_BF]) &&
        (got_rf      == (uint32_t)row[ORACLE_COL_OUT_RF]) &&
        (got_nonce   == (uint32_t)row[ORACLE_COL_OUT_NONCE]) &&
        (got_wal     == (uint32_t)row[ORACLE_COL_OUT_WAL]) &&
        (got_tmr_svn == (uint32_t)row[ORACLE_COL_OUT_TMR_SVN]) &&
        (got_otp_svn == (uint32_t)row[ORACLE_COL_OUT_OTP_SVN]) &&
        (got_issued  == (uint32_t)row[ORACLE_COL_OUT_ISSUED]) &&
        (got_wipe    == (uint32_t)row[ORACLE_COL_OUT_WIPE]);

    if (!match) {
      if (mismatches < ORACLE_MAX_REPORTED_DIFFS) {
        fprintf(stderr,
                "MISMATCH vec=%u (suite=%u sl=%u stg=%u wi=%u cf=%u bf=%u rf=%u rst=%u mbx=%u cld=%u tmp=%u):\n"
                "  expected: kind=%u err=%u tent=%u app=%u bf=%u rf=%u n=%u wal=%u tsvn=%u osvn=%u iss=%u wipe=%u\n"
                "  actual  : kind=%u err=%u tent=%u app=%u bf=%u rf=%u n=%u wal=%u tsvn=%u osvn=%u iss=%u wipe=%u (raw_st=0x%08X)\n",
                idx, suite, slot_cfg, stg_cfg, wal_code, confirm_cfg, retry_cnt,
                rec_retry, reset_code, mbx_cfg, cloud_cfg, tamper_cfg,
                (unsigned)row[ORACLE_COL_OUT_KIND],
                (unsigned)row[ORACLE_COL_OUT_ERR],
                (unsigned)row[ORACLE_COL_OUT_TENT],
                (unsigned)row[ORACLE_COL_OUT_APP_ID],
                (unsigned)row[ORACLE_COL_OUT_BF],
                (unsigned)row[ORACLE_COL_OUT_RF],
                (unsigned)row[ORACLE_COL_OUT_NONCE],
                (unsigned)row[ORACLE_COL_OUT_WAL],
                (unsigned)row[ORACLE_COL_OUT_TMR_SVN],
                (unsigned)row[ORACLE_COL_OUT_OTP_SVN],
                (unsigned)row[ORACLE_COL_OUT_ISSUED],
                (unsigned)row[ORACLE_COL_OUT_WIPE],
                got_kind, got_err, got_tent, got_app_id, got_bf, got_rf,
                got_nonce, got_wal, got_tmr_svn, got_otp_svn,
                got_issued, got_wipe,
                (unsigned)ret_status);
      }
      mismatches++;
    }
  }

  /* 9. Coupled TDR1-02 / TDR1-03 / FV-17b (`BOOT_ERR_DEFER`) invariants */
  {
    /* 9a. Tentative apply -> Crash rollback -> Re-apply -> Confirm promotion */
    memcpy(s_flash, s_base_flash, sizeof(s_flash));
    s_otp_svn = ORACLE_BASELINE_OTP_SVN;
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], s_img_app_v2, ORACLE_IMAGE_BYTES);
    memcpy(&s_flash[CHIP_SCRATCH_SLOT_ABS_ADDR], s_img_bkup_v1, ORACLE_IMAGE_BYTES);
    memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR],
           s_stg_bundles[ORACLE_STG_CFG_VALID_V3], ORACLE_STG_BUNDLE_BYTES);

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    assert(boot_journal_init(&s_platform) == BOOT_OK);
    wal_tmr_payload_t tmr0;
    assert(boot_journal_get_tmr(&s_platform, &tmr0) == BOOT_OK);
    tmr0.app_svn = ORACLE_SVN_APP_V2;
    tmr0.app_build_number = ORACLE_BUILD_APP_V2;
    tmr0.active_key_index = ORACLE_KEY_INDEX_ACTIVE;
    tmr0.pending_key_index = 0U;
    tmr0.pending_build_number = 0U;
    assert(boot_journal_update_tmr(&s_platform, &tmr0) == BOOT_OK);

    wal_entry_payload_t upd_ent;
    memset(&upd_ent, 0, sizeof(upd_ent));
    upd_ent.intent = (uint32_t)WAL_INTENT_UPDATE_PENDING;
    upd_ent.offset = CHIP_STAGING_SLOT_ABS_ADDR;
    assert(boot_journal_append(&s_platform, &upd_ent) == BOOT_OK);

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    s_rtc_confirm_nonce = 0ULL;
    boot_target_config_t tgt1;
    memset(&tgt1, 0, sizeof(tgt1));
    boot_status_t st1 = BOOT_OK;
    int pan1 = execute_boot_with_panic_trap(&tgt1, &st1);

    wal_tmr_payload_t tmr1;
    uint32_t wal1 = ORACLE_WI_NONE;
    inspect_post_boot_wal_and_tmr(&tmr1, &wal1);

    if (pan1 != 0 || st1 != BOOT_OK || !tgt1.is_tentative_boot ||
        tmr1.app_build_number != ORACLE_BUILD_APP_V2 ||
        (tmr1.pending_key_index & WAL_TMR_PENDING_META_BIT) == 0U ||
        tmr1.pending_build_number != ORACLE_BUILD_STG_V3 ||
        toob_diag_state.last_update_outcome != ORACLE_OUTCOME_APPLIED) {
      fprintf(stderr, "MISMATCH extended TDR1-02/03 tentative-apply check\n");
      mismatches++;
    }

    /* Watchdog crash triggers rollback: pending cleared, ratified preserved,
     * outcome == 3 (reverted), pre-heal observed_failure_count >= 1 */
    sim_reset_sram_globals(RESET_REASON_WATCHDOG);
    s_rtc_confirm_nonce = 0ULL;
    boot_target_config_t tgt2;
    memset(&tgt2, 0, sizeof(tgt2));
    boot_status_t st2 = BOOT_OK;
    int pan2 = execute_boot_with_panic_trap(&tgt2, &st2);

    wal_tmr_payload_t tmr2;
    uint32_t wal2 = ORACLE_WI_NONE;
    inspect_post_boot_wal_and_tmr(&tmr2, &wal2);

    if (pan2 != 0 || st2 != BOOT_OK || tgt2.is_tentative_boot ||
        tmr2.app_build_number != ORACLE_BUILD_APP_V2 ||
        (tmr2.pending_key_index & WAL_TMR_PENDING_META_BIT) != 0U ||
        toob_diag_state.last_update_outcome != ORACLE_OUTCOME_REVERTED ||
        toob_diag_state.edge_recovery_events == 0U) {
      fprintf(stderr, "MISMATCH extended TDR1-02/03 rollback check\n");
      mismatches++;
    }

    /* Re-stage v3 and confirm via RTC nonce: pending promotes into app_* */
    memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR],
           s_stg_bundles[ORACLE_STG_CFG_VALID_V3], ORACLE_STG_BUNDLE_BYTES);
    assert(boot_journal_append(&s_platform, &upd_ent) == BOOT_OK);

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    s_rtc_confirm_nonce = 0ULL;
    boot_target_config_t tgt3;
    memset(&tgt3, 0, sizeof(tgt3));
    boot_status_t st3 = BOOT_OK;
    (void)execute_boot_with_panic_trap(&tgt3, &st3);

    wal_tmr_payload_t tmr3;
    uint32_t wal3 = ORACLE_WI_NONE;
    inspect_post_boot_wal_and_tmr(&tmr3, &wal3);
    const uint64_t live_nonce =
        ((uint64_t)tmr3.active_nonce_hi << 32U) | (uint64_t)tmr3.active_nonce_lo;

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    s_rtc_confirm_nonce = live_nonce;
    boot_target_config_t tgt4;
    memset(&tgt4, 0, sizeof(tgt4));
    boot_status_t st4 = BOOT_OK;
    int pan4 = execute_boot_with_panic_trap(&tgt4, &st4);

    wal_tmr_payload_t tmr4;
    uint32_t wal4 = ORACLE_WI_NONE;
    inspect_post_boot_wal_and_tmr(&tmr4, &wal4);

    if (pan4 != 0 || st4 != BOOT_OK || tgt4.is_tentative_boot ||
        tmr4.app_build_number != ORACLE_BUILD_STG_V3 ||
        (tmr4.pending_key_index & WAL_TMR_PENDING_META_BIT) != 0U) {
      fprintf(stderr, "MISMATCH extended TDR1-02 confirm-promotion check\n");
      mismatches++;
    }

    /* 9b. TDR1-03 controlled verify rejection preserves ratified app identity */
    memcpy(s_flash, s_base_flash, sizeof(s_flash));
    s_otp_svn = ORACLE_BASELINE_OTP_SVN;
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], s_img_app_v2, ORACLE_IMAGE_BYTES);
    memcpy(&s_flash[CHIP_SCRATCH_SLOT_ABS_ADDR], s_img_bkup_v1, ORACLE_IMAGE_BYTES);
    memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR],
           s_stg_bundles[ORACLE_STG_CFG_BAD_SIG], ORACLE_STG_BUNDLE_BYTES);

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    assert(boot_journal_init(&s_platform) == BOOT_OK);
    assert(boot_journal_update_tmr(&s_platform, &tmr0) == BOOT_OK);
    assert(boot_journal_append(&s_platform, &upd_ent) == BOOT_OK);

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    s_rtc_confirm_nonce = 0ULL;
    boot_target_config_t tgt_rej;
    memset(&tgt_rej, 0, sizeof(tgt_rej));
    boot_status_t st_rej = BOOT_OK;
    int pan_rej = execute_boot_with_panic_trap(&tgt_rej, &st_rej);

    if (pan_rej != 0 || st_rej != BOOT_OK ||
        inspect_post_boot_app_id() != ORACLE_PAYLOAD_ID_APP_V2 ||
        toob_diag_state.last_update_outcome != ORACLE_OUTCOME_REJECTED ||
        toob_diag_state.build_number != ORACLE_BUILD_APP_V2) {
      fprintf(stderr, "MISMATCH extended TDR1-03 verify-rejection check\n");
      mismatches++;
    }

    /* 9c. FV-17b low-Vbat deferral (BOOT_ERR_DEFER -> SLEEP_BACKOFF, 0 retries) */
    memcpy(s_flash, s_base_flash, sizeof(s_flash));
    s_otp_svn = ORACLE_BASELINE_OTP_SVN;
    memcpy(&s_flash[CHIP_APP_SLOT_ABS_ADDR], s_img_app_v2, ORACLE_IMAGE_BYTES);
    memcpy(&s_flash[CHIP_SCRATCH_SLOT_ABS_ADDR], s_img_bkup_v1, ORACLE_IMAGE_BYTES);
    memcpy(&s_flash[CHIP_STAGING_SLOT_ABS_ADDR],
           s_stg_bundles[ORACLE_STG_CFG_VALID_V3], ORACLE_STG_BUNDLE_BYTES);

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    assert(boot_journal_init(&s_platform) == BOOT_OK);
    assert(boot_journal_update_tmr(&s_platform, &tmr0) == BOOT_OK);
    assert(boot_journal_append(&s_platform, &upd_ent) == BOOT_OK);

    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    s_supply_mv = ORACLE_LOW_SUPPLY_MV;
    s_rtc_confirm_nonce = 0ULL;
    boot_target_config_t tgt_def;
    memset(&tgt_def, 0, sizeof(tgt_def));
    boot_status_t st_def = BOOT_OK;
    int pan_def = execute_boot_with_panic_trap(&tgt_def, &st_def);

    wal_tmr_payload_t tmr_def;
    assert(boot_journal_get_tmr(&s_platform, &tmr_def) == BOOT_OK);
    wal_entry_payload_t txn_def;
    memset(&txn_def, 0, sizeof(txn_def));
    assert(boot_journal_reconstruct_txn(&s_platform, &txn_def, NULL, NULL) == BOOT_OK);

    const uint32_t head_ent_addr = wal_sector_addrs[active_wal_index] +
                                   cached_write_offset -
                                   (uint32_t)sizeof(wal_entry_aligned_t);
    wal_entry_aligned_t head_ent;
    memcpy(&head_ent, &s_flash[head_ent_addr], sizeof(head_ent));

    if (pan_def != 0 || st_def != BOOT_OK ||
        inspect_post_boot_app_id() != ORACLE_PAYLOAD_ID_APP_V2 ||
        toob_diag_state.last_update_outcome != ORACLE_OUTCOME_DEFERRED ||
        tmr_def.boot_failure_counter != 0U ||
        tmr_def.recovery_failure_counter != 0U ||
        head_ent.data.intent != (uint32_t)WAL_INTENT_SLEEP_BACKOFF ||
        txn_def.intent != (uint32_t)WAL_INTENT_UPDATE_PENDING) {
      fprintf(stderr, "MISMATCH extended FV-17b low-Vbat BOOT_ERR_DEFER check\n");
      mismatches++;
    }

    /* Next boot with restored supply voltage completes the deferred update */
    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    s_supply_mv = ORACLE_SUPPLY_MV;
    s_rtc_confirm_nonce = 0ULL;
    boot_target_config_t tgt_res;
    memset(&tgt_res, 0, sizeof(tgt_res));
    boot_status_t st_res = BOOT_OK;
    int pan_res = execute_boot_with_panic_trap(&tgt_res, &st_res);

    if (pan_res != 0 || st_res != BOOT_OK || !tgt_res.is_tentative_boot ||
        inspect_post_boot_app_id() != ORACLE_PAYLOAD_ID_STG_V3 ||
        toob_diag_state.last_update_outcome != ORACLE_OUTCOME_APPLIED) {
      fprintf(stderr, "MISMATCH extended FV-17b post-recharge liveness check\n");
      mismatches++;
    }
  }

  printf("[Suite 0: Cartesian Core + 2x2x2 Staging Cube] vectors=%u\n",
         suite_counts[0]);
  printf("[Suite 1: Recovery-OS Retry Exhaustion]        vectors=%u\n",
         suite_counts[1]);
  printf("[Suite 2: OS Mailbox v2 & CRIT-24 Cumulative]  vectors=%u\n",
         suite_counts[2]);
  printf("[Suite 3: Pre-Auth TCC1 Cloud Commands]        vectors=%u\n",
         suite_counts[3]);
  printf("[Suite 4: K4 TMR & Security-Entry MAC Tamper]  vectors=%u\n",
         suite_counts[4]);
  printf("[Suite 5: TDR1-02/03 & Low-Vbat Deferral]      checks=3\n");
  printf("ROCQ_ORACLE_SUMMARY vectors=%u mismatches=%u status=%s\n",
         (unsigned)ROCQ_ORACLE_VECTOR_COUNT, mismatches,
         (mismatches == 0U) ? "PASS" : "FAIL");

  return (mismatches == 0U) ? 0 : 1;
}
