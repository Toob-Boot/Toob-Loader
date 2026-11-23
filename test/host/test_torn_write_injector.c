/**
 * @file test_torn_write_injector.c
 * @brief Exhaustive C17 Host-SIL Torn-Write, Power-Cut & ECC Write-Once Fault Injector (Wave 5C)
 *
 * Proves Non-Brickability (Theorem 1), Crash-Idempotence (Theorem 2),
 * Anti-Rollback Monotonicity (svn >= otp_min_svn), and Hardware 8-Byte / 32-Byte
 * ECC Write-Once Compliance across all Toob-Loader Core update & rollback paths:
 *   - Suite 1: Tier 0 (BFB2 Dual-Bank) & Tier 1B (XIP_REMAP + ONEWAY) Full TBM1 OTA
 *   - Suite 2: Tier 2B (Swap-Move) & Tier 3 (Swap-Scratch) two-way swap + WDT rollback
 *   - Suite 3: TDS1 Forward-Delta + Heatshrink decompression + Region 6 Reverse-Delta rollback
 *   - Suite 4: Asymmetric STM32F4 sector geometry (16 KB / 64 KB / 128 KB + mixed WAL)
 *   - Suite 5: Nested Double Power-Cuts (abort at k1, abort recovery at k2, 3rd boot converges)
 *   - Suite 6: Hardware 8B (STM32L4) & 32B (STM32H7) ECC write-once bitmap observer
 */

#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TOOB_INJ_PROFILE
#define TOOB_INJ_PROFILE 1
#endif

/* ============================================================================
 * Compile-Time Chip & Transport Profiles (1..6)
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

#define CHIP_FLASH_BASE_ADDR             0x00000000U
#define CHIP_FLASH_XIP_BASE              0x08000000U
#define CHIP_FLASH_ERASED_BYTE           0xFFU
#define CHIP_MMU_PAGE_SIZE               65536U

#if TOOB_INJ_PROFILE == 6
/* Profile 6: STM32F429 Dual-Bank 2 MB asymmetric sector layout (16K / 64K / 128K) */
#define CHIP_FLASH_WRITE_ALIGNMENT       32U
#define CHIP_FLASH_TOTAL_SIZE            0x00200000U
#define CHIP_FLASH_MAX_SECTOR_SIZE       0x00020000U

#define CHIP_STAGE0_ABS_ADDR             0x00000000U
#define CHIP_STAGE0_SIZE                 0x00004000U
#define CHIP_STAGE1A_ABS_ADDR            0x00004000U
#define CHIP_STAGE1A_SIZE                0x00004000U
#define CHIP_STAGE1B_ABS_ADDR            0x00104000U
#define CHIP_STAGE1B_SIZE                0x00004000U
#define CHIP_APP_SLOT_ABS_ADDR           0x00008000U
#define CHIP_APP_SLOT_SIZE               0x00038000U /* 16K + 16K + 64K + 128K = 224K */
#define CHIP_RECOVERY_OS_ABS_ADDR        0x00040000U
#define CHIP_RECOVERY_OS_SIZE            0x00020000U
#define CHIP_CLOUD_CMD_SLOT_ABS_ADDR     0x00060000U
#define CHIP_CLOUD_CMD_SLOT_SIZE         0x00020000U
#define CHIP_STAGING_SLOT_ABS_ADDR       0x00088000U
#define CHIP_STAGING_SLOT_SIZE           0x00058000U /* 16K + 16K + 64K + 128K + 128K = 352K */
#define CHIP_FORENSIC_SLOT_ABS_ADDR      0x00100000U
#define CHIP_FORENSIC_SLOT_SIZE          0x00004000U
#define CHIP_SCRATCH_SLOT_ABS_ADDR       0x00108000U
#define CHIP_SCRATCH_SLOT_SIZE           0x00038000U /* 16K + 16K + 64K + 128K = 224K */
#define CHIP_MAILBOX_ABS_ADDR            0x00140000U
#define CHIP_MAILBOX_SLOT_SIZE           0x00020000U
#define CHIP_MAILBOX_SIZE                0x00040000U
#define CHIP_WAL_ABS_ADDR                0x00180000U
#define CHIP_WAL_SIZE                    0x00020000U
#define CHIP_KDM_QUORUM_ABS_ADDR         0x001A0000U
#define CHIP_KDM_QUORUM_SIZE             0x00060000U
#define CHIP_NETCORE_SLOT_ABS_ADDR       0x00000000U
#define CHIP_NETCORE_SLOT_SIZE           0x00000000U

#define TOOB_WAL_SECTORS                 5U
#define TOOB_WAL_SECTOR_ADDRS            { 0x00180000U, 0x00184000U, 0x00188000U, 0x0018C000U, 0x00190000U }
#define TOOB_WAL_SECTOR_SIZES            { 0x00004000U, 0x00004000U, 0x00004000U, 0x00004000U, 0x00010000U }

#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_ONEWAY
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_FULL

#else /* Uniform 4 KB sector 512 KB NOR flash profiles (1..5) */

#if (TOOB_INJ_PROFILE == 2) || (TOOB_INJ_PROFILE == 4)
#define CHIP_FLASH_WRITE_ALIGNMENT       32U
#else
#define CHIP_FLASH_WRITE_ALIGNMENT       8U
#endif

#define CHIP_FLASH_TOTAL_SIZE            0x00080000U
#define CHIP_FLASH_MAX_SECTOR_SIZE       0x00001000U

#define CHIP_STAGE0_ABS_ADDR             0x00000000U
#define CHIP_STAGE0_SIZE                 0x00002000U
#define CHIP_STAGE1A_ABS_ADDR            0x00002000U
#define CHIP_STAGE1A_SIZE                0x00002000U
#define CHIP_STAGE1B_ABS_ADDR            0x00004000U
#define CHIP_STAGE1B_SIZE                0x00002000U
#define CHIP_APP_SLOT_ABS_ADDR           0x00010000U /* 64 KB-aligned for XIP MMU */
#define CHIP_APP_SLOT_SIZE               0x00008000U /* 32 KB (8 sectors) */
#define CHIP_STAGING_SLOT_ABS_ADDR       0x00020000U /* 64 KB-aligned for XIP MMU */
#define CHIP_STAGING_SLOT_SIZE           0x0000C000U /* 48 KB (12 sectors) */

#if (TOOB_INJ_PROFILE == 1) || (TOOB_INJ_PROFILE == 3)
#define CHIP_SCRATCH_SLOT_ABS_ADDR       0x00000000U
#define CHIP_SCRATCH_SLOT_SIZE           0x00000000U
#elif TOOB_INJ_PROFILE == 4
#define CHIP_SCRATCH_SLOT_ABS_ADDR       0x00030000U
#define CHIP_SCRATCH_SLOT_SIZE           0x00004000U /* 16 KB (4-sector wear ring) */
#else
#define CHIP_SCRATCH_SLOT_ABS_ADDR       0x00030000U
#define CHIP_SCRATCH_SLOT_SIZE           0x00008000U /* 32 KB backup/delta scratch */
#endif

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

#if TOOB_INJ_PROFILE == 1
#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_POINTER
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_NONE
#elif TOOB_INJ_PROFILE == 2
#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_ONEWAY
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_FULL
#elif TOOB_INJ_PROFILE == 3
#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_SWAPMOVE
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_NONE
#elif TOOB_INJ_PROFILE == 4
#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_SWAPSCRATCH
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_NONE
#elif TOOB_INJ_PROFILE == 5
#define TOOB_TRANSPORT_PROVIDER          TOOB_TRANSPORT_ONEWAY
#define TOOB_ONEWAY_BACKUP_MODE          TOOB_ONEWAY_BACKUP_REVERSE_DELTA
#else
#error "Unsupported TOOB_INJ_PROFILE"
#endif

#endif /* TOOB_INJ_PROFILE == 6 */

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
 * Production Core Modules (Single-TU White-Box Inclusion for Full SRAM Reset)
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

/* ============================================================================
 * Panic / Provisioning Traps
 * ============================================================================ */
_Noreturn void boot_terminal_halt(const boot_platform_t *p, boot_status_t r,
                                  uint16_t site) {
  (void)p;
  fprintf(stderr, "FATAL: unexpected boot_terminal_halt(0x%08X, site=%u)\n",
          (unsigned)r, (unsigned)site);
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
  fprintf(stderr, "FATAL: unexpected boot_provisioning_run\n");
  abort();
}

/* ============================================================================
 * Physical NOR Flash Simulator + ECC Write-Once Observer + Torn-Write Injector
 * ============================================================================ */
#define ECC_WORD_COUNT (CHIP_FLASH_TOTAL_SIZE / CHIP_FLASH_WRITE_ALIGNMENT)
#define MAX_RECORDED_OPS 4096U

typedef enum {
  CORRUPT_MODE_A_CLEAN_PREFIX = 0,
  CORRUPT_MODE_B_METASTABLE_BITFLIP = 1,
  CORRUPT_MODE_C_HALF_ERASE_TAIL = 2,
  CORRUPT_MODE_COUNT = 3
} corrupt_mode_t;

typedef struct {
  bool is_erase;
  uint32_t addr;
  uint32_t len;
  bool is_critical; /* WAL, Mailbox, Erase, Header/Trailer, or Sector Boundary */
} recorded_op_t;

static uint8_t s_flash[CHIP_FLASH_TOTAL_SIZE];
static uint8_t s_ecc_written[ECC_WORD_COUNT];

/* Snapshot storage for fast deterministic step-k replay */
typedef struct {
  uint8_t flash[CHIP_FLASH_TOTAL_SIZE];
  uint8_t ecc_written[ECC_WORD_COUNT];
  uint32_t otp_svn;
  uint32_t bfb2_bank;
  uint32_t xip_volatile_slot;
  uint64_t rtc_confirm_nonce;
  reset_reason_t reset_reason;
} hw_snapshot_t;

static hw_snapshot_t s_snap;

/* Fault-injection control */
static jmp_buf s_power_cut_jmp;
static bool s_record_ops = false;
static recorded_op_t s_recorded[MAX_RECORDED_OPS];
static uint32_t s_recorded_count = 0U;

static uint32_t s_flash_op_counter = 0U;
static uint32_t s_cut_at_op = 0U;
static corrupt_mode_t s_corrupt_mode = CORRUPT_MODE_A_CLEAN_PREFIX;

/* Global telemetry counters reported at exit */
static uint64_t s_total_power_cuts_executed = 0ULL;
static uint64_t s_total_ecc_word_checks = 0ULL;

/* Persistent vs volatile hardware state */
static uint32_t s_otp_svn = 0U;
static uint8_t s_dslc_state = 0x01U;
static uint32_t s_bfb2_bank = 0U;         /* Persistent across POWER_ON */
static uint32_t s_xip_volatile_slot = 0U; /* Volatile: cleared on POWER_ON */
static uint64_t s_rtc_confirm_nonce = 0ULL;
static reset_reason_t s_reset_reason = RESET_REASON_POWER_ON;
static uint32_t s_tick_ms = 100U;
static uint32_t s_rng_state = 0x9E3779B9U;

static uint8_t s_root_sk[64];
static uint8_t s_root_pk[32];
static uint8_t s_cloud_sk[64];
static uint8_t s_cloud_pk[32];

static const uint32_t k_seal_key[4] = {
    0xA55A1234U, 0xC33C5678U, 0x96699ABCU, 0xF00FDEF0U
};

static boot_status_t sim_flash_get_sector_size(uint32_t addr, size_t *size_out) {
  if (!size_out || addr >= CHIP_FLASH_TOTAL_SIZE) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
#if TOOB_INJ_PROFILE == 6
  /* STM32F429 Dual-Bank: each 512 KB half-bank = 4x16K + 1x64K + 3x128K */
  uint32_t sub = addr & 0x0007FFFFU;
  if (sub < 0x00010000U) {
    *size_out = 0x00004000U; /* 16 KB */
  } else if (sub < 0x00020000U) {
    *size_out = 0x00010000U; /* 64 KB */
  } else {
    *size_out = 0x00020000U; /* 128 KB */
  }
#else
  *size_out = 4096U;
#endif
  return BOOT_OK;
}

static uint32_t sector_base_of(uint32_t addr) {
#if TOOB_INJ_PROFILE == 6
  uint32_t bank = addr & ~0x0007FFFFU;
  uint32_t sub = addr & 0x0007FFFFU;
  if (sub < 0x00010000U) {
    return bank + (sub & ~0x00003FFFU);
  }
  if (sub < 0x00020000U) {
    return bank + 0x00010000U;
  }
  return bank + (sub & ~0x0001FFFFU);
#else
  return addr & ~0x00000FFFU;
#endif
}

static bool op_is_critical(bool is_erase, uint32_t addr, size_t len) {
  if (is_erase) {
    return true;
  }
  if (addr >= CHIP_WAL_ABS_ADDR && addr < (CHIP_WAL_ABS_ADDR + CHIP_WAL_SIZE)) {
    return true;
  }
  if (addr >= CHIP_MAILBOX_ABS_ADDR &&
      addr < (CHIP_MAILBOX_ABS_ADDR + CHIP_MAILBOX_SIZE)) {
    return true;
  }
  if (addr >= CHIP_KDM_QUORUM_ABS_ADDR &&
      addr < (CHIP_KDM_QUORUM_ABS_ADDR + CHIP_KDM_QUORUM_SIZE)) {
    return true;
  }
  uint32_t sbase = sector_base_of(addr);
  size_t ssize = 4096U;
  (void)sim_flash_get_sector_size(addr, &ssize);
  if (addr == sbase || (addr + (uint32_t)len) >= (sbase + (uint32_t)ssize)) {
    return true;
  }
  return false;
}

static void assert_ecc_clean_and_check_nor(uint32_t addr, const uint8_t *src,
                                           size_t len, bool check_src_bits) {
  uint32_t first_word = addr / CHIP_FLASH_WRITE_ALIGNMENT;
  uint32_t word_count = (uint32_t)(len / CHIP_FLASH_WRITE_ALIGNMENT);
  for (uint32_t w = 0U; w < word_count; w++) {
    s_total_ecc_word_checks++;
    if (s_ecc_written[first_word + w] != 0U) {
      fprintf(stderr,
              "ECC WRITE-ONCE VIOLATION (align=%u): double-write without erase "
              "at 0x%08X (word=%u, op=%u)!\n",
              (unsigned)CHIP_FLASH_WRITE_ALIGNMENT,
              (unsigned)((first_word + w) * CHIP_FLASH_WRITE_ALIGNMENT),
              (unsigned)(first_word + w), (unsigned)s_flash_op_counter);
      abort();
    }
  }
  if (check_src_bits && src != NULL) {
    for (size_t i = 0U; i < len; i++) {
      if ((~s_flash[addr + i] & src[i]) != 0U) {
        fprintf(stderr,
                "NOR 0->1 VIOLATION at 0x%08X+%zu: flash=0x%02X write=0x%02X\n",
                (unsigned)addr, i, s_flash[addr + i], src[i]);
        abort();
      }
    }
  }
}

static void mark_ecc_after_torn_write(uint32_t addr, size_t len,
                                      size_t full_prefix_bytes,
                                      bool hv_fired_on_tail_word,
                                      size_t tail_byte_pos) {
  uint32_t align = CHIP_FLASH_WRITE_ALIGNMENT;
  for (size_t off = 0U; off < len; off += align) {
    uint32_t w = (addr + (uint32_t)off) / align;
    bool complete_word = (off + align <= full_prefix_bytes);
    bool any_non_ff = false;
    for (size_t b = 0U; b < align; b++) {
      if (s_flash[addr + off + b] != 0xFFU) {
        any_non_ff = true;
        break;
      }
    }
    bool hit_tail = hv_fired_on_tail_word &&
                    (tail_byte_pos >= off && tail_byte_pos < (off + align));
    if (complete_word || any_non_ff || (hit_tail && any_non_ff)) {
      s_ecc_written[w] = 1U;
    }
  }
}

static boot_status_t sim_flash_init(void) { return BOOT_OK; }
static void sim_flash_deinit(void) {}

static boot_status_t sim_flash_read(uint32_t addr, void *buf, size_t len) {
  if (!buf || addr > CHIP_FLASH_TOTAL_SIZE ||
      len > CHIP_FLASH_TOTAL_SIZE - addr) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  memcpy(buf, &s_flash[addr], len);
  return BOOT_OK;
}

static boot_status_t sim_flash_write(uint32_t addr, const void *buf,
                                     size_t len) {
  if (!buf || addr > CHIP_FLASH_TOTAL_SIZE ||
      len > CHIP_FLASH_TOTAL_SIZE - addr) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
      (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
    return BOOT_ERR_FLASH_ALIGN;
  }
  if (len == 0U) {
    return BOOT_OK;
  }

  const uint8_t *src = (const uint8_t *)buf;
  s_flash_op_counter++;

  if (s_record_ops && s_recorded_count < MAX_RECORDED_OPS) {
    s_recorded[s_recorded_count].is_erase = false;
    s_recorded[s_recorded_count].addr = addr;
    s_recorded[s_recorded_count].len = (uint32_t)len;
    s_recorded[s_recorded_count].is_critical = op_is_critical(false, addr, len);
    s_recorded_count++;
  }

  /* Always enforce ECC write-once & NOR 1->0 before applying normal or torn write */
  assert_ecc_clean_and_check_nor(addr, src, len, true);

  if (s_cut_at_op != 0U && s_flash_op_counter == s_cut_at_op) {
    size_t prefix = (s_corrupt_mode == CORRUPT_MODE_C_HALF_ERASE_TAIL)
                        ? (len / 4U)
                        : (len / 2U);
    for (size_t i = 0U; i < prefix; i++) {
      s_flash[addr + i] &= src[i];
    }

    if (s_corrupt_mode == CORRUPT_MODE_A_CLEAN_PREFIX) {
      mark_ecc_after_torn_write(addr, len, prefix, false, 0U);
    } else {
      /* Mode B & Mode C write abort: metastable partial bit-flip at cut word */
      size_t pos = prefix;
      if (pos < len) {
        s_flash[addr + pos] &= (uint8_t)(src[pos] | 0x55U);
        /* If the interrupted ECC word had target 0-bits in src but (src[pos]|0x55)
         * happened to equal 0xFF, flip one target 0-bit in that ECC word so the
         * metastable HV-interrupted cell is physically observable in NOR data. */
        size_t w_off = (pos / CHIP_FLASH_WRITE_ALIGNMENT) *
                       CHIP_FLASH_WRITE_ALIGNMENT;
        bool word_all_ff = true;
        for (size_t b = 0U; b < CHIP_FLASH_WRITE_ALIGNMENT; b++) {
          if (s_flash[addr + w_off + b] != 0xFFU) {
            word_all_ff = false;
            break;
          }
        }
        if (word_all_ff) {
          for (size_t b = 0U; b < CHIP_FLASH_WRITE_ALIGNMENT; b++) {
            if (src[w_off + b] != 0xFFU) {
              uint8_t zero_mask = (uint8_t)(~src[w_off + b]);
              uint8_t lowest_zero_bit = (uint8_t)(zero_mask & (0U - zero_mask));
              s_flash[addr + w_off + b] &= (uint8_t)(~lowest_zero_bit);
              break;
            }
          }
        }
      }
      mark_ecc_after_torn_write(addr, len, prefix, true, pos);
    }

    longjmp(s_power_cut_jmp, 1);
  }

  for (size_t i = 0U; i < len; i++) {
    s_flash[addr + i] &= src[i];
  }
  uint32_t first_word = addr / CHIP_FLASH_WRITE_ALIGNMENT;
  uint32_t word_count = (uint32_t)(len / CHIP_FLASH_WRITE_ALIGNMENT);
  for (uint32_t w = 0U; w < word_count; w++) {
    s_ecc_written[first_word + w] = 1U;
  }
  return BOOT_OK;
}

static boot_status_t sim_flash_erase_sector(uint32_t addr) {
  size_t sec_size = 0U;
  if (sim_flash_get_sector_size(addr, &sec_size) != BOOT_OK) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  if (addr != sector_base_of(addr) || addr + sec_size > CHIP_FLASH_TOTAL_SIZE) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  s_flash_op_counter++;

  if (s_record_ops && s_recorded_count < MAX_RECORDED_OPS) {
    s_recorded[s_recorded_count].is_erase = true;
    s_recorded[s_recorded_count].addr = addr;
    s_recorded[s_recorded_count].len = (uint32_t)sec_size;
    s_recorded[s_recorded_count].is_critical = true;
    s_recorded_count++;
  }

  if (s_cut_at_op != 0U && s_flash_op_counter == s_cut_at_op) {
    size_t clean_half = (s_corrupt_mode == CORRUPT_MODE_B_METASTABLE_BITFLIP)
                            ? (sec_size / 4U)
                            : (sec_size / 2U);
    memset(&s_flash[addr], 0xFF, clean_half);
    uint32_t first_word = addr / CHIP_FLASH_WRITE_ALIGNMENT;
    uint32_t clean_words = (uint32_t)(clean_half / CHIP_FLASH_WRITE_ALIGNMENT);
    memset(&s_ecc_written[first_word], 0, clean_words);

    if (s_corrupt_mode == CORRUPT_MODE_C_HALF_ERASE_TAIL) {
      /* Mode C: Incomplete erase tail (old_byte | 0xAAU) — neither valid old
       * data nor clean 0xFF! Preserve non-0xFF observability on partially
       * erased cells so physical incomplete-erase matches ECC syndrome state. */
      for (size_t i = clean_half; i < sec_size; i++) {
        uint8_t old_b = s_flash[addr + i];
        if (old_b != 0xFFU) {
          uint8_t cand = (uint8_t)(old_b | 0xAAU);
          if (cand == 0xFFU) {
            cand = (uint8_t)(old_b | 0x55U);
          }
          s_flash[addr + i] = cand;
        }
      }
      /* Reconcile ECC word flags in tail if a word had only 0xFF padding */
      uint32_t total_words = (uint32_t)(sec_size / CHIP_FLASH_WRITE_ALIGNMENT);
      for (uint32_t w = clean_words; w < total_words; w++) {
        uint32_t w_addr = (first_word + w) * CHIP_FLASH_WRITE_ALIGNMENT;
        bool any_non_ff = false;
        for (uint32_t b = 0U; b < CHIP_FLASH_WRITE_ALIGNMENT; b++) {
          if (s_flash[w_addr + b] != 0xFFU) {
            any_non_ff = true;
            break;
          }
        }
        s_ecc_written[first_word + w] = any_non_ff ? 1U : 0U;
      }
    }

    longjmp(s_power_cut_jmp, 1);
  }

  memset(&s_flash[addr], 0xFF, sec_size);
  uint32_t first_word = addr / CHIP_FLASH_WRITE_ALIGNMENT;
  uint32_t word_count = (uint32_t)(sec_size / CHIP_FLASH_WRITE_ALIGNMENT);
  memset(&s_ecc_written[first_word], 0, word_count);
  return BOOT_OK;
}

static boot_status_t sim_flash_get_supply_mv(uint32_t *mv_out) {
  if (!mv_out) {
    return BOOT_ERR_INVALID_ARG;
  }
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
    .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
    .total_size = CHIP_FLASH_TOTAL_SIZE,
    .max_erase_cycles = 100000U,
    .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
    .erased_value = 0xFFU,
    .erase_time_us_max = 45000U,
    .write_time_us_page = 50U,
};

/* --- Clock / WDT / Confirm / Crypto / Entropy / Keystore HALs --- */
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
  if (!buf) {
    return BOOT_ERR_INVALID_ARG;
  }
  for (size_t i = 0U; i < len; i++) {
    s_rng_state ^= s_rng_state << 13;
    s_rng_state ^= s_rng_state >> 17;
    s_rng_state ^= s_rng_state << 5;
    buf[i] = (uint8_t)(s_rng_state & 0xFFU);
  }
  if (len >= 8U) {
    uint64_t nz = 0ULL;
    memcpy(&nz, buf, sizeof(nz));
    if (nz == 0ULL) {
      buf[0] = 0xA5U;
    }
  }
  return BOOT_OK;
}

static boot_status_t sim_read_pubkey(uint8_t *key, size_t key_len,
                                     uint8_t key_index) {
  if (!key || key_len < 32U || key_index != 0U) {
    return BOOT_ERR_NOT_FOUND;
  }
  memcpy(key, s_root_pk, 32U);
  return BOOT_OK;
}

static boot_status_t sim_read_uid(uint8_t *buf, size_t max_len,
                                  size_t *out_len) {
  static const uint8_t k_uid[16] = {
      0x5CU, 0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U,
      0x80U, 0x90U, 0xA0U, 0xB0U, 0xC0U, 0xD0U, 0xE0U, 0xF0U
  };
  if (!buf || !out_len || max_len < sizeof(k_uid)) {
    return BOOT_ERR_INVALID_ARG;
  }
  memcpy(buf, k_uid, sizeof(k_uid));
  *out_len = sizeof(k_uid);
  return BOOT_OK;
}

static boot_status_t sim_read_dslc(uint8_t *buf, size_t *len) {
  if (!buf || !len || *len < 1U) {
    return BOOT_ERR_INVALID_ARG;
  }
  buf[0] = s_dslc_state;
  *len = 1U;
  return BOOT_OK;
}

static boot_status_t sim_read_monotonic(uint32_t *ctr) {
  if (!ctr) {
    return BOOT_ERR_INVALID_ARG;
  }
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
      0x41U, 0x52U, 0x63U, 0x74U, 0x85U, 0x96U, 0xA7U, 0xB8U,
      0xC9U, 0xDAU, 0xEBU, 0xFCU, 0x0DU, 0x1EU, 0x2FU, 0x30U,
      0x01U, 0x12U, 0x23U, 0x34U, 0x45U, 0x56U, 0x67U, 0x78U,
      0x89U, 0x9AU, 0xABU, 0xBCU, 0xCDU, 0xDEU, 0xEFU, 0xF1U
  };
  if (!secret_out || !actual_len || max_len < sizeof(k_huk)) {
    return BOOT_ERR_INVALID_ARG;
  }
  memcpy(secret_out, k_huk, sizeof(k_huk));
  *actual_len = sizeof(k_huk);
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
    .read_device_secret = sim_read_device_secret,
};

/* --- Slot Capabilities (Mutable in Profile 1 for BFB2 vs XIP_REMAP) --- */
#if TOOB_INJ_PROFILE == 1
static boot_status_t sim_bfb2_flip(uint32_t target_bank) {
  if (target_bank > 1U) {
    return BOOT_ERR_INVALID_ARG;
  }
  s_bfb2_bank = target_bank;
  return BOOT_OK;
}

static boot_status_t sim_bfb2_get_active(uint32_t *out_slot) {
  if (!out_slot) {
    return BOOT_ERR_INVALID_ARG;
  }
  *out_slot = s_bfb2_bank;
  return BOOT_OK;
}

static boot_status_t sim_xip_remap_commit(uint32_t slot_phys_addr) {
  if ((slot_phys_addr % CHIP_MMU_PAGE_SIZE) != 0U) {
    return BOOT_ERR_FLASH_ALIGN;
  }
  if (slot_phys_addr == CHIP_APP_SLOT_ABS_ADDR) {
    s_xip_volatile_slot = 0U;
    return BOOT_OK;
  }
  if (slot_phys_addr == CHIP_STAGING_SLOT_ABS_ADDR) {
    s_xip_volatile_slot = 1U;
    return BOOT_OK;
  }
  return BOOT_ERR_FLASH_BOUNDS;
}

static boot_status_t sim_xip_get_active(uint32_t *out_slot) {
  if (!out_slot) {
    return BOOT_ERR_INVALID_ARG;
  }
  *out_slot = s_xip_volatile_slot;
  return BOOT_OK;
}

static slot_caps_t s_active_caps = TOOB_SLOT_CAPS_BANK_SWAP(
    2U, sim_bfb2_flip, sim_bfb2_get_active,
    .commit_persistence = SLOT_COMMIT_PERSISTENT);

static void configure_pointer_mode(bool use_bfb2_persistent) {
  if (use_bfb2_persistent) {
    slot_caps_t caps = TOOB_SLOT_CAPS_BANK_SWAP(
        2U, sim_bfb2_flip, sim_bfb2_get_active,
        .commit_persistence = SLOT_COMMIT_PERSISTENT);
    s_active_caps = caps;
  } else {
    slot_caps_t caps = TOOB_SLOT_CAPS_XIP_REMAP(
        2U, sim_xip_remap_commit, sim_xip_get_active,
        .commit_persistence = SLOT_COMMIT_VOLATILE);
    s_active_caps = caps;
  }
}
#else
static slot_caps_t s_active_caps = TOOB_SLOT_CAPS_FIXED(
    1U,
    .has_scratch = (CHIP_SCRATCH_SLOT_SIZE > 0U),
    .scratch_size = CHIP_SCRATCH_SLOT_SIZE);
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

/* ============================================================================
 * Simulated Reboot & Snapshot Helpers
 * ============================================================================ */
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
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH
  current_swap_state = SWAP_STATE_NORMAL;
#endif
  boot_platform_mark_down();

  memset(crypto_arena, 0, sizeof(crypto_arena));
  s_reset_reason = reason;
  s_rng_state = 0x9E3779B9U ^ ((uint32_t)reason * 0x85EBCA6BU);

  if (reason == RESET_REASON_POWER_ON || reason == RESET_REASON_BROWNOUT) {
    /* Volatile SRAM, .noinit, RTC confirm RAM, and volatile XIP MMU clear on power loss */
    memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
    memset(&toob_diag_state, 0, sizeof(toob_diag_state));
    s_rtc_confirm_nonce = 0ULL;
    s_xip_volatile_slot = 0U;
  } else {
    /* Warm/WDT reset clears volatile XIP MMU register unless reasserted by Stage 1 */
    s_xip_volatile_slot = 0U;
  }
}

static void save_hw_snapshot(void) {
  memcpy(s_snap.flash, s_flash, sizeof(s_flash));
  memcpy(s_snap.ecc_written, s_ecc_written, sizeof(s_ecc_written));
  s_snap.otp_svn = s_otp_svn;
  s_snap.bfb2_bank = s_bfb2_bank;
  s_snap.xip_volatile_slot = s_xip_volatile_slot;
  s_snap.rtc_confirm_nonce = s_rtc_confirm_nonce;
  s_snap.reset_reason = s_reset_reason;
}

static void restore_hw_snapshot(void) {
  memcpy(s_flash, s_snap.flash, sizeof(s_flash));
  memcpy(s_ecc_written, s_snap.ecc_written, sizeof(s_ecc_written));
  s_otp_svn = s_snap.otp_svn;
  s_bfb2_bank = s_snap.bfb2_bank;
  s_reset_reason = s_snap.reset_reason;
  sim_reset_sram_globals(s_snap.reset_reason);
  s_xip_volatile_slot = s_snap.xip_volatile_slot;
  s_rtc_confirm_nonce = s_snap.rtc_confirm_nonce;
}

/* Isolated setjmp wrapper so zero locals are clobbered under -O2 -Werror */
static int execute_boot_with_cut_trap(boot_target_config_t *target_out,
                                      boot_status_t *status_out) {
  if (setjmp(s_power_cut_jmp) != 0) {
    return 1;
  }
  *status_out = boot_main(&s_platform, target_out, k_seal_key);
  return 0;
}

/* ============================================================================
 * Deterministic Payload, Heatshrink, TDS1 & Signed TBM1 Builders
 * ============================================================================ */
typedef struct {
  uint8_t *bytes;
  size_t len;
  uint32_t svn;
  uint8_t sha256[32];
  uint8_t ed25519_sig[64];
} signed_image_ref_t;

static void sha256_buf(const uint8_t *data, size_t len, uint8_t out[32]) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, out);
}

static void raw_erase_and_program_region(uint32_t base, uint32_t region_size,
                                         const uint8_t *data, size_t data_len) {
  assert(data_len <= region_size);
  assert((data_len % CHIP_FLASH_WRITE_ALIGNMENT) == 0U);
  uint32_t cur = base;
  while (cur < base + region_size) {
    size_t sec_sz = 0U;
    assert(sim_flash_get_sector_size(cur, &sec_sz) == BOOT_OK);
    assert(sim_flash_erase_sector(cur) == BOOT_OK);
    cur += (uint32_t)sec_sz;
  }
  /* Skip all-0xFF aligned ECC words just like a real flash programmer / OTA agent */
  const uint32_t align = CHIP_FLASH_WRITE_ALIGNMENT;
  size_t i = 0U;
  while (i < data_len) {
    bool all_ff = true;
    for (uint32_t b = 0U; b < align; b++) {
      if (data[i + b] != 0xFFU) {
        all_ff = false;
        break;
      }
    }
    if (all_ff) {
      i += align;
      continue;
    }
    size_t run_start = i;
    i += align;
    while (i < data_len) {
      bool next_ff = true;
      for (uint32_t b = 0U; b < align; b++) {
        if (data[i + b] != 0xFFU) {
          next_ff = false;
          break;
        }
      }
      if (next_ff) {
        break;
      }
      i += align;
    }
    assert(sim_flash_write(base + (uint32_t)run_start, data + run_start,
                           i - run_start) == BOOT_OK);
  }
}

static void build_test_image(signed_image_ref_t *out, size_t len, uint32_t svn,
                             uint8_t variant_tag) {
  assert((len % 4096U) == 0U);
  assert((len % CHIP_FLASH_WRITE_ALIGNMENT) == 0U);
  uint8_t *buf = (uint8_t *)malloc(len);
  assert(buf != NULL);

  for (size_t i = 0U; i < len; i++) {
    /* Shared deterministic code base in [1024..2560), .bss zeros in [2560..3072),
     * embedded 0xFF erased-flash gap in [3072..3328) (tests ECC skip_erased!),
     * and variant-specific code/rodata elsewhere. */
    size_t sec_mod = i % 4096U;
    if (i >= 1024U && i < 2560U) {
      buf[i] = (uint8_t)((i * 37U + 0x5AU) & 0xFFU);
    } else if (sec_mod >= 2560U && sec_mod < 3072U) {
      buf[i] = 0x00U;
    } else if (sec_mod >= 3072U && sec_mod < 3328U) {
      buf[i] = 0xFFU;
    } else {
      buf[i] = (uint8_t)(variant_tag ^ (uint8_t)((i * 13U + (i >> 8U) * 7U) & 0xFFU));
    }
  }

  toob_image_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TOOB_MAGIC_HEADER;
  hdr.image_size = (uint32_t)len;
  hdr.entry_point = 0x100U;
  memcpy(buf, &hdr, sizeof(hdr));

  assert(len >= sizeof(toob_image_header_t) + sizeof(toob_img_sig_trailer_t));
  size_t signed_len = len - sizeof(toob_img_sig_trailer_t);
  uint8_t tsig_digest[32];
  sha256_buf(buf, signed_len, tsig_digest);

  toob_img_sig_trailer_t trailer;
  memset(&trailer, 0, sizeof(trailer));
  trailer.magic = TOOB_IMG_SIG_MAGIC;
  trailer.key_index = 0U;
  trailer.flags = TOOB_IMG_SIG_FLAG_SHA256;
  trailer.reserved = 0U;
  crypto_ed25519_sign(trailer.sig_ed25519, s_root_sk, tsig_digest,
                      sizeof(tsig_digest));
  memcpy(buf + signed_len, &trailer, sizeof(trailer));

  out->bytes = buf;
  out->len = len;
  out->svn = svn;
  sha256_buf(buf, len, out->sha256);
  crypto_ed25519_sign(out->ed25519_sig, s_root_sk, out->sha256,
                      sizeof(out->sha256));
}

static size_t heatshrink_compress_buf(const uint8_t *in, size_t in_len,
                                      uint8_t *out, size_t out_cap) {
  heatshrink_encoder hse;
  heatshrink_encoder_reset(&hse);
  size_t in_pos = 0U;
  size_t out_pos = 0U;

  while (in_pos < in_len) {
    size_t sunk = 0U;
    HSE_sink_res sr =
        heatshrink_encoder_sink(&hse, (uint8_t *)(uintptr_t)(in + in_pos),
                                in_len - in_pos, &sunk);
    assert(sr == HSER_SINK_OK && sunk > 0U);
    in_pos += sunk;

    HSE_poll_res pr;
    do {
      size_t polled = 0U;
      assert(out_pos < out_cap);
      pr = heatshrink_encoder_poll(&hse, out + out_pos, out_cap - out_pos,
                                   &polled);
      assert(pr >= 0);
      out_pos += polled;
    } while (pr == HSER_POLL_MORE);
  }

  HSE_finish_res fr;
  do {
    fr = heatshrink_encoder_finish(&hse);
    assert(fr >= 0);
    if (fr == HSER_FINISH_MORE) {
      HSE_poll_res pr;
      do {
        size_t polled = 0U;
        assert(out_pos < out_cap);
        pr = heatshrink_encoder_poll(&hse, out + out_pos, out_cap - out_pos,
                                     &polled);
        assert(pr >= 0);
        out_pos += polled;
      } while (pr == HSER_POLL_MORE);
    }
  } while (fr == HSER_FINISH_MORE);

  return out_pos;
}

/**
 * Encodes a real TDS1 stream (COPY_BASE + BZERO + Heatshrink INSERT_LIT + EOF)
 * transforming `base_img` -> `target_img`.
 */
static size_t build_tds1_delta(const signed_image_ref_t *base_img,
                               const signed_image_ref_t *target_img,
                               uint8_t *out_buf, size_t out_cap) {
  toob_tds_instr_t instrs[64];
  uint8_t lit_pool[65536];
  uint32_t instr_count = 0U;
  size_t lit_off = 0U;
  size_t pos = 0U;

  while (pos < target_img->len) {
    assert(instr_count + 1U < 64U);
    /* 1. Check for >= 256-byte BZERO run */
    size_t zrun = 0U;
    while (pos + zrun < target_img->len && target_img->bytes[pos + zrun] == 0x00U) {
      zrun++;
    }
    if (zrun >= 256U) {
      memset(&instrs[instr_count], 0, sizeof(toob_tds_instr_t));
      instrs[instr_count].opcode = TOOB_TDS_OP_BZERO;
      instrs[instr_count].length = (uint32_t)zrun;
      instrs[instr_count].offset = 0U;
      instrs[instr_count].crc32 = compute_boot_crc32(
          (const uint8_t *)&instrs[instr_count],
          offsetof(toob_tds_instr_t, crc32));
      instr_count++;
      pos += zrun;
      continue;
    }

    /* 2. Check for >= 256-byte COPY_BASE match at same offset */
    size_t crun = 0U;
    while (pos + crun < target_img->len && pos + crun < base_img->len &&
           target_img->bytes[pos + crun] == base_img->bytes[pos + crun]) {
      crun++;
    }
    if (crun >= 256U) {
      memset(&instrs[instr_count], 0, sizeof(toob_tds_instr_t));
      instrs[instr_count].opcode = TOOB_TDS_OP_COPY_BASE;
      instrs[instr_count].length = (uint32_t)crun;
      instrs[instr_count].offset = (uint32_t)pos;
      instrs[instr_count].crc32 = compute_boot_crc32(
          (const uint8_t *)&instrs[instr_count],
          offsetof(toob_tds_instr_t, crc32));
      instr_count++;
      pos += crun;
      continue;
    }

    /* 3. Emit Heatshrink-compressed INSERT_LIT up to next match/zero block */
    size_t lit_end = pos + 1U;
    while (lit_end < target_img->len && (lit_end - pos) < 4096U) {
      size_t zcheck = 0U;
      while (lit_end + zcheck < target_img->len && zcheck < 256U &&
             target_img->bytes[lit_end + zcheck] == 0x00U) {
        zcheck++;
      }
      if (zcheck >= 256U) {
        break;
      }
      size_t ccheck = 0U;
      while (lit_end + ccheck < target_img->len &&
             lit_end + ccheck < base_img->len && ccheck < 256U &&
             target_img->bytes[lit_end + ccheck] ==
                 base_img->bytes[lit_end + ccheck]) {
        ccheck++;
      }
      if (ccheck >= 256U) {
        break;
      }
      lit_end++;
    }

    size_t raw_len = lit_end - pos;
    size_t comp_len = heatshrink_compress_buf(
        target_img->bytes + pos, raw_len, lit_pool + lit_off,
        sizeof(lit_pool) - lit_off);

    memset(&instrs[instr_count], 0, sizeof(toob_tds_instr_t));
    instrs[instr_count].opcode = TOOB_TDS_OP_INSERT_LIT;
    instrs[instr_count].length = (uint32_t)comp_len;
    instrs[instr_count].offset = (uint32_t)raw_len;
    instrs[instr_count].crc32 = compute_boot_crc32(
        (const uint8_t *)&instrs[instr_count],
        offsetof(toob_tds_instr_t, crc32));
    instr_count++;
    lit_off += comp_len;
    pos = lit_end;
  }

  /* Append EOF instruction */
  memset(&instrs[instr_count], 0, sizeof(toob_tds_instr_t));
  instrs[instr_count].opcode = TOOB_TDS_OP_EOF;
  instrs[instr_count].crc32 = compute_boot_crc32(
      (const uint8_t *)&instrs[instr_count],
      offsetof(toob_tds_instr_t, crc32));
  instr_count++;

  uint32_t lit_block_off =
      (uint32_t)(sizeof(toob_tds_header_t) + instr_count * sizeof(toob_tds_instr_t));
  size_t total_len = (size_t)lit_block_off + lit_off;
  assert(total_len <= out_cap);

  toob_tds_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TOOB_TDS_MAGIC;
  hdr.expected_target_size = (uint32_t)target_img->len;
  memcpy(hdr.base_fingerprint, base_img->sha256, 8U);
  hdr.base_size = (uint32_t)base_img->len;
  hdr.literal_block_offset = lit_block_off;
  hdr.instr_count = instr_count;
  hdr.header_crc32 = compute_boot_crc32(
      (const uint8_t *)&hdr, offsetof(toob_tds_header_t, header_crc32));

  memcpy(out_buf, &hdr, sizeof(hdr));
  memcpy(out_buf + sizeof(hdr), instrs, instr_count * sizeof(toob_tds_instr_t));
  memcpy(out_buf + lit_block_off, lit_pool, lit_off);
  return total_len;
}

static uint32_t align_up_u32(uint32_t v, uint32_t a) {
  return (v + (a - 1U)) & ~(a - 1U);
}

/**
 * Stages a signed Trailer-TBM1 bundle into `[slot_base .. slot_base + slot_size)`
 * through the ECC-checked flash HAL and returns the absolute TBM1 manifest address.
 */
static uint32_t stage_trailer_tbm1_bundle(
    uint32_t slot_base, uint32_t slot_size, const signed_image_ref_t *base_v1,
    const signed_image_ref_t *target_v2, uint8_t comp_alg, uint8_t delta_alg,
    bool include_reverse_delta) {
  size_t max_bundle = (size_t)slot_size;
  uint8_t *bundle = (uint8_t *)malloc(max_bundle);
  assert(bundle != NULL);
  memset(bundle, 0xFF, max_bundle);

  uint32_t data_off = 0U;
  uint32_t stored_size = 0U;

  if (comp_alg == TBM1_COMP_NONE && delta_alg == TBM1_DELTA_NONE) {
    data_off = 0U;
    stored_size = (uint32_t)target_v2->len;
    memcpy(bundle + data_off, target_v2->bytes, target_v2->len);
  } else if (comp_alg == TBM1_COMP_HEATSHRINK && delta_alg == TBM1_DELTA_NONE) {
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    data_off = align_up_u32((uint32_t)target_v2->len, 4096U);
#else
    data_off = 0U;
#endif
    stored_size = (uint32_t)heatshrink_compress_buf(
        target_v2->bytes, target_v2->len, bundle + data_off,
        max_bundle - data_off - 4096U);
  } else if (delta_alg == TBM1_DELTA_TDS1) {
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    /* Zero-Copy POINTER streams into [0..installed_size), so place delta above it */
    data_off = align_up_u32((uint32_t)target_v2->len, 4096U);
#else
    data_off = 0U;
#endif
    stored_size = (uint32_t)build_tds1_delta(
        base_v1, target_v2, bundle + data_off, max_bundle - data_off - 4096U);
  } else {
    abort();
  }

  uint32_t cursor = align_up_u32(data_off + stored_size, CHIP_FLASH_WRITE_ALIGNMENT);

  uint32_t rdelta_off = 0U;
  uint32_t rdelta_stored = 0U;
  if (include_reverse_delta) {
    rdelta_off = cursor;
    rdelta_stored = (uint32_t)build_tds1_delta(
        target_v2, base_v1, bundle + rdelta_off, max_bundle - rdelta_off - 2048U);
    cursor = align_up_u32(rdelta_off + rdelta_stored, CHIP_FLASH_WRITE_ALIGNMENT);
  }

  /* Place TBM1 manifest above both cursor and installed_size (for 2-way swaps / zero-copy) */
  uint32_t min_tbm1 = (uint32_t)target_v2->len;
  if (base_v1 != NULL && (uint32_t)base_v1->len > min_tbm1) {
    min_tbm1 = (uint32_t)base_v1->len;
  }
  if (cursor < min_tbm1) {
    cursor = min_tbm1;
  }
  uint32_t tbm1_off = align_up_u32(cursor, 4096U);

  const uint32_t chunk_size = 4096U;
  const uint32_t num_chunks = (uint32_t)(target_v2->len / chunk_size);
  const uint32_t hashes_off = TBM1_FIXED_LEN;
  const uint32_t hashes_len = num_chunks * 32U;
  const uint32_t rdesc_off = hashes_off + hashes_len;
  const uint32_t rdesc_len =
      include_reverse_delta ? (uint32_t)sizeof(tbm1_rdelta_desc_t) : 0U;
  const uint32_t total_tbm1_len =
      TBM1_FIXED_LEN + hashes_len + rdesc_len + TBM1_SIG_LEN;

  assert(tbm1_off + total_tbm1_len + 64U <= max_bundle);

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
  hdr->hw_rev_max = 10U;
  hdr->key_index = 0U;
  hdr->image_count = 1U;
  hdr->boot_retry_limit = BOOT_CONFIG_MAX_RETRIES;
  hdr->min_reader_major = TBM1_VERSION_MAJOR;
  hdr->svn = target_v2->svn;
  hdr->build_number = 100U + target_v2->svn;
  hdr->fw_ver_major = 2U;
  hdr->fw_ver_minor = (uint16_t)target_v2->svn;

  hdr->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
  hdr->regions[0].off = hashes_off;
  hdr->regions[0].len = hashes_len;

  if (include_reverse_delta) {
    hdr->regions[1].region_id = TBM1_REGION_REVERSE_DELTA;
    hdr->regions[1].off = rdesc_off;
    hdr->regions[1].len = rdesc_len;
  }

  hdr->images[0].image_type = 0U;
  hdr->images[0].target_slot = TBM1_SLOT_APP;
  hdr->images[0].compression_alg = comp_alg;
  hdr->images[0].delta_alg = delta_alg;
  hdr->images[0].data_off = data_off;
  hdr->images[0].stored_size = stored_size;
  hdr->images[0].installed_size = (uint32_t)target_v2->len;
  hdr->images[0].chunk_size = chunk_size;
  hdr->images[0].num_chunks = num_chunks;
  hdr->images[0].ver_major = 2U;
  hdr->images[0].ver_minor = (uint16_t)target_v2->svn;
  if (delta_alg == TBM1_DELTA_TDS1 && base_v1 != NULL) {
    hdr->images[0].base_svn = base_v1->svn;
    memcpy(hdr->images[0].base_fingerprint, base_v1->sha256, 8U);
  }

  hdr->fixed_crc32 = compute_boot_crc32(tbm1_buf, TBM1_CRC_LEN);

  for (uint32_t c = 0U; c < num_chunks; c++) {
    sha256_buf(target_v2->bytes + (size_t)c * chunk_size, chunk_size,
               tbm1_buf + hashes_off + c * 32U);
  }

  if (include_reverse_delta) {
    tbm1_rdelta_desc_t rdesc;
    memset(&rdesc, 0, sizeof(rdesc));
    rdesc.target_slot = TBM1_SLOT_APP;
    rdesc.delta_alg = TBM1_DELTA_TDS1;
    rdesc.data_off = rdelta_off;
    rdesc.stored_size = rdelta_stored;
    rdesc.restored_size = (uint32_t)base_v1->len;
    memcpy(rdesc.restored_sha256, base_v1->sha256, 32U);
    memcpy(tbm1_buf + rdesc_off, &rdesc, sizeof(rdesc));
  }

  crypto_ed25519_sign(tbm1_buf + total_tbm1_len - TBM1_SIG_LEN, s_root_sk,
                      tbm1_buf, total_tbm1_len - TBM1_SIG_LEN);

  /* Also append 16-byte Trailer Locator aligned to CHIP_FLASH_WRITE_ALIGNMENT */
  uint32_t total_bundle_end = align_up_u32(
      tbm1_off + total_tbm1_len + (uint32_t)sizeof(toob_tbm1_trailer_locator_t),
      CHIP_FLASH_WRITE_ALIGNMENT);
  assert(total_bundle_end <= max_bundle);

  toob_tbm1_trailer_locator_t loc;
  memset(&loc, 0, sizeof(loc));
  loc.magic = TOOB_TBM1_TRAILER_MAGIC;
  loc.tbm1_off = tbm1_off;
  loc.tbm1_len = total_tbm1_len;
  loc.crc32 = compute_boot_crc32(
      (const uint8_t *)&loc, offsetof(toob_tbm1_trailer_locator_t, crc32));
  memcpy(bundle + total_bundle_end - sizeof(loc), &loc, sizeof(loc));

  raw_erase_and_program_region(slot_base, slot_size, bundle, total_bundle_end);
  free(bundle);
  return slot_base + tbm1_off;
}

static void write_mailbox_request(uint16_t req_flags, uint32_t seq,
                                  uint32_t tbm1_addr, uint64_t nonce) {
  uint32_t slot_idx = seq % TOOB_MAILBOX_SLOTS;
  uint32_t slot_addr = CHIP_MAILBOX_ABS_ADDR + slot_idx * CHIP_MAILBOX_SLOT_SIZE;

  toob_mailbox_t mbx;
  memset(&mbx, 0, sizeof(mbx));
  mbx.magic = TOOB_MAILBOX_MAGIC;
  mbx.version = TOOB_MAILBOX_VERSION;
  mbx.request = req_flags;
  mbx.seq = seq;
  mbx.tbm1_addr = tbm1_addr;
  mbx.nonce = nonce;
  mbx.crc32 = compute_boot_crc32((const uint8_t *)&mbx, TOOB_MAILBOX_CRC_LEN);

  _Static_assert(sizeof(toob_mailbox_t) == 32U, "Mailbox wire size must be 32B");
  assert(sim_flash_erase_sector(slot_addr) == BOOT_OK);
  assert(sim_flash_write(slot_addr, &mbx, sizeof(mbx)) == BOOT_OK);
}

static void init_fresh_device(const signed_image_ref_t *v1,
                              const signed_image_ref_t *recovery) {
  memset(s_flash, 0xFF, sizeof(s_flash));
  memset(s_ecc_written, 0, sizeof(s_ecc_written));
  s_record_ops = false;
  s_cut_at_op = 0U;
  s_flash_op_counter = 0U;
  s_otp_svn = 0U;
  s_dslc_state = 0x00U;
  s_bfb2_bank = 0U;
  s_xip_volatile_slot = 0U;
  s_rtc_confirm_nonce = 0ULL;
  sim_reset_sram_globals(RESET_REASON_POWER_ON);

  /* Initialize blank WAL while factory unprovisioned (DSLC == 0x00, epoch == 0, CRIT-69),
   * then step OTP epoch/app_svn up to v1->svn and lock device as deployed (DSLC == 0x01). */
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  wal_tmr_payload_t tmr;
  while (s_otp_svn < v1->svn) {
    s_otp_svn++;
    assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
    tmr.app_svn = v1->svn;
    assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  }
  s_dslc_state = 0x01U;
  sim_reset_sram_globals(RESET_REASON_POWER_ON);

  /* Provision 3-way KDM quorum via boot_rstore_write (tests 8B/32B ECC alignment!) */
  size_t kdm_sec0 = 0U, kdm_sec1 = 0U, kdm_sec2 = 0U;
  assert(sim_flash_get_sector_size(CHIP_KDM_QUORUM_ABS_ADDR, &kdm_sec0) == BOOT_OK);
  uint32_t kdm_addr1 = CHIP_KDM_QUORUM_ABS_ADDR + (uint32_t)kdm_sec0;
  assert(sim_flash_get_sector_size(kdm_addr1, &kdm_sec1) == BOOT_OK);
  uint32_t kdm_addr2 = kdm_addr1 + (uint32_t)kdm_sec1;
  assert(sim_flash_get_sector_size(kdm_addr2, &kdm_sec2) == BOOT_OK);

  const uint32_t kdm_addrs[3] = {CHIP_KDM_QUORUM_ABS_ADDR, kdm_addr1, kdm_addr2};
  const size_t kdm_sizes[3] = {kdm_sec0, kdm_sec1, kdm_sec2};
  const boot_rstore_desc_t kdm_desc = {
      .slot_addrs = kdm_addrs,
      .slot_sizes = kdm_sizes,
      .slot_count = 3U,
      .record_size = sizeof(toob_kdm_t),
      .magic = 0x4B444D51U,
  };

  toob_kdm_t kdm;
  memset(&kdm, 0, sizeof(kdm));
  kdm.sequence_number = 1U;
  memcpy(kdm.new_cloud_pubkey, s_cloud_pk, sizeof(s_cloud_pk));
  crypto_ed25519_sign(kdm.signature_ed25519, s_root_sk, (const uint8_t *)&kdm,
                      offsetof(toob_kdm_t, signature_ed25519));
  assert(boot_rstore_write(&s_platform, &kdm_desc, &kdm) == BOOT_OK);

  /* Program factory v1 in App Slot 0 and immutable Recovery OS */
  raw_erase_and_program_region(CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE,
                               v1->bytes, v1->len);
  raw_erase_and_program_region(CHIP_RECOVERY_OS_ABS_ADDR, CHIP_RECOVERY_OS_SIZE,
                               recovery->bytes, recovery->len);

  /* Run baseline cold boot + verify initial TMR app_svn = v1->svn */
  boot_target_config_t target;
  assert(boot_main(&s_platform, &target, k_seal_key) == BOOT_OK);
  assert(target.boot_recovery_os == false);
  assert(target.proof.image_addr == CHIP_APP_SLOT_ABS_ADDR);

  sim_reset_sram_globals(RESET_REASON_POWER_ON);
  assert(boot_journal_init(&s_platform) == BOOT_OK);
  assert(boot_journal_get_tmr(&s_platform, &tmr) == BOOT_OK);
  tmr.app_svn = v1->svn;
  assert(boot_journal_update_tmr(&s_platform, &tmr) == BOOT_OK);
  sim_reset_sram_globals(RESET_REASON_POWER_ON);
}

/* ============================================================================
 * Theorem 1, Theorem 2 & Anti-Rollback Post-Recovery Verifier
 * ============================================================================ */
typedef enum {
  EXPECT_CONVERGE_V2_OR_V1 = 0,
  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY = 1
} convergence_goal_t;

static const char *s_cur_diag_suite = "";
static uint32_t s_cur_diag_k = 0U;
static int s_cur_diag_m = -1;

static void assert_recovered_handoff_valid(const boot_target_config_t *target,
                                           const signed_image_ref_t *v1,
                                           const signed_image_ref_t *v2,
                                           const signed_image_ref_t *recovery,
                                           convergence_goal_t goal) {
  /* 1. Seal proof + .noinit handoff CRC-32 must be cryptographically intact */
  assert(boot_proof_verify(&target->proof, k_seal_key) == BOOT_OK);
  uint32_t expected_handoff_crc = compute_boot_crc32(
      (const uint8_t *)&toob_handoff_state,
      offsetof(toob_handoff_t, crc32_trailer));
  assert(toob_handoff_state.crc32_trailer == expected_handoff_crc);

  /* 2. Theorem 2: Booted image MUST be byte-for-byte + SHA-256 + Ed25519
   *    identical to an authentic signed image (NEVER half-written / Frankenstein!) */
  uint32_t boot_addr = target->proof.image_addr;
  uint32_t boot_size = target->proof.image_size;
  assert(boot_size > 0U && boot_addr + boot_size <= CHIP_FLASH_TOTAL_SIZE);

  uint8_t actual_sha256[32];
  sha256_buf(&s_flash[boot_addr], boot_size, actual_sha256);

  bool matches_v2 =
      (!target->boot_recovery_os) && (boot_size == v2->len) &&
      (memcmp(actual_sha256, v2->sha256, 32U) == 0) &&
      (crypto_ed25519_check(v2->ed25519_sig, s_root_pk, actual_sha256, 32U) == 0) &&
      (memcmp(&s_flash[boot_addr], v2->bytes, v2->len) == 0);

  bool matches_v1 =
      (!target->boot_recovery_os) && (boot_size == v1->len) &&
      (memcmp(actual_sha256, v1->sha256, 32U) == 0) &&
      (crypto_ed25519_check(v1->ed25519_sig, s_root_pk, actual_sha256, 32U) == 0) &&
      (memcmp(&s_flash[boot_addr], v1->bytes, v1->len) == 0);

  bool matches_recovery =
      target->boot_recovery_os && (boot_addr == CHIP_RECOVERY_OS_ABS_ADDR) &&
      (boot_size == recovery->len) &&
      (memcmp(actual_sha256, recovery->sha256, 32U) == 0) &&
      (crypto_ed25519_check(recovery->ed25519_sig, s_root_pk, actual_sha256,
                            32U) == 0) &&
      (memcmp(&s_flash[boot_addr], recovery->bytes, recovery->len) == 0);

  if (goal == EXPECT_CONVERGE_V2_OR_V1) {
    if (!matches_v2 && !matches_v1) {
      fprintf(stderr,
              "THEOREM 2 VIOLATION (OTA): booted addr=0x%08X size=%u rec=%d "
              "matches neither signed v2 nor fallback v1!\n",
              (unsigned)boot_addr, (unsigned)boot_size,
              target->boot_recovery_os ? 1 : 0);
      abort();
    }
    uint32_t booted_svn = matches_v2 ? v2->svn : v1->svn;
    assert(booted_svn >= s_otp_svn);
    assert(toob_diag_state.current_svn >= s_otp_svn);
  } else {
    if (!matches_v1 && !matches_recovery &&
        !(matches_v2 && target->is_tentative_boot)) {
      fprintf(stderr,
              "THEOREM 2 VIOLATION (ROLLBACK) [%s k=%u m=%d]: booted addr=0x%08X size=%u rec=%d "
              "tent=%d matches neither signed v1, Recovery OS, nor intact tentative v2!\n",
              s_cur_diag_suite, (unsigned)s_cur_diag_k, s_cur_diag_m,
              (unsigned)boot_addr, (unsigned)boot_size,
              target->boot_recovery_os ? 1 : 0,
              target->is_tentative_boot ? 1 : 0);
      abort();
    }
    if (matches_v1) {
      assert(v1->svn >= s_otp_svn);
    } else if (matches_v2) {
      assert(v2->svn >= s_otp_svn);
    }
  }

#if TOOB_INJ_PROFILE == 1
  /* Verify volatile XIP MMU / persistent BFB2 hardware matches booted slot */
  if (!target->boot_recovery_os) {
    if (s_active_caps.exec_model == SLOT_EXEC_XIP_REMAP) {
      assert(s_xip_volatile_slot == target->active_slot);
    } else if (s_active_caps.exec_model == SLOT_EXEC_BANK_SWAP) {
      assert(s_bfb2_bank == target->active_slot);
    }
  }
#endif
}

/* ============================================================================
 * Step 1..N Single Power-Cut & Nested Double Power-Cut Sweep Engines
 * ============================================================================ */
static bool should_test_step(uint32_t k_1based, uint32_t total_ops) {
  if (total_ops <= 500U) {
    return true; /* 100% exhaustive for all <= 500 flash-op scenarios! */
  }
  const recorded_op_t *op = &s_recorded[k_1based - 1U];
  if (op->is_critical || k_1based <= 24U || k_1based + 24U > total_ops) {
    return true;
  }
  uint32_t stride = (total_ops + 249U) / 250U;
  return ((k_1based % stride) == 0U);
}

static void run_exhaustive_single_cut_sweep(const char *suite_label,
                                            const signed_image_ref_t *v1,
                                            const signed_image_ref_t *v2,
                                            const signed_image_ref_t *recovery,
                                            convergence_goal_t goal) {
  s_cur_diag_suite = suite_label;
  s_cur_diag_k = 0U;
  s_cur_diag_m = -1;
  save_hw_snapshot();

  /* 1. Reference pass: record total flash operations N */
  s_record_ops = true;
  s_recorded_count = 0U;
  s_flash_op_counter = 0U;
  s_cut_at_op = 0U;

  boot_target_config_t ref_target;
  boot_status_t ref_st = boot_main(&s_platform, &ref_target, k_seal_key);
  assert(ref_st == BOOT_OK);
  assert_recovered_handoff_valid(&ref_target, v1, v2, recovery, goal);
  if (goal == EXPECT_CONVERGE_V2_OR_V1) {
    assert(memcmp(&s_flash[ref_target.proof.image_addr], v2->bytes, v2->len) == 0);
  } else {
    assert(memcmp(&s_flash[ref_target.proof.image_addr], v1->bytes, v1->len) == 0);
  }

  uint32_t total_ops = s_flash_op_counter;
  s_record_ops = false;
  assert(total_ops > 0U && total_ops <= MAX_RECORDED_OPS);

  uint32_t cuts_in_suite = 0U;

  /* 2. Sweep every step k in {1..N} across all 3 physical NOR corruption modes */
  for (uint32_t k = 1U; k <= total_ops; k++) {
    if (!should_test_step(k, total_ops)) {
      continue;
    }
    for (int m = 0; m < (int)CORRUPT_MODE_COUNT; m++) {
      s_cur_diag_suite = suite_label;
      s_cur_diag_k = k;
      s_cur_diag_m = m;
      restore_hw_snapshot();
      s_flash_op_counter = 0U;
      s_cut_at_op = k;
      s_corrupt_mode = (corrupt_mode_t)m;

      boot_target_config_t cut_target;
      boot_status_t cut_st = BOOT_ERR_VERIFY;
      int did_cut = execute_boot_with_cut_trap(&cut_target, &cut_st);
      assert(did_cut == 1);
      s_total_power_cuts_executed++;
      cuts_in_suite++;

      /* Immediate POWER_ON reboot: clear volatile SRAM, preserve NOR + ECC + OTP */
      s_cut_at_op = 0U;
      sim_reset_sram_globals(RESET_REASON_POWER_ON);

      /* Theorem 1: Must converge in <= BOOT_CONFIG_MAX_RETRIES + 1 boots without bootloop */
      uint32_t reboots = 0U;
      boot_target_config_t rec_target;
      boot_status_t rec_st = BOOT_ERR_STATE;
      while (reboots <= BOOT_CONFIG_MAX_RETRIES) {
        reboots++;
        rec_st = boot_main(&s_platform, &rec_target, k_seal_key);
        if (rec_st == BOOT_OK) {
          break;
        }
        sim_reset_sram_globals(RESET_REASON_POWER_ON);
      }
      assert(rec_st == BOOT_OK);
      assert(reboots <= BOOT_CONFIG_MAX_RETRIES + 1U);
      assert_recovered_handoff_valid(&rec_target, v1, v2, recovery, goal);

      /* If power cut hit at k=1 BEFORE WAL_INTENT_TXN_ROLLBACK_PENDING persisted,
       * POWER_ON wiped the volatile WDT reset latch and handed off intact tentative
       * v2 with WDT armed. Prove that when buggy v2 trips WDT again, it converges to v1! */
      if (goal == EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY &&
          !rec_target.boot_recovery_os && rec_target.is_tentative_boot) {
        reboots++;
        assert(reboots <= BOOT_CONFIG_MAX_RETRIES + 1U);
        sim_reset_sram_globals(RESET_REASON_WATCHDOG);
        rec_st = boot_main(&s_platform, &rec_target, k_seal_key);
        assert(rec_st == BOOT_OK);
        assert(!rec_target.is_tentative_boot);
        assert_recovered_handoff_valid(&rec_target, v1, v2, recovery, goal);
      }
    }
  }

  restore_hw_snapshot();
  printf("  [PASS] %-52s | N=%3u ops | cuts=%4u | align=%2uB ECC=0-violations\n",
         suite_label, (unsigned)total_ops, (unsigned)cuts_in_suite,
         (unsigned)CHIP_FLASH_WRITE_ALIGNMENT);
  fflush(stdout);
}

static void run_nested_double_cut_sweep(const char *suite_label,
                                        const signed_image_ref_t *v1,
                                        const signed_image_ref_t *v2,
                                        const signed_image_ref_t *recovery,
                                        convergence_goal_t goal) {
  s_cur_diag_suite = suite_label;
  s_cur_diag_k = 0U;
  s_cur_diag_m = -1;
  save_hw_snapshot();

  /* Measure baseline N1 */
  s_record_ops = false;
  s_flash_op_counter = 0U;
  s_cut_at_op = 0U;
  boot_target_config_t ref_target;
  assert(boot_main(&s_platform, &ref_target, k_seal_key) == BOOT_OK);
  uint32_t n1 = s_flash_op_counter;
  assert(n1 >= 2U);

  /* Select 8 representative k1 cut points spanning early, mid-sector, swap, and WAL flush */
  uint32_t k1_points[8] = {
      1U,
      (n1 / 6U) + 1U,
      (n1 / 3U) + 1U,
      (n1 / 2U) + 1U,
      ((2U * n1) / 3U) + 1U,
      ((5U * n1) / 6U) + 1U,
      (n1 > 2U) ? (n1 - 1U) : n1,
      n1
  };

  uint32_t double_pairs = 0U;

  for (size_t idx = 0U; idx < 8U; idx++) {
    uint32_t k1 = k1_points[idx];
    if (k1 > n1) {
      k1 = n1;
    }

    /* Probe recovery length N2 after cutting at k1 */
    restore_hw_snapshot();
    s_flash_op_counter = 0U;
    s_cut_at_op = k1;
    s_corrupt_mode = (corrupt_mode_t)(idx % CORRUPT_MODE_COUNT);
    boot_target_config_t dummy_t;
    boot_status_t dummy_st = BOOT_ERR_VERIFY;
    assert(execute_boot_with_cut_trap(&dummy_t, &dummy_st) == 1);
    s_total_power_cuts_executed++;

    s_cut_at_op = 0U;
    sim_reset_sram_globals(RESET_REASON_POWER_ON);
    s_flash_op_counter = 0U;
    assert(boot_main(&s_platform, &dummy_t, k_seal_key) == BOOT_OK);
    uint32_t n2 = s_flash_op_counter;
    if (n2 == 0U) {
      continue;
    }

    /* Sweep ~10 representative k2 cut points during the recovery boot across all 3 modes */
    uint32_t k2_stride = (n2 > 10U) ? (n2 / 10U) : 1U;
    for (uint32_t k2 = 1U; k2 <= n2; k2 += k2_stride) {
      for (int m2 = 0; m2 < (int)CORRUPT_MODE_COUNT; m2++) {
        restore_hw_snapshot();

        /* Cut #1 at k1 */
        s_flash_op_counter = 0U;
        s_cut_at_op = k1;
        s_corrupt_mode = (corrupt_mode_t)((idx + (size_t)m2) % CORRUPT_MODE_COUNT);
        assert(execute_boot_with_cut_trap(&dummy_t, &dummy_st) == 1);
        s_total_power_cuts_executed++;

        /* Reboot #1 -> Cut #2 at k2 DURING recovery! */
        sim_reset_sram_globals(RESET_REASON_POWER_ON);
        s_flash_op_counter = 0U;
        s_cut_at_op = k2;
        s_corrupt_mode = (corrupt_mode_t)m2;
        assert(execute_boot_with_cut_trap(&dummy_t, &dummy_st) == 1);
        s_total_power_cuts_executed++;
        double_pairs++;

        /* Reboot #2 (3rd boot overall): MUST converge deterministically! */
        s_cur_diag_suite = suite_label;
        s_cur_diag_k = k1 * 1000U + k2;
        s_cur_diag_m = m2;
        s_cut_at_op = 0U;
        sim_reset_sram_globals(RESET_REASON_POWER_ON);
        boot_target_config_t final_target;
        assert(boot_main(&s_platform, &final_target, k_seal_key) == BOOT_OK);
        assert_recovered_handoff_valid(&final_target, v1, v2, recovery, goal);

        if (goal == EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY &&
            !final_target.boot_recovery_os && final_target.is_tentative_boot) {
          sim_reset_sram_globals(RESET_REASON_WATCHDOG);
          assert(boot_main(&s_platform, &final_target, k_seal_key) == BOOT_OK);
          assert(!final_target.is_tentative_boot);
          assert_recovered_handoff_valid(&final_target, v1, v2, recovery, goal);
        }
      }
    }
  }

  restore_hw_snapshot();
  printf("  [PASS] %-52s | nested_double_cuts=%4u | align=%2uB ECC=0-violations\n",
         suite_label, (unsigned)double_pairs,
         (unsigned)CHIP_FLASH_WRITE_ALIGNMENT);
  fflush(stdout);
}

/* ============================================================================
 * Profile-Specific Scenario Suites (Suites 1..6)
 * ============================================================================ */
int main(void) {
  uint8_t root_seed[32];
  uint8_t cloud_seed[32];
  for (size_t i = 0U; i < 32U; i++) {
    root_seed[i] = (uint8_t)(0x21U + i * 5U);
    cloud_seed[i] = (uint8_t)(0xE7U - i * 3U);
  }
  crypto_ed25519_key_pair(s_root_sk, s_root_pk, root_seed);
  crypto_ed25519_key_pair(s_cloud_sk, s_cloud_pk, cloud_seed);

  signed_image_ref_t img_v1 = {0};
  signed_image_ref_t img_v2 = {0};
  signed_image_ref_t img_rec = {0};

#if TOOB_INJ_PROFILE == 6
  /* 224 KB = 16 KB + 16 KB + 64 KB + 128 KB spanning all STM32F4 sector sizes */
  const size_t k_app_img_size = 0x00038000U;
  const size_t k_rec_img_size = 0x00004000U;
#else
  /* 12 KB = 3 x 4 KB sectors (multi-sector swap/delta/decomp, N <= 500 -> 100% step coverage) */
  const size_t k_app_img_size = 0x00003000U;
  const size_t k_rec_img_size = 0x00001000U;
#endif

  build_test_image(&img_v1, k_app_img_size, 1U, 0xA1U);
  build_test_image(&img_v2, k_app_img_size, 2U, 0xB2U);
  build_test_image(&img_rec, k_rec_img_size, 1U, 0xE0U);

#if TOOB_INJ_PROFILE == 1
  printf("=== Profile 1: POINTER (Tier 0 BFB2 + Tier 1B XIP_REMAP + Zero-Copy TDS1 + 8B ECC) ===\n");

  /* Suite 1A: Tier 0 BFB2 Dual-Bank Full OTA + WDT Rollback */
  configure_pointer_mode(true);
  init_fresh_device(&img_v1, &img_rec);
  uint32_t tbm1_addr = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_NONE, false);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_addr, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);
  run_exhaustive_single_cut_sweep("Suite 1A: Tier 0 BFB2 Full TBM1 OTA (v1->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);

  /* Deploy v2 cleanly, then inject power-cuts across BFB2 WDT rollback! */
  restore_hw_snapshot();
  boot_target_config_t deployed;
  assert(boot_main(&s_platform, &deployed, k_seal_key) == BOOT_OK);
  assert(deployed.active_slot == 1U && deployed.is_tentative_boot);
  sim_reset_sram_globals(RESET_REASON_WATCHDOG);
  run_exhaustive_single_cut_sweep("Suite 1A-RB: Tier 0 BFB2 Unconfirmed WDT Rollback",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);

  /* Suite 1B: Tier 1B XIP_REMAP Volatile Two-Slot Full OTA + WDT Rollback */
  configure_pointer_mode(false);
  init_fresh_device(&img_v1, &img_rec);
  tbm1_addr = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_NONE, false);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_addr, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);
  run_exhaustive_single_cut_sweep("Suite 1B: Tier 1B XIP_REMAP Full TBM1 OTA (v1->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);

  restore_hw_snapshot();
  assert(boot_main(&s_platform, &deployed, k_seal_key) == BOOT_OK);
  assert(deployed.active_slot == 1U && deployed.is_tentative_boot);
  sim_reset_sram_globals(RESET_REASON_WATCHDOG);
  run_exhaustive_single_cut_sweep("Suite 1B-RB: Tier 1B XIP_REMAP WDT Rollback",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);

  /* Suite 3A: Zero-Copy POINTER + TDS1 Forward-Delta + Heatshrink */
  init_fresh_device(&img_v1, &img_rec);
  tbm1_addr = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_TDS1, false);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_addr, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);
  run_exhaustive_single_cut_sweep("Suite 3A: Zero-Copy POINTER TDS1+Heatshrink (v1->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);
  run_nested_double_cut_sweep("Suite 5A: Nested Double Cuts (POINTER TDS1)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_V2_OR_V1);

#elif TOOB_INJ_PROFILE == 2
  printf("=== Profile 2: ONEWAY_FULL (Tier 1B Staging->Active Copy + Backup + 32B ECC) ===\n");

  init_fresh_device(&img_v1, &img_rec);
  uint32_t tbm1_addr = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_NONE, false);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_addr, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);

  run_exhaustive_single_cut_sweep("Suite 1C: Tier 1B ONEWAY Full TBM1 OTA (v1->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);
  run_nested_double_cut_sweep("Suite 5B-1: Nested Double Cuts (ONEWAY OTA)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_V2_OR_V1);

  /* Deploy v2 cleanly, then test WDT rollback power-cuts + nested double cuts */
  restore_hw_snapshot();
  boot_target_config_t deployed;
  assert(boot_main(&s_platform, &deployed, k_seal_key) == BOOT_OK);
  assert(deployed.is_tentative_boot);
  sim_reset_sram_globals(RESET_REASON_WATCHDOG);
  run_exhaustive_single_cut_sweep("Suite 1D: Tier 1B ONEWAY Unconfirmed WDT Rollback",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);
  run_nested_double_cut_sweep("Suite 5B-2: Nested Double Cuts (ONEWAY Rollback)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);

#elif TOOB_INJ_PROFILE == 3
  printf("=== Profile 3: SWAPMOVE (Tier 2B Two-Way In-Place Slide Swap + 8B ECC) ===\n");

  init_fresh_device(&img_v1, &img_rec);
  uint32_t tbm1_addr = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_NONE, false);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_addr, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);

  run_exhaustive_single_cut_sweep("Suite 2A: Tier 2B Swap-Move 2-Way Swap (v1<->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);
  run_nested_double_cut_sweep("Suite 5C-1: Nested Double Cuts (Swap-Move OTA)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_V2_OR_V1);

  restore_hw_snapshot();
  boot_target_config_t deployed;
  assert(boot_main(&s_platform, &deployed, k_seal_key) == BOOT_OK);
  assert(deployed.is_tentative_boot);
  sim_reset_sram_globals(RESET_REASON_WATCHDOG);
  run_exhaustive_single_cut_sweep("Suite 2B: Tier 2B Swap-Move WDT Rollback (v2->v1)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);
  run_nested_double_cut_sweep("Suite 5C-2: Nested Double Cuts (Swap-Move Rollback)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);

#elif TOOB_INJ_PROFILE == 4
  printf("=== Profile 4: SWAPSCRATCH (Tier 3 Two-Way Scratch-Ring Swap + 32B ECC) ===\n");

  init_fresh_device(&img_v1, &img_rec);
  uint32_t tbm1_addr = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_NONE, false);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_addr, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);

  run_exhaustive_single_cut_sweep("Suite 2C: Tier 3 Swap-Scratch 2-Way Swap (v1<->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);
  run_nested_double_cut_sweep("Suite 5D-1: Nested Double Cuts (Swap-Scratch OTA)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_V2_OR_V1);

  restore_hw_snapshot();
  boot_target_config_t deployed;
  assert(boot_main(&s_platform, &deployed, k_seal_key) == BOOT_OK);
  assert(deployed.is_tentative_boot);
  sim_reset_sram_globals(RESET_REASON_WATCHDOG);
  run_exhaustive_single_cut_sweep("Suite 2D: Tier 3 Swap-Scratch WDT Rollback (v2->v1)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);
  run_nested_double_cut_sweep("Suite 5D-2: Nested Double Cuts (Swap-Scratch Rollback)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);

#elif TOOB_INJ_PROFILE == 5
  printf("=== Profile 5: TDS1 Forward-Delta + Heatshrink Decomp + Reverse-Delta Rollback (8B ECC) ===\n");

  /* Suite 3B: Full Heatshrink Decompression OTA (boot_decomp.c) + Reverse-Delta */
  init_fresh_device(&img_v1, &img_rec);
  uint32_t tbm1_decomp = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_HEATSHRINK, TBM1_DELTA_NONE, true);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_decomp, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);
  run_exhaustive_single_cut_sweep("Suite 3B: Heatshrink Full Decomp OTA (v1->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);

  /* Suite 3C: TDS1 Forward-Delta + Heatshrink Literals (boot_delta.c) */
  init_fresh_device(&img_v1, &img_rec);
  uint32_t tbm1_delta = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_TDS1, true);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_delta, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);
  run_exhaustive_single_cut_sweep("Suite 3C: TDS1 Forward-Delta + Heatshrink (v1->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);
  run_nested_double_cut_sweep("Suite 5E-1: Nested Double Cuts (TDS1 Forward-Delta)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_V2_OR_V1);

  /* Suite 3D: Region 6 Reverse-Delta Rollback (v2 -> v1 via SDVM + SHA-256) */
  restore_hw_snapshot();
  boot_target_config_t deployed;
  assert(boot_main(&s_platform, &deployed, k_seal_key) == BOOT_OK);
  assert(deployed.is_tentative_boot);
  sim_reset_sram_globals(RESET_REASON_WATCHDOG);
  run_exhaustive_single_cut_sweep("Suite 3D: Region 6 Reverse-Delta Rollback (v2->v1)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);
  run_nested_double_cut_sweep("Suite 5E-2: Nested Double Cuts (Reverse-Delta Rollback)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);

#elif TOOB_INJ_PROFILE == 6
  printf("=== Profile 6: Asymmetric STM32F4 Geometry (16KB / 64KB / 128KB + 32B ECC) ===\n");

  init_fresh_device(&img_v1, &img_rec);
  uint32_t tbm1_addr = stage_trailer_tbm1_bundle(
      CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, &img_v1, &img_v2,
      TBM1_COMP_NONE, TBM1_DELTA_NONE, false);
  write_mailbox_request(TOOB_REQ_UPDATE_PENDING, 1U, tbm1_addr, 0ULL);
  sim_reset_sram_globals(RESET_REASON_SOFTWARE);

  run_exhaustive_single_cut_sweep("Suite 4A: STM32F4 16K/64K/128K 224KB OTA (v1->v2)",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_V2_OR_V1);
  run_nested_double_cut_sweep("Suite 5F: Nested Double Cuts (Asymmetric 16K/64K/128K)",
                              &img_v1, &img_v2, &img_rec,
                              EXPECT_CONVERGE_V2_OR_V1);

  restore_hw_snapshot();
  boot_target_config_t deployed;
  assert(boot_main(&s_platform, &deployed, k_seal_key) == BOOT_OK);
  assert(deployed.is_tentative_boot);
  sim_reset_sram_globals(RESET_REASON_WATCHDOG);
  run_exhaustive_single_cut_sweep("Suite 4B: STM32F4 16K/64K/128K WDT Rollback",
                                  &img_v1, &img_v2, &img_rec,
                                  EXPECT_CONVERGE_ROLLBACK_V1_OR_RECOVERY);
#endif

  free(img_v1.bytes);
  free(img_v2.bytes);
  free(img_rec.bytes);

  printf("TORN_WRITE_SUMMARY profile=%d cuts=%llu ecc_checks=%llu status=PASS\n\n",
         (int)TOOB_INJ_PROFILE,
         (unsigned long long)s_total_power_cuts_executed,
         (unsigned long long)s_total_ecc_word_checks);
  return 0;
}
