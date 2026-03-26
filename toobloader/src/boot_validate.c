/**
 * @file boot_validate.c
 * @brief Bootloader Slot Validation — Minimal RPK Header Checks
 *
 * Performs the absolute minimum validation needed by the bootloader
 * before jumping to a kernel image:
 *  - RPK magic bytes (4 bytes: "RPK\0")
 *  - Header CRC32 (integrity of header struct)
 *  - ABI version compatibility
 *  - Entry point within slot bounds
 *
 * This is deliberately simpler than the full 12-step OTA validation
 * in ota_validate.c — the bootloader has no crypto, no dynamic alloc,
 * and must run in <10ms.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../include/boot_config.h"
#include "../include/common/kb_tags.h"
#include "../include/common/rp_assert.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bootloader flash read */
extern int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len);

/* ============================================================================
 * RPK Header (duplicated from ota_validate.c to avoid kernel dependency)
 * ========================================================================== */

#define RPK_MAGIC_0 0x52 /* 'R' */
#define RPK_MAGIC_1 0x50 /* 'P' */
#define RPK_MAGIC_2 0x4B /* 'K' */
#define RPK_MAGIC_3 0x00

typedef struct __attribute__((packed)) {
  uint8_t magic[4];
  uint8_t abi_version;
  uint8_t arch_id;
  uint16_t flags;
  uint32_t text_size;
  uint32_t data_size;
  uint32_t bss_size;
  uint32_t entry_offset;
  uint32_t version;
  uint32_t min_hdf_ver;
  uint32_t ttl_expiry;
  uint32_t header_crc;
} boot_rpk_header_t;

_Static_assert(sizeof(boot_rpk_header_t) == 40,
               "RPK Header must be exactly 40 bytes");

/** Expected kernel ABI version (bootloader hardcodes this) */
#ifndef BOOT_ABI_VERSION
#define BOOT_ABI_VERSION 1
#endif

/* Kernel partition size (for entry point bounds check) */
#define BOOT_KERNEL_MAX_SIZE (128u * 1024u)

/* ============================================================================
 * CRC32 (Compact implementation for bootloader)
 *
 * Standard CRC-32/ISO-HDLC (poly 0xEDB88320, reflected).
 * No lookup table: saves ~1KB ROM, acceptable at boot time.
 * ========================================================================== */

static uint32_t boot_crc32(const uint8_t *data, uint32_t len) {
  uint32_t crc = 0xFFFFFFFFu;

  for (uint32_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (uint8_t bit = 0; bit < 8; bit++) {
      if (crc & 1u) {
        crc = (crc >> 1) ^ 0xEDB88320u;
      } else {
        crc >>= 1;
      }
    }
  }

  return crc ^ 0xFFFFFFFFu;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

/**
 * @osv
 * component: Bootloader.Validate
 * thread_safe: false
 * emits: []
 * consumes: []
 * hardware_resources: []
 * calls_indirect: []
 * sync_primitive: none
 * tag_status: auto
 */
KB_CORE()
int32_t boot_validate_slot(uint32_t slot_addr, uint32_t active_version,
                           uint32_t *out_entry) {
  RP_ASSERT(out_entry != NULL, "boot_v out NULL");
  if (!out_entry)
    return -1;
  *out_entry = 0;

  /* Read header from flash */
  boot_rpk_header_t hdr;
  int32_t ret = boot_flash_read(slot_addr, (uint8_t *)&hdr, sizeof(hdr));
  if (ret != 0)
    return -2;

  /* Check 1: Magic bytes */
  if (hdr.magic[0] != RPK_MAGIC_0 || hdr.magic[1] != RPK_MAGIC_1 ||
      hdr.magic[2] != RPK_MAGIC_2 || hdr.magic[3] != RPK_MAGIC_3) {
    return -3;
  }

  /* Check 2: Header CRC32 */
  boot_rpk_header_t crc_hdr;
  (void)rp_memcpy(&crc_hdr, &hdr, sizeof(hdr));
  crc_hdr.header_crc = 0;
  uint32_t computed = boot_crc32((const uint8_t *)&crc_hdr, sizeof(crc_hdr));
  if (computed != hdr.header_crc) {
    return -4;
  }

  /* Check 3: ABI version */
  if (hdr.abi_version != BOOT_ABI_VERSION) {
    return -5;
  }

  /* Check 4: Mathematical Bounds (P10 Rules 2/5)
   * A corrupted text_size of 0xFFFFFFFF could cause infinite loops or DoS.
   */
  if (hdr.text_size > BOOT_KERNEL_MAX_SIZE ||
      hdr.data_size > BOOT_KERNEL_MAX_SIZE ||
      hdr.bss_size > BOOT_KERNEL_MAX_SIZE) {
    return -6;
  }

  uint32_t total_size = hdr.text_size + hdr.data_size + hdr.bss_size;
  if (total_size > BOOT_KERNEL_MAX_SIZE) {
    return -7; /* Exceeds allowed slot partition size */
  }

  /* Check 5: Entry point within slot bounds */
  if (hdr.entry_offset >= total_size) {
    return -8;
  }

  /* Check 6: Anti-Rollback (Monotonic Counter) */
  if (hdr.version < active_version) {
    return -10; /* Downgrade Attack or Stale Image */
  }

  /* Compute absolute entry address securely */
  uint32_t absolute_entry =
      slot_addr + sizeof(boot_rpk_header_t) + hdr.entry_offset;
  if (absolute_entry < slot_addr) {
    return -9; /* Overflow */
  }
  *out_entry = absolute_entry;

  return 0;
}
