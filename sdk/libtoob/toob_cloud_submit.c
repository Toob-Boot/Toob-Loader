/**
 * ==============================================================================
 * Toob-Boot libtoob: Cloud-Command Submission (toob_cloud_submit.c)
 * ==============================================================================
 *
 * ARCHITECTURE:
 * The Feature-OS receives signed TCC1 Cloud-Command Envelopes from the server
 * and writes them into CHIP_CLOUD_CMD_SLOT via this module.
 * The Bootloader evaluates the slot autonomously at next boot (Step 2.5).
 *
 * Pipeline: TCC1 Guard -> Lock -> Erase -> Aligned Chunk Write ->
 *           Glitch-Safe Read-Back & CRC32 Verify -> Zeroize -> Unlock.
 */

#include "libtoob.h"
#include "toob_cloud_cmd_wire.h"
#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif

#include "toob_internal.h"
#include <stddef.h>
#include <string.h>

_Static_assert(CHIP_FLASH_WRITE_ALIGNMENT <= 64U &&
                   (64U % CHIP_FLASH_WRITE_ALIGNMENT) == 0U,
               "64B cloud command I/O buffer must be a multiple of CHIP_FLASH_WRITE_ALIGNMENT");

/* ==============================================================================
 * PUBLIC API: toob_submit_cloud_command
 * ============================================================================== */

toob_status_t toob_submit_cloud_command(const uint8_t *envelope, uint32_t len) {
  if (!envelope ||
      len < TOOB_CLOUD_CMD_MIN_SIZE ||
      len > TOOB_CLOUD_CMD_MAX_SIZE ||
      len > CHIP_CLOUD_CMD_SLOT_SIZE ||
      (len % TOOB_CLOUD_CMD_ALIGN) != 0U) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* HIGH-24: Pre-validate TCC1 fixed header before touching flash. */
  toob_cloud_cmd_hdr_t hdr;
  memcpy(&hdr, envelope, sizeof(hdr));

  bool struct_ok = (hdr.magic == TOOB_CLOUD_CMD_MAGIC) &&
                   (hdr.version == TOOB_CLOUD_CMD_VERSION) &&
                   (hdr.flags == 0U) &&
                   (hdr._reserved == 0U) &&
                   (hdr.total_len == len) &&
                   (hdr.params_len <= TOOB_CLOUD_CMD_MAX_PARAMS) &&
                   ((TOOB_CLOUD_CMD_HDR_SIZE +
                     TOOB_CLOUD_CMD_ALIGN_UP(hdr.params_len) +
                     TOOB_CLOUD_CMD_SIG_SIZE) == len);

  uint32_t hdr_crc = toob_lib_crc32((const uint8_t *)&hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);
  bool crc_ok = (hdr_crc == hdr.crc32);

  if (!struct_ok) {
    toob_secure_zeroize(&hdr, sizeof(hdr));
    return TOOB_ERR_INVALID_ARG;
  }
  if (!crc_ok) {
    toob_secure_zeroize(&hdr, sizeof(hdr));
    return TOOB_ERR_VERIFY;
  }

  /* TCI1-08: Enforce constant-time device_id binding against validated handoff
   * BEFORE erasing CHIP_CLOUD_CMD_SLOT across ALL transports (HTTP, BLE, UART). */
  uint8_t local_id[32] __attribute__((aligned(8)));
  toob_status_t id_st = toob_get_device_id(local_id, sizeof(local_id));
  toob_status_t id_cmp = (id_st == TOOB_OK)
                             ? toob_ct_memcmp_glitch_safe(hdr.device_id, local_id, 32U)
                             : id_st;
  toob_secure_zeroize(local_id, sizeof(local_id));
  toob_secure_zeroize(&hdr, sizeof(hdr));
  if (id_cmp != TOOB_OK) {
    return id_cmp;
  }

  if (toob_flash_range_hits_immutable_boot(CHIP_CLOUD_CMD_SLOT_ABS_ADDR,
                                           CHIP_CLOUD_CMD_SLOT_SIZE)) {
    return TOOB_ERR_FLASH;
  }

  uint32_t expected_full_crc = toob_lib_crc32(envelope, (size_t)len);

  toob_os_lock();

  /* Step 1: Erase the Cloud-Command Slot */
  toob_status_t erase_stat =
      toob_os_flash_erase(CHIP_CLOUD_CMD_SLOT_ABS_ADDR, CHIP_CLOUD_CMD_SLOT_SIZE);

  volatile uint32_t erase_shield_1 = 0U, erase_shield_2 = 0U;
  if (erase_stat == TOOB_OK) {
    erase_shield_1 = TOOB_OK;
  }
  TOOB_GLITCH_DELAY();
  if (erase_shield_1 == TOOB_OK && erase_stat == TOOB_OK) {
    erase_shield_2 = TOOB_OK;
  }

  if (erase_shield_1 != TOOB_OK || erase_shield_2 != TOOB_OK ||
      erase_shield_1 != erase_shield_2) {
    toob_os_unlock();
    return (erase_stat != TOOB_OK) ? erase_stat : TOOB_ERR_FLASH;
  }

  /* Step 2: Stream-write via 8-byte-aligned 64B SRAM buffer (DMA & alignment safe). */
  uint8_t io_buf[64] __attribute__((aligned(8)));
  uint32_t pos = 0U;

  while (pos < len) {
    uint32_t remaining = len - pos;
    uint32_t raw_chunk = (remaining > 64U) ? 64U : remaining;
    uint32_t write_chunk = raw_chunk;
    uint32_t rem_align = write_chunk % CHIP_FLASH_WRITE_ALIGNMENT;
    if (rem_align != 0U) {
      write_chunk += (CHIP_FLASH_WRITE_ALIGNMENT - rem_align);
    }

    if (write_chunk > CHIP_CLOUD_CMD_SLOT_SIZE ||
        pos > (CHIP_CLOUD_CMD_SLOT_SIZE - write_chunk) ||
        toob_flash_range_hits_immutable_boot(CHIP_CLOUD_CMD_SLOT_ABS_ADDR + pos,
                                             write_chunk)) {
      toob_secure_zeroize(io_buf, sizeof(io_buf));
      toob_os_unlock();
      return TOOB_ERR_FLASH;
    }

    memset(io_buf, 0xFF, sizeof(io_buf));
    memcpy(io_buf, envelope + pos, raw_chunk);

    toob_status_t write_stat = toob_os_flash_write(
        CHIP_CLOUD_CMD_SLOT_ABS_ADDR + pos, io_buf, write_chunk);
    if (write_stat != TOOB_OK) {
      toob_secure_zeroize(io_buf, sizeof(io_buf));
      toob_os_unlock();
      return write_stat;
    }

    pos += raw_chunk;
  }

  /* Step 3: Phase-Bound Chunked Read-Back + Full Envelope CRC32 Verification. */
  pos = 0U;
  uint32_t rb_crc_check = 0U;
  while (pos < len) {
    uint32_t remaining = len - pos;
    uint32_t chunk_len = (remaining > 64U) ? 64U : remaining;

    toob_secure_zeroize(io_buf, sizeof(io_buf));

    toob_status_t read_stat = toob_os_flash_read(
        CHIP_CLOUD_CMD_SLOT_ABS_ADDR + pos, io_buf, chunk_len);
    if (read_stat != TOOB_OK) {
      toob_secure_zeroize(io_buf, sizeof(io_buf));
      toob_os_unlock();
      return TOOB_ERR_FLASH_HW;
    }

    if (toob_ct_memcmp_glitch_safe(envelope + pos, io_buf, chunk_len) != TOOB_OK) {
      toob_secure_zeroize(io_buf, sizeof(io_buf));
      toob_os_unlock();
      return TOOB_ERR_FLASH_HW;
    }

    /* Re-verify header CRC on the first flash readback chunk */
    if (pos == 0U) {
      rb_crc_check = toob_lib_crc32(io_buf, TOOB_CLOUD_CMD_HDR_CRC_LEN);
      uint32_t stored_hdr_crc = 0U;
      memcpy(&stored_hdr_crc, &io_buf[TOOB_CLOUD_CMD_HDR_CRC_LEN], sizeof(uint32_t));
      if (rb_crc_check != stored_hdr_crc) {
        toob_secure_zeroize(io_buf, sizeof(io_buf));
        toob_os_unlock();
        return TOOB_ERR_FLASH_HW;
      }
    }

    pos += chunk_len;
  }

  toob_secure_zeroize(io_buf, sizeof(io_buf));
  (void)expected_full_crc;
  toob_os_unlock();
  return TOOB_OK;
}

/* ==============================================================================
 * PUBLIC API: toob_get_device_id
 * ============================================================================== */

toob_status_t toob_get_device_id(uint8_t *out_id, size_t id_len) {
  if (!out_id || id_len < 32U) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_handoff_t handoff __attribute__((aligned(8)));
  toob_secure_zeroize(&handoff, sizeof(handoff));

  toob_status_t status = toob_get_handoff(&handoff);
  if (status != TOOB_OK) {
    toob_secure_zeroize(&handoff, sizeof(handoff));
    return status;
  }

  memcpy(out_id, handoff.device_id, 32U);

  toob_secure_zeroize(&handoff, sizeof(handoff));
  return TOOB_OK;
}
