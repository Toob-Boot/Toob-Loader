/**
 * ==============================================================================
 * Toob-Boot libtoob: Cloud-Command Submission (toob_cloud_submit.c)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/plan.md Phase 7 (OS-Boundary Cloud-Command Pipeline)
 * - docs/libtoob_api.md (Zero-Dependency Isolation, WAL Append semantics)
 * - docs/concept_fusion.md (TOCTOU-safe Flash Writes, Anti-Glitch defense)
 *
 * ARCHITECTURE:
 * The Feature-OS receives Cloud-Command Envelopes (CBOR, Ed25519-signed) from
 * the server and writes them into the CHIP_CLOUD_CMD_SLOT via this module.
 * The Bootloader evaluates the slot autonomously at every boot (Step 2.5).
 *
 * Pipeline: Guard → Erase → Write → CRC Read-Back → Zeroize.
 */

#include "libtoob.h"
#include "libtoob_config_sandbox.h"
#include "toob_internal.h"
#include <stddef.h>
#include <string.h>

/* ==============================================================================
 * PUBLIC API: toob_submit_cloud_command
 * ============================================================================== */

toob_status_t toob_submit_cloud_command(const uint8_t *envelope, uint32_t len) {
  if (!envelope || len == 0 || len > TOOB_CLOUD_CMD_SLOT_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Step 1: Erase the Cloud-Command Slot */
  toob_status_t erase_stat =
      toob_os_flash_erase(TOOB_CLOUD_CMD_SLOT_ADDR, TOOB_CLOUD_CMD_SLOT_SIZE);

  volatile uint32_t erase_shield_1 = 0, erase_shield_2 = 0;
  if (erase_stat == TOOB_OK)
    erase_shield_1 = TOOB_OK;
  TOOB_GLITCH_DELAY();
  if (erase_shield_1 == TOOB_OK && erase_stat == TOOB_OK)
    erase_shield_2 = TOOB_OK;

  if (erase_shield_1 != TOOB_OK || erase_shield_2 != TOOB_OK ||
      erase_shield_1 != erase_shield_2) {
    return (erase_stat != TOOB_OK) ? erase_stat : TOOB_ERR_FLASH;
  }

  /* Step 2: Write the Envelope */
  toob_status_t write_stat =
      toob_os_flash_write(TOOB_CLOUD_CMD_SLOT_ADDR, envelope, len);

  if (write_stat != TOOB_OK) {
    return write_stat;
  }

  /* Step 3: Phase-Bound Chunked Read-Back Verify.
   * We verify in 64-byte chunks to avoid a 4KB stack allocation
   * that would overflow typical RTOS thread stacks (4-8KB). */
  {
    uint8_t chunk_buf[64] __attribute__((aligned(8)));
    uint32_t pos = 0;

    while (pos < len) {
      uint32_t remaining = len - pos;
      uint32_t chunk_len = (remaining > 64U) ? 64U : remaining;

      toob_secure_zeroize(chunk_buf, sizeof(chunk_buf));

      toob_status_t read_stat = toob_os_flash_read(
          TOOB_CLOUD_CMD_SLOT_ADDR + pos, chunk_buf, chunk_len);

      if (read_stat != TOOB_OK) {
        toob_secure_zeroize(chunk_buf, sizeof(chunk_buf));
        return TOOB_ERR_FLASH_HW;
      }

      if (toob_ct_memcmp_glitch_safe(envelope + pos, chunk_buf,
                                     chunk_len) != TOOB_OK) {
        toob_secure_zeroize(chunk_buf, sizeof(chunk_buf));
        return TOOB_ERR_FLASH_HW;
      }

      pos += chunk_len;
    }

    toob_secure_zeroize(chunk_buf, sizeof(chunk_buf));
  }

  return TOOB_OK;
}

/* ==============================================================================
 * PUBLIC API: toob_get_device_id
 * ============================================================================== */

toob_status_t toob_get_device_id(uint8_t *out_id, size_t id_len) {
  if (!out_id || id_len < 32) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_handoff_t handoff __attribute__((aligned(8)));
  toob_secure_zeroize(&handoff, sizeof(handoff));

  toob_status_t status = toob_get_handoff(&handoff);
  if (status != TOOB_OK) {
    toob_secure_zeroize(&handoff, sizeof(handoff));
    return status;
  }

  memcpy(out_id, handoff.device_id, 32);

  toob_secure_zeroize(&handoff, sizeof(handoff));
  return TOOB_OK;
}
