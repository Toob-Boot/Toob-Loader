/**
 * @file boot_swap.c
 * @brief Power-Fail-Safe OTA Overwrite Engine
 *
 * Implements the A<-B overwrite logic with fine-grained TMR
 * progress tracking to ensure zero bricking risk on power loss.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../include/boot_swap.h"
#include "../include/boot_state.h"
#include "../include/common/kb_tags.h"
#include "../include/common/rp_assert.h"
#include "../third_party/chacha20/chacha20.h"

#include <stddef.h>
#include <stdint.h>

/* These should ideally match the target's configuration */
#define BOOT_KERNEL_A_ADDR 0x00008000u
#define BOOT_KERNEL_B_ADDR 0x00028000u
#define SWAP_CHUNK_SIZE 1024u

extern int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len);
extern int32_t boot_flash_write(uint32_t addr, const uint8_t *buf,
                                uint32_t len);
extern int32_t boot_flash_erase(uint32_t addr, uint32_t len);
extern void boot_uart_puts(const char *msg);

/**
 * @osv
 * component: Bootloader.OTA
 */
KB_CORE()
int32_t boot_swap_process_update(boot_state_sector_t *state) {
  RP_ASSERT(state != NULL, "state is NULL");

  if (state->ota_update_pending != 1) {
    return 0; /* Nothing to do */
  }

  (void)boot_uart_puts("[SWAP] Starting Power-Fail-Safe Ping-Pong Swap\r\n");

  uint8_t fek[32];
  boot_hal_get_firmware_key(fek);

  /* A predefined or hash-derived Nonce strategy is ideal. For bare metal
   * efficiency, we initialize the Nonce to 0, relying solely on the AES stream
   * counter (`ota_copy_progress`) for cryptographic integrity.
   */
  uint8_t nonce[12] = {0};

  /* Derive Backup Nonce for reversing avoiding Two-Time Pad */
  uint8_t backup_nonce[12];
  (void)rp_memcpy(backup_nonce, nonce, 12);
  backup_nonce[0] ^= 0xFF; /* Robust static derivation */

  uint8_t chunk_buf[SWAP_CHUNK_SIZE];
  struct chacha20_context ctx;

  while (state->ota_copy_progress < state->ota_image_size) {
    uint32_t sector_offset = state->ota_copy_progress;
    uint32_t remaining = state->ota_image_size - sector_offset;
    uint32_t sector_data_len =
        (remaining < BOOT_SECTOR_SIZE) ? remaining : BOOT_SECTOR_SIZE;

    /* Micro-Step 1: A -> Scratch */
    if (state->swap_state == SWAP_STATE_IDLE ||
        state->swap_state == SWAP_STATE_A_TO_SCRATCH) {
      if (state->swap_state == SWAP_STATE_IDLE) {
        state->swap_state = SWAP_STATE_A_TO_SCRATCH;
        if (boot_state_write_tmr(state) != 0)
          return -4;
      }
      if (boot_flash_erase(BOOT_SCRATCH_ADDR, BOOT_SECTOR_SIZE) != 0)
        return -1;

      for (uint32_t i = 0; i < sector_data_len; i += SWAP_CHUNK_SIZE) {
        uint32_t chunk_len = ((sector_data_len - i) < SWAP_CHUNK_SIZE)
                                 ? (sector_data_len - i)
                                 : SWAP_CHUNK_SIZE;
        if (boot_flash_read(BOOT_KERNEL_A_ADDR + sector_offset + i, chunk_buf,
                            chunk_len) != 0)
          return -2;
        if (boot_flash_write(BOOT_SCRATCH_ADDR + i, chunk_buf, chunk_len) != 0)
          return -3;
      }
      state->swap_state = SWAP_STATE_B_TO_A;
      if (boot_state_write_tmr(state) != 0)
        return -4;
    }

    /* Micro-Step 2: B -> A (Decrypt) */
    if (state->swap_state == SWAP_STATE_B_TO_A) {
      if (boot_flash_erase(BOOT_KERNEL_A_ADDR + sector_offset,
                           BOOT_SECTOR_SIZE) != 0)
        return -1;

      for (uint32_t i = 0; i < sector_data_len; i += SWAP_CHUNK_SIZE) {
        uint32_t chunk_len = ((sector_data_len - i) < SWAP_CHUNK_SIZE)
                                 ? (sector_data_len - i)
                                 : SWAP_CHUNK_SIZE;
        if (boot_flash_read(BOOT_KERNEL_B_ADDR + sector_offset + i, chunk_buf,
                            chunk_len) != 0)
          return -2;

        chacha20_init_context(&ctx, fek, nonce, (sector_offset + i) / 64);
        ctx.position = (sector_offset + i) % 64;
        chacha20_xor(&ctx, chunk_buf, chunk_len);

        if (boot_flash_write(BOOT_KERNEL_A_ADDR + sector_offset + i, chunk_buf,
                             chunk_len) != 0)
          return -3;
      }
      state->swap_state = SWAP_STATE_SCRATCH_TO_B;
      if (boot_state_write_tmr(state) != 0)
        return -4;
    }

    /* Micro-Step 3: Scratch -> B (Encrypt Backup) */
    if (state->swap_state == SWAP_STATE_SCRATCH_TO_B) {
      if (boot_flash_erase(BOOT_KERNEL_B_ADDR + sector_offset,
                           BOOT_SECTOR_SIZE) != 0)
        return -1;

      for (uint32_t i = 0; i < sector_data_len; i += SWAP_CHUNK_SIZE) {
        uint32_t chunk_len = ((sector_data_len - i) < SWAP_CHUNK_SIZE)
                                 ? (sector_data_len - i)
                                 : SWAP_CHUNK_SIZE;
        if (boot_flash_read(BOOT_SCRATCH_ADDR + i, chunk_buf, chunk_len) != 0)
          return -2;

        chacha20_init_context(&ctx, fek, backup_nonce,
                              (sector_offset + i) / 64);
        ctx.position = (sector_offset + i) % 64;
        chacha20_xor(&ctx, chunk_buf, chunk_len);

        if (boot_flash_write(BOOT_KERNEL_B_ADDR + sector_offset + i, chunk_buf,
                             chunk_len) != 0)
          return -3;
      }

      state->ota_copy_progress += BOOT_SECTOR_SIZE;
      if (state->ota_copy_progress >= state->ota_image_size) {
        state->ota_copy_progress = state->ota_image_size;
      }

      state->swap_state = SWAP_STATE_IDLE;
      if (boot_state_write_tmr(state) != 0)
        return -4;
    }
  }

  (void)boot_uart_puts("[SWAP] OTA Ping-Pong Swap FULLY completed.\r\n");

  /* Extract the new Security Version from the newly decrypted Slot A header
   * The `version` field in `boot_rpk_header_t` is at offset 24.
   */
  uint32_t new_version = 0;
  if (boot_flash_read(BOOT_KERNEL_A_ADDR + 24, (uint8_t *)&new_version, 4) ==
      0) {
    state->active_version = new_version;
  }

  state->ota_update_pending = 0;
  state->ota_copy_progress = 0;
  /* state->ota_image_size is RETAINED intentionally for the Auto-Revert engine
   */
  state->swap_state = SWAP_STATE_IDLE;
  state->active_slot = 0; /* Boot from Slot A after successful overwrite */

  return boot_state_write_tmr(state);
}

/**
 * @osv
 * component: Bootloader.OTA
 */
KB_CORE()
int32_t boot_swap_revert_update(boot_state_sector_t *state) {
  RP_ASSERT(state != NULL, "state is NULL");

  if (state->ota_image_size == 0) {
    return -1; /* No known backup size to revert */
  }

  (void)boot_uart_puts("[SWAP] CRITICAL: Bootloop Threshold Reached!\r\n");
  (void)boot_uart_puts(
      "[SWAP] Triggering Auto-Revert (Slot B -> Slot A)...\r\n");

  uint8_t fek[32];
  boot_hal_get_firmware_key(fek);

  uint8_t nonce[12] = {0};
  uint8_t backup_nonce[12];
  (void)rp_memcpy(backup_nonce, nonce, 12);
  backup_nonce[0] ^= 0xFF; /* Must match the backup derivation exactly */

  uint8_t chunk_buf[SWAP_CHUNK_SIZE];
  struct chacha20_context ctx;

  /* Destructive Revert: We don't save the crashing Slot A. We just overwrite
   * it. */
  if (boot_flash_erase(BOOT_KERNEL_A_ADDR, state->ota_image_size) != 0) {
    return -1;
  }

  uint32_t progress = 0;
  while (progress < state->ota_image_size) {
    uint32_t remaining = state->ota_image_size - progress;
    uint32_t chunk_len =
        (remaining < SWAP_CHUNK_SIZE) ? remaining : SWAP_CHUNK_SIZE;

    if (boot_flash_read(BOOT_KERNEL_B_ADDR + progress, chunk_buf, chunk_len) !=
        0)
      return -2;

    chacha20_init_context(&ctx, fek, backup_nonce, progress / 64);
    ctx.position = progress % 64;
    chacha20_xor(&ctx, chunk_buf, chunk_len);

    if (boot_flash_write(BOOT_KERNEL_A_ADDR + progress, chunk_buf, chunk_len) !=
        0)
      return -3;

    progress += chunk_len;
  }

  /* Revert successful. Clear state to boot natively from restored Slot A */
  (void)boot_uart_puts(
      "[SWAP] Auto-Revert successful. Restored Backup V1.\r\n");

  state->boot_count = 0;  /* Reset failure count since we healed the firmware */
  state->in_recovery = 0; /* Turn off panic mode */

  /* We read the version of the restored firmware back into the active version
   */
  uint32_t restored_version = 0;
  if (boot_flash_read(BOOT_KERNEL_A_ADDR + 24, (uint8_t *)&restored_version,
                      4) == 0) {
    state->active_version = restored_version;
  }

  return boot_state_write_tmr(state);
}
