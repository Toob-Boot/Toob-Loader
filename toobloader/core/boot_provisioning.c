/*
 * ==============================================================================
 * Toob-Boot Core File: boot_provisioning.c
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/plan.md Phase 8 (Provisioning-HAL + CLI-Integration)
 * - docs/stuff.md Section 6.2 (DSLC-Gated Provisioning in Stage 1)
 * - docs/concept_fusion.md (Zero-Allocation, P10 Bounds)
 *
 * ARCHITECTURE:
 * This module implements the UART-based factory provisioning loop, entered
 * exclusively when the device is in DEVELOPMENT state (DSLC == 0x00). The
 * toob-cli sends COBS-framed commands to burn keys, advance DSLC, and set
 * protection bits. Each command receives a 4-byte status response.
 *
 * SECURITY:
 * 1. _Noreturn: No return path into the normal boot flow prevents accidental
 *    provisioning-to-OS transitions.
 * 2. Zero-Allocation: All buffers reside in the crypto_arena (BSS segment).
 * 3. CRC-32: Every command frame is CRC-protected against line noise.
 * 4. Arena Zeroize: Sensitive key material is wiped after every command.
 */

#include "boot_provisioning.h"
#include "boot_cobs.h"
#include "boot_crc32.h"
#include "boot_features.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include <stddef.h>
#include <string.h>

#if TOOB_FEATURE_UART_PROVISIONING

/* P5: Arena is now passed explicitly by the caller */

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 512,
               "Crypto Arena muss mindestens 512B für Provisioning-Puffer");

/* ==============================================================================
 * Arena Partitioning (Zero-Allocation)
 * ==============================================================================
 */
#define PROV_RX_MAX_SIZE 256
#define PROV_TX_MAX_SIZE 16
#define PROV_KEY_MAX_SIZE 128

_Static_assert((PROV_RX_MAX_SIZE + PROV_TX_MAX_SIZE + PROV_KEY_MAX_SIZE) <= BOOT_CRYPTO_ARENA_SIZE,
               "Provisioning arena partitions exceed BOOT_CRYPTO_ARENA_SIZE");

/* Frame layout: [CMD(1)] [PAYLOAD(N)] [CRC32(4)] — min 5 bytes */
#define PROV_FRAME_MIN_SIZE 5
#define PROV_CRC_SIZE 4

/* ==============================================================================
 * Internal Helpers
 * ==============================================================================
 */

/**
 * @brief Sends a 4-byte Little-Endian status response via COBS.
 */
static void send_status(const boot_platform_t *platform, uint8_t *tx_buf, boot_status_t status) {
  tx_buf[0] = (uint8_t)(status & 0xFF);
  tx_buf[1] = (uint8_t)((status >> 8) & 0xFF);
  tx_buf[2] = (uint8_t)((status >> 16) & 0xFF);
  tx_buf[3] = (uint8_t)((status >> 24) & 0xFF);
  boot_cobs_send_frame(platform, tx_buf, 4);
  boot_secure_zeroize(tx_buf, PROV_TX_MAX_SIZE);
}

/* ==============================================================================
 * PUBLIC API
 * ==============================================================================
 */

_Noreturn void boot_provisioning_run(const boot_platform_t *platform, uint8_t *arena,
                                     size_t arena_len) {
  /* P10 Defensive: Verify prerequisites before entering the loop */
  if (!platform || !platform->provisioning ||
      platform->provisioning->abi_version != TOOB_HAL_ABI_V3 || !platform->console ||
      !platform->console->getchar || !platform->console->putchar) {
    /* Terminal halt — no provisioning HAL, ABI mismatch, or no UART */
    boot_terminal_halt(platform, BOOT_ERR_INVALID_ARG, SITE_PROVISIONING_GLITCH);
  }

  /* Arena Partitioning */
  boot_secure_zeroize(arena, arena_len);
  uint8_t *rx_buf = arena;
  uint8_t *tx_buf = rx_buf + PROV_RX_MAX_SIZE;
  uint8_t *key_buf = tx_buf + PROV_TX_MAX_SIZE;

  /* Announce provisioning mode to the CLI */
  boot_cobs_send_frame(platform, (const uint8_t *)"PROV", 4);

  /* ==============================================================================
   * Main Provisioning Loop
   * ==============================================================================
   */
  while (1) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }

    /* Receive a COBS-framed command */
    boot_secure_zeroize(rx_buf, PROV_RX_MAX_SIZE);
    size_t raw_len = 0;

    boot_status_t recv_stat = boot_cobs_recv_frame(platform, rx_buf, PROV_RX_MAX_SIZE, &raw_len);
    if (recv_stat != BOOT_OK) {
      continue;
    }

    /* Decode COBS in-place */
    size_t decoded_len = 0;
    if (boot_cobs_decode_in_place(rx_buf, raw_len, &decoded_len) != BOOT_OK ||
        decoded_len < PROV_FRAME_MIN_SIZE) {
      send_status(platform, tx_buf, BOOT_ERR_INVALID_ARG);
      continue;
    }

    /* CRC-32 Verification (last 4 bytes are CRC of preceding payload) */
    size_t payload_len = decoded_len - PROV_CRC_SIZE;
    uint32_t received_crc = 0;
    memcpy(&received_crc, &rx_buf[payload_len], PROV_CRC_SIZE);

    uint32_t computed_crc = compute_boot_crc32(rx_buf, payload_len);

    bool crc_ok = true;
    BOOT_SECURE_REQUIRE(received_crc == computed_crc, { crc_ok = false; });
    if (!crc_ok) {
      send_status(platform, tx_buf, BOOT_ERR_VERIFY);
      continue;
    }

    /* Command Dispatch */
    uint8_t cmd = rx_buf[0];
    const uint8_t *cmd_payload = &rx_buf[1];
    size_t cmd_payload_len = payload_len - 1;
    boot_status_t result = BOOT_ERR_NOT_SUPPORTED;

    switch (cmd) {

    case PROV_CMD_BURN_KEY: {
      /* Payload: [key_index(1)] [key_data(N)] */
      if (cmd_payload_len < 2 || !platform->provisioning->burn_pubkey) {
        result = BOOT_ERR_INVALID_ARG;
        break;
      }
      uint8_t key_index = cmd_payload[0];
      size_t key_len = cmd_payload_len - 1;
      if (key_len > PROV_KEY_MAX_SIZE) {
        result = BOOT_ERR_INVALID_ARG;
        break;
      }

      boot_secure_zeroize(key_buf, PROV_KEY_MAX_SIZE);
      memcpy(key_buf, &cmd_payload[1], key_len);

      result = platform->provisioning->burn_pubkey(key_buf, key_len, key_index);
      boot_secure_zeroize(key_buf, PROV_KEY_MAX_SIZE);
      break;
    }

    case PROV_CMD_SET_DSLC: {
      /* Payload: [dslc_value(1)] */
      if (cmd_payload_len != 1U || cmd_payload[0] == 0x00U || cmd_payload[0] == 0xFFU ||
          !platform->provisioning->write_dslc) {
        result = BOOT_ERR_INVALID_ARG;
        break;
      }
      result = platform->provisioning->write_dslc(&cmd_payload[0], 1U);
      break;
    }

    case PROV_CMD_SET_PROTECTION: {
      /* Payload: [bitmask(4)] LE */
      if (cmd_payload_len != 4 || !platform->provisioning->set_protection_bits) {
        result = BOOT_ERR_INVALID_ARG;
        break;
      }
      uint32_t mask = 0;
      memcpy(&mask, cmd_payload, 4);
      result = platform->provisioning->set_protection_bits(mask);
      break;
    }

    case PROV_CMD_ENABLE_SB: {
      if (!platform->provisioning->enable_secure_boot) {
        result = BOOT_ERR_NOT_SUPPORTED;
        break;
      }
      result = platform->provisioning->enable_secure_boot();
      break;
    }

    case PROV_CMD_ENABLE_FE: {
      if (!platform->provisioning->enable_flash_encryption) {
        result = BOOT_ERR_NOT_SUPPORTED;
        break;
      }
      result = platform->provisioning->enable_flash_encryption();
      break;
    }

    case PROV_CMD_READ_ID: {
      /* Response: [status(4)] + [chip_uid(N)] as a second frame */
      if (!platform->keystore || !platform->keystore->read_chip_uid) {
        result = BOOT_ERR_NOT_SUPPORTED;
        break;
      }
      boot_secure_zeroize(key_buf, PROV_KEY_MAX_SIZE);
      size_t uid_len = 0;
      result = platform->keystore->read_chip_uid(key_buf, PROV_KEY_MAX_SIZE, &uid_len);
      send_status(platform, tx_buf, result);
      if (result == BOOT_OK && uid_len > 0) {
        boot_cobs_send_frame(platform, key_buf, uid_len);
      }
      boot_secure_zeroize(key_buf, PROV_KEY_MAX_SIZE);
      continue; /* Skip the default send_status at loop end */
    }

    case PROV_CMD_LOCK_BOOT_FLASH: {
      if (!platform->provisioning->lock_immutable_flash) {
        result = BOOT_ERR_NOT_SUPPORTED;
        break;
      }
      uint32_t lock_offset = 0U;
      uint32_t lock_size = 0U;
      if (cmd_payload_len == 0U) {
#if defined(CHIP_STAGE0_ABS_ADDR)
        lock_offset = (uint32_t)CHIP_STAGE0_ABS_ADDR;
        lock_size = (uint32_t)CHIP_STAGE0_SIZE;
#else
        lock_offset = 0U;
        lock_size = (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END;
#endif
        if (lock_size == 0U || (UINT32_MAX - lock_offset) < lock_size) {
          result = BOOT_ERR_INVALID_ARG;
          break;
        }
      } else if (cmd_payload_len == 8U) {
        lock_offset = (uint32_t)cmd_payload[0] | ((uint32_t)cmd_payload[1] << 8) |
                      ((uint32_t)cmd_payload[2] << 16) | ((uint32_t)cmd_payload[3] << 24);
        lock_size = (uint32_t)cmd_payload[4] | ((uint32_t)cmd_payload[5] << 8) |
                    ((uint32_t)cmd_payload[6] << 16) | ((uint32_t)cmd_payload[7] << 24);
        if (lock_size == 0U || (UINT32_MAX - lock_offset) < lock_size) {
          result = BOOT_ERR_INVALID_ARG;
          break;
        }
      } else {
        result = BOOT_ERR_INVALID_ARG;
        break;
      }
      result = platform->provisioning->lock_immutable_flash(lock_offset, lock_size);
      break;
    }

    case PROV_CMD_REBOOT: {
      send_status(platform, tx_buf, BOOT_OK);

      /* Zeroize the arena before reset */
      boot_secure_zeroize(arena, arena_len);

      /* Starve the WDT to trigger a hardware reset */
      boot_terminal_halt(platform, BOOT_OK, SITE_PROVISIONING_GLITCH);
      break;
    }

    default:
      result = BOOT_ERR_NOT_SUPPORTED;
      break;
    }

    send_status(platform, tx_buf, result);
  }
}

#else /* !TOOB_FEATURE_UART_PROVISIONING */

_Noreturn void boot_provisioning_run(const boot_platform_t *platform, uint8_t *arena,
                                     size_t arena_len) {
  (void)arena;
  (void)arena_len;
  boot_terminal_halt(platform, BOOT_ERR_NOT_SUPPORTED, SITE_PROVISIONING_GLITCH);
}

#endif /* TOOB_FEATURE_UART_PROVISIONING */
