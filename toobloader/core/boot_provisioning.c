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
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include <stddef.h>
#include <string.h>

extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 512,
               "Crypto Arena muss mindestens 512B für Provisioning-Puffer");

/* ==============================================================================
 * Arena Partitioning (Zero-Allocation)
 * ==============================================================================
 */
#define PROV_RX_MAX_SIZE 256
#define PROV_TX_MAX_SIZE 16
#define PROV_KEY_MAX_SIZE 128

_Static_assert((PROV_RX_MAX_SIZE + PROV_TX_MAX_SIZE + PROV_KEY_MAX_SIZE) <=
                   BOOT_CRYPTO_ARENA_SIZE,
               "Provisioning arena partitions exceed BOOT_CRYPTO_ARENA_SIZE");

/* ==============================================================================
 * Provisioning Command Opcodes (Wire Protocol)
 * ==============================================================================
 */
#define PROV_CMD_BURN_KEY 0x01
#define PROV_CMD_SET_DSLC 0x02
#define PROV_CMD_SET_PROTECTION 0x03
#define PROV_CMD_ENABLE_SB 0x04
#define PROV_CMD_ENABLE_FE 0x05
#define PROV_CMD_READ_ID 0x06
#define PROV_CMD_REBOOT 0xFF

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
static void send_status(const boot_platform_t *platform, uint8_t *tx_buf,
                        boot_status_t status) {
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

_Noreturn void boot_provisioning_run(const boot_platform_t *platform) {
  /* P10 Defensive: Verify prerequisites before entering the loop */
  if (!platform || !platform->provisioning || !platform->console ||
      !platform->console->getchar || !platform->console->putchar) {
    /* Terminal halt — no provisioning HAL, no UART */
    while (1) {
      if (platform && platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
    }
  }

  /* Arena Partitioning */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
  uint8_t *rx_buf = crypto_arena;
  uint8_t *tx_buf = rx_buf + PROV_RX_MAX_SIZE;
  uint8_t *key_buf = tx_buf + PROV_TX_MAX_SIZE;

  /* Announce provisioning mode to the CLI */
  boot_cobs_send_frame(platform, (const uint8_t *)"PROV", 4);

  /* ==============================================================================
   * Main Provisioning Loop
   * ==============================================================================
   */
  while (1) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    /* Receive a COBS-framed command */
    boot_secure_zeroize(rx_buf, PROV_RX_MAX_SIZE);
    size_t raw_len = 0;

    boot_status_t recv_stat =
        boot_cobs_recv_frame(platform, rx_buf, PROV_RX_MAX_SIZE, &raw_len);
    if (recv_stat != BOOT_OK)
      continue;

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

    volatile uint32_t crc_shield_1 = 0, crc_shield_2 = 0;
    bool crc_ok = (received_crc == computed_crc);
    if (crc_ok)
      crc_shield_1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (crc_shield_1 == BOOT_OK && crc_ok)
      crc_shield_2 = BOOT_OK;

    if (crc_shield_1 != BOOT_OK || crc_shield_2 != BOOT_OK ||
        crc_shield_1 != crc_shield_2) {
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
      if (cmd_payload_len != 1 || !platform->provisioning->write_dslc) {
        result = BOOT_ERR_INVALID_ARG;
        break;
      }
      result = platform->provisioning->write_dslc(cmd_payload[0]);
      break;
    }

    case PROV_CMD_SET_PROTECTION: {
      /* Payload: [bitmask(4)] LE */
      if (cmd_payload_len != 4 ||
          !platform->provisioning->set_protection_bits) {
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
      if (!platform->crypto || !platform->crypto->read_chip_uid) {
        result = BOOT_ERR_NOT_SUPPORTED;
        break;
      }
      boot_secure_zeroize(key_buf, PROV_KEY_MAX_SIZE);
      size_t uid_len = 0;
      result =
          platform->crypto->read_chip_uid(key_buf, PROV_KEY_MAX_SIZE, &uid_len);
      send_status(platform, tx_buf, result);
      if (result == BOOT_OK && uid_len > 0) {
        boot_cobs_send_frame(platform, key_buf, uid_len);
      }
      boot_secure_zeroize(key_buf, PROV_KEY_MAX_SIZE);
      continue; /* Skip the default send_status at loop end */
    }

    case PROV_CMD_REBOOT: {
      send_status(platform, tx_buf, BOOT_OK);

      /* Zeroize the arena before reset */
      boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

      /* Starve the WDT to trigger a hardware reset */
      while (1) {
        /* Intentional infinite loop without WDT kicks */
      }
    }

    default:
      result = BOOT_ERR_NOT_SUPPORTED;
      break;
    }

    send_status(platform, tx_buf, result);
  }
}
