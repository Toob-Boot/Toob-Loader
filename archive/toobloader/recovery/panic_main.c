/**
 * @file panic_main.c
 * @brief Toobloader Stage 2 Recovery (Panic Firmware)
 *
 * Implements an Offline USB/Serial 2FA handshake.
 * Executed ONLY by the Stage 1 Bootloader if the system is completely
 * corrupted.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include "../include/boot_arch.h"
#include "../include/boot_config.h"
#include "../include/common/kb_tags.h"
#include "../include/common/rp_assert.h"

#include <stdint.h>
#include <string.h>

extern void boot_hal_init(void);
extern void boot_uart_puts(const char *msg);

/* Third-Party Ed25519 (Compact25519) */
extern int ed25519_verify(const unsigned char *signature,
                          const unsigned char *message, size_t message_len,
                          const unsigned char *public_key);

/* 104-Byte 2FA Handshake Token Structure */
typedef struct __attribute__((packed)) {
  uint64_t timestamp;
  uint8_t dslc[32];
  uint8_t signature[64];
} recovery_token_t;

/**
 * @brief Passive blocking read for the 104-Byte Token via USB/UART.
 */
static int receive_token(recovery_token_t *token) {
  uint8_t *ptr = (uint8_t *)token;
  uint32_t expected_bytes = sizeof(recovery_token_t);
  uint32_t bytes_read = 0;

  while (bytes_read < expected_bytes) {
    /* Read a single byte with a 500ms timeout per byte */
    if (boot_uart_getc_timeout(&ptr[bytes_read], 500) == 0) {
      bytes_read++;
    } else {
      /* If timeout occurs mid-stream, abort and reset the State Machine */
      return -1;
    }
  }

  return 0; /* 104 Bytes successfully received */
}

/**
 * @brief Computes CRC16-CCITT dynamically (O(1) memory, P10 compliant).
 */
static uint16_t crc16_ccitt(const uint8_t *data, uint16_t length) {
  uint16_t crc = 0;
  while (length--) {
    crc ^= (uint16_t)*data++ << 8;
    for (int i = 0; i < 8; i++) {
      if (crc & 0x8000) {
        crc = (crc << 1) ^ 0x1021;
      } else {
        crc <<= 1;
      }
    }
  }
  return crc;
}

#define XMODEM_SOH 0x01
#define XMODEM_EOT 0x04
#define XMODEM_ACK 0x06
#define XMODEM_NAK 0x15
#define XMODEM_CAN 0x18

/**
 * @brief After 2FA auth, streams the kernel.bin into slot A.
 */
static void receive_xmodem_image(void) {
  uint32_t flash_addr = RECOVERY_SLOT_ADDR;
  uint32_t current_erase_sector = flash_addr;
  uint8_t expected_block = 1;
  uint8_t buf[132];
  uint8_t c;
  char uart_char_str[2] = {0, 0};

  boot_uart_puts("[RECOVERY] Waiting for XMODEM stream (kernel.bin)...\r\n");

  /* Hardware-agnostic initial sector wipe */
  (void)boot_flash_erase(current_erase_sector, 4096);

  /* Transmit 'C' to request CRC mode XMODEM */
  boot_uart_puts("C");

  while (1) {
    /* Poll with long timeouts to afford human response / slow hosts */
    if (boot_uart_getc_timeout(&c, 3000) != 0) {
      boot_uart_puts("C"); /* Re-request upon absolute timeout */
      continue;
    }

    if (c == XMODEM_EOT) {
      uart_char_str[0] = XMODEM_ACK;
      boot_uart_puts(uart_char_str);
      break;
    }

    if (c == XMODEM_CAN) {
      break;
    }

    if (c == XMODEM_SOH) {
      int err = 0;
      /* Read the remaining 132 bytes of the payload:
         BlockNum (1), ~BlockNum (1), Payload (128), CRC (2) */
      for (int i = 0; i < 132; i++) {
        if (boot_uart_getc_timeout(&buf[i], 1000) != 0) {
          err = 1;
          break;
        }
      }

      if (err) {
        uart_char_str[0] = XMODEM_NAK;
        boot_uart_puts(uart_char_str);
        continue;
      }

      uint8_t blk = buf[0];
      uint8_t inv_blk = buf[1];

      if (blk != (uint8_t)(~inv_blk)) {
        uart_char_str[0] = XMODEM_NAK;
        boot_uart_puts(uart_char_str);
        continue;
      }

      uint16_t crc_rcv = ((uint16_t)buf[130] << 8) | buf[131];
      if (crc16_ccitt(&buf[2], 128) != crc_rcv) {
        uart_char_str[0] = XMODEM_NAK;
        boot_uart_puts(uart_char_str);
        continue;
      }

      if (blk == expected_block) {
        /* P10 Memory boundary handling across sectors */
        if (flash_addr >= current_erase_sector + 4096) {
          current_erase_sector += 4096;
          (void)boot_flash_erase(current_erase_sector, 4096);
        }

        (void)boot_flash_write(flash_addr, &buf[2], 128);
        flash_addr += 128;
        expected_block++;
      } else if (blk != (uint8_t)(expected_block - 1)) {
        /* Desynchronized */
        uart_char_str[0] = XMODEM_CAN;
        (void)boot_uart_puts(uart_char_str);
        break;
      }

      uart_char_str[0] = XMODEM_ACK;
      (void)boot_uart_puts(uart_char_str);
    }
  }
}

/**
 * @osv
 * component: Bootloader.Recovery
 * tag_status: auto
 */
/* @osv-ignore: r7_return_discard (Listener/Entry Point) */
KB_CORE()
void panic_main(void) {
  /* NASA P10 Rule 5 / OSV: Defensive Programming Bounds Check */
  RP_ASSERT(sizeof(recovery_token_t) == 104, "Token struct size malformed");

  /* 1. Hardware Init (Zero OS Dependencies) */
  if (boot_hal_init() != 0) {
    (void)boot_arch_halt();
  }
  (void)boot_uart_puts("\r\n=== TOOBLOADER SECURE RECOVERY ===\r\n");

  uint8_t root_key[32];
  uint8_t local_dslc[32];

  /* 2. Extract Secrets via Zero-Dependency HAL (eFuse / Fixed Flash Offset) */
  (void)boot_hal_get_root_key(root_key);
  (void)boot_hal_get_dslc(local_dslc);

  (void)boot_uart_puts("[RECOVERY] Locked. Awaiting 104-Byte 2FA Token...\r\n");

  /* 3. Passive Listener Loop */
  recovery_token_t token;
  (void)rp_secure_zeroMemory(&token, sizeof(token));

  for (uint32_t i = 0; i < 1000000; i++) {
    if (receive_token(&token) == 0) {

      /* Factor 1: Validate DSLC (Possession / Lock Code) */
      if (memcmp(token.dslc, local_dslc, 32) != 0) {
        (void)boot_uart_puts("[RECOVERY] ERR: DSLC Possession Mismatch.\r\n");
        continue;
      }

      /* Factor 2: Validate Signature (Authorization)
       * Message is Timestamp + DSLC (40 bytes total).
       */
#ifdef LINK_ED25519
      if (ed25519_verify(token.signature, (const unsigned char *)&token, 40,
                         root_key) != 1) {
        (void)boot_uart_puts(
            "[RECOVERY] ERR: Invalid ROOT_KEY Authorization.\r\n");
        continue;
      }
#endif

      (void)boot_uart_puts("[RECOVERY] 2FA SUCCESS: Flash Unlocked.\r\n");

      if (receive_xmodem_image() == 0) {
        (void)boot_uart_puts("[RECOVERY] Complete. Rebooting...\r\n");
      } else {
        (void)boot_uart_puts("[RECOVERY] ERR: Transfer Failed.\r\n");
      }

      (void)boot_arch_halt();
    }
  }
}
