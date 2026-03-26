#ifndef BOOTLOADER_BOOT_CONFIG_H
#define BOOTLOADER_BOOT_CONFIG_H

/**
 * @file boot_config.h
 * @brief Global configuration parameters for the Toobloader Bootloader
 *
 * This file is included by all bootloader components.
 * Parameters like RECOVERY_SLOT_ADDR are intended to be
 * passed via CMake during Link-Time Feature Gating.
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* @osv component: Bootloader.Core */
#ifndef BOOT_ABI_VERSION
#define BOOT_ABI_VERSION 1u
#endif

/*
 * RECOVERY_SLOT_ADDR should be provided by the build system.
 * We define a fallback here for testing purposes if it is omitted.
 */
/* @osv component: Bootloader.Core */
#ifndef RECOVERY_SLOT_ADDR
#define RECOVERY_SLOT_ADDR 0x00100000u
#endif

/* @osv component: Bootloader.Core */
#ifndef BOOT_SCRATCH_ADDR
#define BOOT_SCRATCH_ADDR 0x00048000u
#endif

/* @osv component: Bootloader.Core */
#ifndef BOOT_SECTOR_SIZE
#define BOOT_SECTOR_SIZE 4096u
#endif

/* ============================================================================
 * Boot State Sector (Triple Modular Redundancy - O(1) State)
 * ========================================================================== */

/* @osv component: Bootloader.Core */
#define BOOT_STATE_SECTOR_ADDR 0x00001000u
#define BOOT_STATE_MAGIC 0x52505754u /* 'RPWT' */
#define BOOT_MAX_ATTEMPTS 3u

/* Micro-States for Ping-Pong Auto-Revert Swap */
#define SWAP_STATE_IDLE 0x00
#define SWAP_STATE_A_TO_SCRATCH 0x01
#define SWAP_STATE_B_TO_A 0x02
#define SWAP_STATE_SCRATCH_TO_B 0x03

/* @osv component: Bootloader.Core */
typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint8_t active_slot;
  uint8_t boot_count;
  uint8_t in_recovery;
  uint8_t ota_update_pending; /* 1 if an update in Slot B needs copying */
  uint8_t swap_state;         /* Track atomic micro-steps to prevent bricking */
  uint8_t reserved[3];        /* Keep 4-byte architectural alignment */
  uint32_t ota_copy_progress; /* Absolute offset of bytes successfully copied */
  uint32_t ota_image_size;    /* Total size of the incoming image */
  uint32_t active_version;    /* Monotonic Security Counter (Anti-Rollback) */
  uint32_t sector_crc;
} boot_state_sector_t;

_Static_assert(sizeof(boot_state_sector_t) == 28,
               "Boot State Sector must be exactly 28 bytes");

/* ============================================================================
 * Hardware Reliability & Cryptographic Safety
 * ========================================================================== */

/**
 * @osv component: Bootloader.Core
 * @brief Secure, bounded memory copy replacement for libc's memcpy.
 */
extern void *rp_memcpy(void *dest, const void *src, size_t n);

/**
 * @osv component: Bootloader.Core
 * @brief Securely clears memory (prevents compiler from optimizing away)
 */
extern void rp_secure_zeroMemory(void *ptr, size_t size);

/**
 * @osv component: Bootloader.Core
 * @brief Initializes the hardware watchdog with a strict timeout (~500ms)
 */
extern void boot_hal_wdt_init(void);

/**
 * @osv component: Bootloader.Core
 * @brief Feeds the hardware watchdog to prevent physical lockups
 */
extern void boot_hal_wdt_feed(void);

/**
 * @osv component: Bootloader.Core
 * @brief Prints a null-terminated string to the Bootloader Console UART.
 */
extern void boot_uart_puts(const char *msg);

/**
 * @osv component: Bootloader.Core
 * @brief Reads a single byte from the Bootloader Console UART with timeout.
 *        Feeds the watchdog during the wait-state.
 * @param out_char Pointer to the destination byte.
 * @param timeout_ms Maximum time to wait in milliseconds.
 * @return 0 on success, -1 on timeout.
 */
extern int32_t boot_uart_getc_timeout(uint8_t *out_char, uint32_t timeout_ms);

/**
 * @osv component: Bootloader.Core
 * @brief Fallback Hardware Flash Writers
 */
extern int32_t boot_flash_write(uint32_t addr, const uint8_t *buf,
                                uint32_t len);
extern int32_t boot_flash_erase(uint32_t addr, uint32_t len);

/**
 * @osv component: Bootloader.Core
 * @brief Retrieves the 32-Byte Root Key (Authorization) from eFuse/OTP/UICR
 */
extern void boot_hal_get_root_key(uint8_t out_key[32]);

/**
 * @osv component: Bootloader.Crypto
 * @brief Retrieves the 32-Byte Firmware Encryption Key (FEK) from secured eFuse
 */
extern void boot_hal_get_firmware_key(uint8_t out_key[32]);

/**
 * @osv component: Bootloader.Core
 * @brief Retrieves the 32-Byte Device Lock Code (Possession) from fixed Flash
 * Address
 */
extern void boot_hal_get_dslc(uint8_t out_dslc[32]);

/**
 * @osv component: Bootloader.Core
 * @brief Linker script definitions for BSS isolation and Zeroization
 */
extern uint32_t _bss_start;
extern uint32_t _bss_end;

/**
 * @osv component: Bootloader.Core
 * @brief Primary Entry Point to the Boot State Machine (invoked by start_*.c)
 */
extern void boot_main(void);

#ifdef __cplusplus
}
#endif

#endif /* BOOTLOADER_BOOT_CONFIG_H */
