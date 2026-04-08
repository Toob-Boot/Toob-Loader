#ifndef BOOT_CONFIG_MOCK_H
#define BOOT_CONFIG_MOCK_H

/* Temporäre Phase 1-3 Mock-Konfiguration bis der Manifest-Compiler fertig ist */
#define TOOB_WAL_BASE_ADDR 0x000F0000
#define TOOB_WAL_SECTORS   4

/* FIX (Doublecheck): Missing Addresses for App Slot A & Recovery OS */
#define CHIP_APP_SLOT_ABS_ADDR     0x00010000 
#define CHIP_STAGING_SLOT_ABS_ADDR 0x00060000
#define CHIP_RECOVERY_OS_ABS_ADDR  0x000B0000
#define CHIP_SCRATCH_SECTOR_ABS_ADDR 0x00100000
#define CHIP_FLASH_BASE_ADDR       0x00000000
#define CHIP_FLASH_TOTAL_SIZE      0x00200000 /* 2 MB Mock */
#define CHIP_APP_SLOT_SIZE         0x00050000 /* 320 KB Mock */

/* Mocks for Serial-Rescue Target Checks */
#define CHIP_STAGING_SLOT_ID       2

/* WDT Timeout als Hardware-Konstante (generiert vom Manifest Builder) */
#ifndef BOOT_WDT_TIMEOUT_MS
#define BOOT_WDT_TIMEOUT_MS        4100
#endif

/* Maximal physische Sektorgröße für den statischen Swap-Buffer, z.B. 4KB für SPI-Flash */
#ifndef CHIP_FLASH_MAX_SECTOR_SIZE
#define CHIP_FLASH_MAX_SECTOR_SIZE 4096
#endif


/* 
 * TODO (Phase 3.1): Kläre die endgültige physikalische Eigentümerschaft 
 * der crypto_arena. Sollte idealerweise via Linker-Script (flash_layout.ld) 
 * an das RAM-Ende gebunden werden (ohne statische Initialisierung).
 * Hier vorerst gemockt:
 */
#ifndef BOOT_CRYPTO_ARENA_SIZE
#define BOOT_CRYPTO_ARENA_SIZE 2048 /* Mock: Für Monocypher (~2KB) */
#endif

/* Fallback-Config für Crash Cascades */
#ifndef BOOT_CONFIG_MAX_RETRIES
#define BOOT_CONFIG_MAX_RETRIES 3
#endif

#ifndef BOOT_CONFIG_MAX_RECOVERY_RETRIES
#define BOOT_CONFIG_MAX_RECOVERY_RETRIES 3
#endif

#ifndef BOOT_CONFIG_EDGE_UNATTENDED_MODE
#define BOOT_CONFIG_EDGE_UNATTENDED_MODE false
#endif

#ifndef BOOT_CONFIG_BACKOFF_BASE_S
#define BOOT_CONFIG_BACKOFF_BASE_S 3600 /* 1h */
#endif

#include <stdint.h>
extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

#endif /* BOOT_CONFIG_MOCK_H */
