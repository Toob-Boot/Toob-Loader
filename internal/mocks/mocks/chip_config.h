#ifndef CHIP_CONFIG_SANDBOX_H
#define CHIP_CONFIG_SANDBOX_H

#include <stdint.h>

/* --- Flash Typologie (Simuliert: 16 MB NOR-Flash) --- */
#define CHIP_FLASH_TOTAL_SIZE (16 * 1024 * 1024)
#define CHIP_FLASH_MAX_SECTOR_SIZE 4096
#define CHIP_FLASH_PAGE_SIZE 4096
#define CHIP_FLASH_WRITE_ALIGNMENT 4
#define CHIP_APP_ALIGNMENT_BYTES 65536
#define CHIP_FLASH_ERASURE_MAPPING 0xFF
#define TOOB_FLASH_DISABLE_BLANK_CHECK 1

/* --- Hardware Watchdog Limits (Host-Mock) --- */
#define BOOT_WDT_TIMEOUT_MS 5000

/* --- Battery Guard (Host-Mock) --- */
#define CHIP_MIN_BATTERY_MV 3300

#endif /* CHIP_CONFIG_SANDBOX_H */
