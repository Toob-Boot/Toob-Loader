/**
 * ==============================================================================
 * Toob-Boot libtoob_config_sandbox.h (Mock Generiert Phase 3)
 * ==============================================================================
 * 
 * Temporärer Header zur Bereitstellung fiktiver Adressen für Phase 3 M-SANDBOX Tests.
 * Harmonisiert mit den Namen des Manifest-Compilers, um Fallback-Makros zu vermeiden.
 */

#ifndef LIBTOOB_CONFIG_SANDBOX_H
#define LIBTOOB_CONFIG_SANDBOX_H

#include <stdint.h>

/* M-SANDBOX Fuzzer Mock Values */
#define CHIP_WAL_SECTORS 4
#define TOOB_WAL_SECTOR_ADDRS {0x4000, 0x5000, 0x6000, 0x10000}
#define TOOB_WAL_SECTOR_SIZES {4096,   4096,   4096,   16384}

#define CHIP_FLASH_WRITE_ALIGNMENT 8
#define CHIP_FLASH_MAX_SECTOR_SIZE 16384
#define CHIP_FLASH_ERASURE_MAPPING 0xFFFFFFFF

#ifdef TOOB_HOST_FUZZING
    /* Fake pointer for RTC testing in Host-Sandbox */
    extern uint64_t mock_rtc_ram;
    #define ADDR_CONFIRM_RTC_RAM ((volatile uint64_t*)(&mock_rtc_ram))
#endif

/* Cloud-Command Envelope Slot (1 Sektor, Bootloader evaluiert bei jedem Boot) */
#define CHIP_CLOUD_CMD_SLOT_ABS_ADDR  0x000F0000
#define CHIP_CLOUD_CMD_SLOT_SIZE      0x1000

/* App Slots for Sandbox Fuzzing */
#define CHIP_STAGING_SLOT_ABS_ADDR    0x00080000
#define CHIP_STAGING_SLOT_SIZE        0x00060000

/* KDM Quorum Store (Phase 4: 3 sectors for quorum-protected KDM) */
#define TOOB_KDM_QUORUM_ADDR     0x000F1000
#define TOOB_KDM_QUORUM_SIZE     0x3000

/* OS→Core Mailbox (2 sectors, Double-Slot: 2×SectorSize, torn-write safe) */
#define CHIP_MAILBOX_ABS_ADDR    0x000F4000
#define CHIP_MAILBOX_SLOT_SIZE   0x1000
#define CHIP_MAILBOX_SIZE        0x2000

#endif /* LIBTOOB_CONFIG_SANDBOX_H */
