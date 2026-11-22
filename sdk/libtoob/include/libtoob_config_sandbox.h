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

/* Immutable Stage-0 Boot Region (Non-Brickability Write-Firewall) */
#ifndef CHIP_STAGE0_ABS_ADDR
#define CHIP_STAGE0_ABS_ADDR          0x00000000U
#endif
#ifndef CHIP_STAGE0_SIZE
#define CHIP_STAGE0_SIZE              0x00004000U
#endif
#ifndef CHIP_FLASH_IMMUTABLE_BOOT_END
#if (CHIP_STAGE0_SIZE) > 0U
#define CHIP_FLASH_IMMUTABLE_BOOT_END ((uint64_t)(CHIP_STAGE0_ABS_ADDR) + (uint64_t)(CHIP_STAGE0_SIZE))
#else
#define CHIP_FLASH_IMMUTABLE_BOOT_END 0x00000000ULL
#endif
#endif

/* M-SANDBOX Fuzzer Mock Values */
#define CHIP_WAL_SECTORS 4
#ifndef TOOB_WAL_SECTORS
#define TOOB_WAL_SECTORS CHIP_WAL_SECTORS
#endif
#define TOOB_WAL_SECTOR_ADDRS {0x4000, 0x5000, 0x6000, 0x10000}
#define TOOB_WAL_SECTOR_SIZES {4096,   4096,   4096,   16384}

#define CHIP_FLASH_WRITE_ALIGNMENT 8U
#define CHIP_FLASH_MAX_SECTOR_SIZE 16384U
#define CHIP_FLASH_ERASURE_MAPPING 0xFFFFFFFFU

#ifndef TOOB_TRANSPORT_SWAPSCRATCH
#  define TOOB_TRANSPORT_SWAPSCRATCH 1
#  define TOOB_TRANSPORT_ONEWAY      2
#  define TOOB_TRANSPORT_SWAPMOVE    3
#  define TOOB_TRANSPORT_POINTER     4
#  define TOOB_TRANSPORT_SWAPOFFSET  5
#endif

#ifndef TOOB_TRANSPORT_PROVIDER
#  define TOOB_TRANSPORT_PROVIDER TOOB_TRANSPORT_SWAPSCRATCH
#endif

#ifdef TOOB_HOST_FUZZING
    /* Fake pointer for RTC testing in Host-Sandbox */
    extern uint64_t mock_rtc_ram;
    #define ADDR_CONFIRM_RTC_RAM ((volatile uint64_t *)(&mock_rtc_ram))
#endif

/* App & Staging Slots for Sandbox Fuzzing (each 384 KB, 16 KB sector-aligned) */
#define CHIP_APP_SLOT_ABS_ADDR        0x00020000U
#define CHIP_APP_SLOT_SIZE            0x00060000U

#define CHIP_STAGING_SLOT_ABS_ADDR    0x00080000U
#define CHIP_STAGING_SLOT_SIZE        0x00060000U

/* Cloud-Command Envelope Slot (1 Sektor, Bootloader evaluiert bei jedem Boot) */
#define CHIP_CLOUD_CMD_SLOT_ABS_ADDR  0x000EC000U
#define CHIP_CLOUD_CMD_SLOT_SIZE      0x00004000U

/* KDM Quorum Store (Phase 4: 3 sectors for quorum-protected KDM) */
#define TOOB_KDM_QUORUM_ADDR          0x000F1000U
#define TOOB_KDM_QUORUM_SIZE          0x00003000U
#ifndef CHIP_KDM_QUORUM_ABS_ADDR
#define CHIP_KDM_QUORUM_ABS_ADDR      TOOB_KDM_QUORUM_ADDR
#endif
#ifndef CHIP_KDM_QUORUM_SIZE
#define CHIP_KDM_QUORUM_SIZE          TOOB_KDM_QUORUM_SIZE
#endif

/* OS→Core Mailbox (2 sectors, Double-Slot: 2×SectorSize, torn-write safe) */
#define CHIP_MAILBOX_ABS_ADDR         0x000F4000U
#define CHIP_MAILBOX_SLOT_SIZE        0x00004000U
#define CHIP_MAILBOX_SIZE             0x00008000U

#endif /* LIBTOOB_CONFIG_SANDBOX_H */
