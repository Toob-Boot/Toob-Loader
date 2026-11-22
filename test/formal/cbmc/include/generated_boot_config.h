/*
 * Parameterized Boot Configuration for Toob-Loader CBMC Suite (Wave 5A).
 *
 * Parameterizable compile-time knobs:
 *   -DCHIP_FLASH_WRITE_ALIGNMENT={1U,4U,8U,32U}  (default: 8U)
 *   -DCBMC_ASYMMETRIC_SECTORS={0,1}              (default: 0)
 *   -DTOOB_TRANSPORT_PROVIDER=...                (default: TOOB_TRANSPORT_SWAPSCRATCH)
 */
#ifndef GENERATED_BOOT_CONFIG_H
#define GENERATED_BOOT_CONFIG_H

#include <stdint.h>
#include "boot_layout.h"

#ifndef CHIP_FLASH_WRITE_ALIGNMENT
#define CHIP_FLASH_WRITE_ALIGNMENT               8U
#endif

#ifndef CHIP_FLASH_BASE_ADDR
#define CHIP_FLASH_BASE_ADDR                     0x00000000U
#endif

#ifndef CHIP_FLASH_ERASED_BYTE
#define CHIP_FLASH_ERASED_BYTE                   0xFFU
#endif

#ifndef CHIP_FLASH_ERASURE_MAPPING
#define CHIP_FLASH_ERASURE_MAPPING               0xFFFFFFFFU
#endif

#ifndef CHIP_STAGING_SLOT_ID
#define CHIP_STAGING_SLOT_ID                     2U
#endif

#if CBMC_ASYMMETRIC_SECTORS == 0

#ifndef CHIP_FLASH_TOTAL_SIZE
#define CHIP_FLASH_TOTAL_SIZE                    0x00100000U
#endif
#ifndef CHIP_FLASH_MAX_SECTOR_SIZE
#define CHIP_FLASH_MAX_SECTOR_SIZE               4096U
#endif
#ifndef TOOB_WAL_SECTORS
#define TOOB_WAL_SECTORS                         4U
#endif
#ifndef TOOB_WAL_SECTOR_ADDRS
#define TOOB_WAL_SECTOR_ADDRS                    { \
    CHIP_WAL_SECTOR_0_ADDR, \
    CHIP_WAL_SECTOR_1_ADDR, \
    CHIP_WAL_SECTOR_2_ADDR, \
    CHIP_WAL_SECTOR_3_ADDR  \
}
#endif
#ifndef TOOB_WAL_SECTOR_SIZES
#define TOOB_WAL_SECTOR_SIZES                    { \
    CHIP_WAL_SECTOR_0_SIZE, \
    CHIP_WAL_SECTOR_1_SIZE, \
    CHIP_WAL_SECTOR_2_SIZE, \
    CHIP_WAL_SECTOR_3_SIZE  \
}
#endif

#else /* CBMC_ASYMMETRIC_SECTORS != 0 */

#ifndef CHIP_FLASH_TOTAL_SIZE
#define CHIP_FLASH_TOTAL_SIZE                    0x00200000U
#endif
#ifndef CHIP_FLASH_MAX_SECTOR_SIZE
#define CHIP_FLASH_MAX_SECTOR_SIZE               131072U
#endif
#ifndef TOOB_WAL_SECTORS
#define TOOB_WAL_SECTORS                         4U
#endif
#ifndef TOOB_WAL_SECTOR_ADDRS
#define TOOB_WAL_SECTOR_ADDRS                    { \
    CHIP_WAL_SECTOR_0_ADDR, \
    CHIP_WAL_SECTOR_1_ADDR, \
    CHIP_WAL_SECTOR_2_ADDR, \
    CHIP_WAL_SECTOR_3_ADDR  \
}
#endif
#ifndef TOOB_WAL_SECTOR_SIZES
#define TOOB_WAL_SECTOR_SIZES                    { \
    CHIP_WAL_SECTOR_0_SIZE, \
    CHIP_WAL_SECTOR_1_SIZE, \
    CHIP_WAL_SECTOR_2_SIZE, \
    CHIP_WAL_SECTOR_3_SIZE  \
}
#endif

#endif /* CBMC_ASYMMETRIC_SECTORS */

#ifndef CHIP_WAL_SECTORS
#define CHIP_WAL_SECTORS                         TOOB_WAL_SECTORS
#endif

#ifndef TOOB_KDM_SLOT_ADDRS
#define TOOB_KDM_SLOT_ADDRS                      { \
    CHIP_KDM_QUORUM_ABS_ADDR, \
    CHIP_KDM_QUORUM_ABS_ADDR + (CHIP_KDM_QUORUM_SIZE / 3U), \
    CHIP_KDM_QUORUM_ABS_ADDR + 2U * (CHIP_KDM_QUORUM_SIZE / 3U) \
}
#endif

#ifndef TOOB_KDM_SLOT_SIZES
#define TOOB_KDM_SLOT_SIZES                      { \
    (CHIP_KDM_QUORUM_SIZE / 3U), \
    (CHIP_KDM_QUORUM_SIZE / 3U), \
    (CHIP_KDM_QUORUM_SIZE / 3U)  \
}
#endif

#ifndef CHIP_STAGE0_BYTE_SIZE
#define CHIP_STAGE0_BYTE_SIZE                    CHIP_STAGE0_SIZE
#endif

#ifndef CHIP_FLASH_IMMUTABLE_BOOT_XIP_END
#define CHIP_FLASH_IMMUTABLE_BOOT_XIP_END        CHIP_FLASH_IMMUTABLE_BOOT_END
#endif

#ifndef BOOT_CRYPTO_ARENA_SIZE
#define BOOT_CRYPTO_ARENA_SIZE                   2048U
#endif
#ifndef BOOT_WDT_TIMEOUT_MS
#define BOOT_WDT_TIMEOUT_MS                      2000U
#endif
#ifndef BOOT_CONFIG_MAX_RETRIES
#define BOOT_CONFIG_MAX_RETRIES                  2U
#endif
#ifndef BOOT_CONFIG_MAX_RECOVERY_RETRIES
#define BOOT_CONFIG_MAX_RECOVERY_RETRIES         5U
#endif
#ifndef BOOT_CONFIG_EDGE_UNATTENDED_MODE
#define BOOT_CONFIG_EDGE_UNATTENDED_MODE         1
#endif
#ifndef BOOT_CONFIG_BACKOFF_BASE_S
#define BOOT_CONFIG_BACKOFF_BASE_S               1U
#endif
#ifndef BOOT_STAGE1_SVN
#define BOOT_STAGE1_SVN                          1U
#endif

#ifndef TOOB_DEVICE_PRODUCT_ID
#define TOOB_DEVICE_PRODUCT_ID                   0x0043U
#endif
#ifndef TOOB_DEVICE_VENDOR_ID
#define TOOB_DEVICE_VENDOR_ID                    0x0001U
#endif
#ifndef TOOB_DEVICE_HW_REV
#define TOOB_DEVICE_HW_REV                       1U
#endif

#ifndef TOOB_TRANSPORT_SWAPSCRATCH
#define TOOB_TRANSPORT_SWAPSCRATCH               1
#define TOOB_TRANSPORT_ONEWAY                    2
#define TOOB_TRANSPORT_SWAPMOVE                  3
#define TOOB_TRANSPORT_POINTER                   4
#define TOOB_TRANSPORT_SWAPOFFSET                5
#endif

#ifndef TOOB_ONEWAY_BACKUP_NONE
#define TOOB_ONEWAY_BACKUP_NONE                  0
#define TOOB_ONEWAY_BACKUP_FULL                  1
#define TOOB_ONEWAY_BACKUP_REVERSE_DELTA         2
#endif

#ifndef TOOB_TRANSPORT_PROVIDER
#define TOOB_TRANSPORT_PROVIDER                  TOOB_TRANSPORT_SWAPSCRATCH
#endif

#ifndef TOOB_ONEWAY_BACKUP_MODE
#define TOOB_ONEWAY_BACKUP_MODE                  TOOB_ONEWAY_BACKUP_FULL
#endif

#ifndef TOOB_PQC_ENABLED
#define TOOB_PQC_ENABLED                         0
#endif

/* Compile-time immutable-boot firewall invariant */
_Static_assert((uint64_t)CHIP_FLASH_IMMUTABLE_BOOT_END >=
                   ((uint64_t)CHIP_STAGE0_ABS_ADDR + (uint64_t)CHIP_STAGE0_SIZE),
               "CHIP_FLASH_IMMUTABLE_BOOT_END must protect Stage 0");

_Static_assert(CHIP_FLASH_WRITE_ALIGNMENT == 1U ||
                   CHIP_FLASH_WRITE_ALIGNMENT == 4U ||
                   CHIP_FLASH_WRITE_ALIGNMENT == 8U ||
                   CHIP_FLASH_WRITE_ALIGNMENT == 32U,
               "CHIP_FLASH_WRITE_ALIGNMENT must be in {1, 4, 8, 32}");

#ifdef CBMC_STAGE0_SRAM_DECL
extern uint8_t g_stage0_sram[320];
#endif

#ifdef CBMC_FORCE_BAREMETAL_RTC
#undef __linux__
#undef _WIN32
#undef __APPLE__
extern volatile uint64_t g_mock_rtc_ram;
#endif

#ifdef CBMC_TRAP_DECL
void cbmc_hardware_trap_halt(void);
#endif

#endif /* GENERATED_BOOT_CONFIG_H */
