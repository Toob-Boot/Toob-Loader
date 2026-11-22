/*
 * Formal Verification Partition Layout for Toob-Loader CBMC Suite (Wave 5A).
 *
 * Supports two deterministic flash sector geometries via CBMC_ASYMMETRIC_SECTORS:
 *   0 (default): Homogeneous 4 KB NOR sectors (ESP32-C3 / RP2040 / nRF52840 class)
 *   1          : Asymmetric 16 KB / 64 KB / 128 KB Dual-Bank sectors (STM32F429 class)
 *
 * Every macro is #ifndef-guarded so individual proof harnesses or CLI -D flags
 * can specialize slot sizes or sector addresses without duplicating layout headers.
 */
#ifndef BOOT_LAYOUT_H
#define BOOT_LAYOUT_H

#ifndef CBMC_ASYMMETRIC_SECTORS
#define CBMC_ASYMMETRIC_SECTORS 0
#endif

#if CBMC_ASYMMETRIC_SECTORS == 0

/* ==========================================================================
 * Mode 0: Homogeneous 4 KB Sector Geometry (1 MB Total Flash)
 * ========================================================================== */

#ifndef CHIP_STAGE0_ABS_ADDR
#define CHIP_STAGE0_ABS_ADDR                     0x00000000U
#endif
#ifndef CHIP_STAGE0_SIZE
#define CHIP_STAGE0_SIZE                         0x00008000U
#endif

#ifndef CHIP_STAGE1A_ABS_ADDR
#define CHIP_STAGE1A_ABS_ADDR                    0x00008000U
#endif
#ifndef CHIP_STAGE1A_SIZE
#define CHIP_STAGE1A_SIZE                        0x00010000U
#endif

#ifndef CHIP_STAGE1B_ABS_ADDR
#define CHIP_STAGE1B_ABS_ADDR                    0x00018000U
#endif
#ifndef CHIP_STAGE1B_SIZE
#define CHIP_STAGE1B_SIZE                        0x00010000U
#endif

#ifndef CHIP_APP_SLOT_ABS_ADDR
#define CHIP_APP_SLOT_ABS_ADDR                   0x00028000U
#endif
#ifndef CHIP_APP_SLOT_SIZE
#define CHIP_APP_SLOT_SIZE                       0x00010000U
#endif

#ifndef CHIP_STAGING_SLOT_ABS_ADDR
#define CHIP_STAGING_SLOT_ABS_ADDR               0x00038000U
#endif
#ifndef CHIP_STAGING_SLOT_SIZE
#define CHIP_STAGING_SLOT_SIZE                   0x00010000U
#endif

#ifndef CHIP_SCRATCH_SLOT_ABS_ADDR
#define CHIP_SCRATCH_SLOT_ABS_ADDR               0x00048000U
#endif
#ifndef CHIP_SCRATCH_SLOT_SIZE
#define CHIP_SCRATCH_SLOT_SIZE                   0x00004000U
#endif

#ifndef CHIP_RECOVERY_OS_ABS_ADDR
#define CHIP_RECOVERY_OS_ABS_ADDR                0x0004C000U
#endif
#ifndef CHIP_RECOVERY_OS_SIZE
#define CHIP_RECOVERY_OS_SIZE                    0x00010000U
#endif

#ifndef CHIP_NETCORE_SLOT_ABS_ADDR
#define CHIP_NETCORE_SLOT_ABS_ADDR               0x00000000U
#endif
#ifndef CHIP_NETCORE_SLOT_SIZE
#define CHIP_NETCORE_SLOT_SIZE                   0x00000000U
#endif

#ifndef CHIP_WAL_ABS_ADDR
#define CHIP_WAL_ABS_ADDR                        0x0005C000U
#endif
#ifndef CHIP_WAL_SIZE
#define CHIP_WAL_SIZE                            0x00004000U
#endif
#ifndef CHIP_WAL_SECTOR_0_ADDR
#define CHIP_WAL_SECTOR_0_ADDR                   0x0005C000U
#define CHIP_WAL_SECTOR_0_SIZE                   0x00001000U
#define CHIP_WAL_SECTOR_1_ADDR                   0x0005D000U
#define CHIP_WAL_SECTOR_1_SIZE                   0x00001000U
#define CHIP_WAL_SECTOR_2_ADDR                   0x0005E000U
#define CHIP_WAL_SECTOR_2_SIZE                   0x00001000U
#define CHIP_WAL_SECTOR_3_ADDR                   0x0005F000U
#define CHIP_WAL_SECTOR_3_SIZE                   0x00001000U
#endif

#ifndef CHIP_KDM_QUORUM_ABS_ADDR
#define CHIP_KDM_QUORUM_ABS_ADDR                 0x00060000U
#endif
#ifndef CHIP_KDM_QUORUM_SIZE
#define CHIP_KDM_QUORUM_SIZE                     0x00003000U
#endif

#ifndef CHIP_CLOUD_CMD_SLOT_ABS_ADDR
#define CHIP_CLOUD_CMD_SLOT_ABS_ADDR             0x00063000U
#endif
#ifndef CHIP_CLOUD_CMD_SLOT_SIZE
#define CHIP_CLOUD_CMD_SLOT_SIZE                 0x00001000U
#endif

#ifndef CHIP_MAILBOX_ABS_ADDR
#define CHIP_MAILBOX_ABS_ADDR                    0x00064000U
#endif
#ifndef CHIP_MAILBOX_SIZE
#define CHIP_MAILBOX_SIZE                        0x00002000U
#endif
#ifndef CHIP_MAILBOX_SLOT_SIZE
#define CHIP_MAILBOX_SLOT_SIZE                   0x00001000U
#endif

#ifndef CHIP_FORENSIC_SLOT_ABS_ADDR
#define CHIP_FORENSIC_SLOT_ABS_ADDR              0x00066000U
#endif
#ifndef CHIP_FORENSIC_SLOT_SIZE
#define CHIP_FORENSIC_SLOT_SIZE                  0x00001000U
#endif

#ifndef CHIP_FLASH_IMMUTABLE_BOOT_END
#define CHIP_FLASH_IMMUTABLE_BOOT_END            0x00008000U
#endif

#else /* CBMC_ASYMMETRIC_SECTORS != 0 */

/* ==========================================================================
 * Mode 1: Asymmetric Dual-Bank 16 KB / 64 KB / 128 KB Sector Geometry (2 MB)
 *
 * Both Bank 1 [0x00000000, 0x00100000) and Bank 2 [0x00100000, 0x00200000)
 * follow the STM32F429 physical sector map:
 *   +0x000000 .. +0x010000 : 4 x 16 KB (0x04000)
 *   +0x010000 .. +0x020000 : 1 x 64 KB (0x10000)
 *   +0x020000 .. +0x100000 : 7 x 128 KB (0x20000)
 *
 * App Slot and Staging Slot each span [16 KB + 64 KB + 128 KB] = 208 KB so
 * every multi-sector operation traverses all three sector sizes.
 * ========================================================================== */

#ifndef CHIP_STAGE0_ABS_ADDR
#define CHIP_STAGE0_ABS_ADDR                     0x00000000U
#endif
#ifndef CHIP_STAGE0_SIZE
#define CHIP_STAGE0_SIZE                         0x00004000U
#endif

#ifndef CHIP_WAL_ABS_ADDR
#define CHIP_WAL_ABS_ADDR                        0x00004000U
#endif
#ifndef CHIP_WAL_SIZE
#define CHIP_WAL_SIZE                            0x00008000U
#endif
#ifndef CHIP_WAL_SECTOR_0_ADDR
#define CHIP_WAL_SECTOR_0_ADDR                   0x00004000U
#define CHIP_WAL_SECTOR_0_SIZE                   0x00004000U
#define CHIP_WAL_SECTOR_1_ADDR                   0x00008000U
#define CHIP_WAL_SECTOR_1_SIZE                   0x00004000U
#define CHIP_WAL_SECTOR_2_ADDR                   0x00140000U
#define CHIP_WAL_SECTOR_2_SIZE                   0x00020000U
#define CHIP_WAL_SECTOR_3_ADDR                   0x00160000U
#define CHIP_WAL_SECTOR_3_SIZE                   0x00020000U
#endif

#ifndef CHIP_STAGING_SLOT_ABS_ADDR
#define CHIP_STAGING_SLOT_ABS_ADDR               0x0000C000U
#endif
#ifndef CHIP_STAGING_SLOT_SIZE
#define CHIP_STAGING_SLOT_SIZE                   0x00034000U
#endif

#ifndef CHIP_SCRATCH_SLOT_ABS_ADDR
#define CHIP_SCRATCH_SLOT_ABS_ADDR               0x00040000U
#endif
#ifndef CHIP_SCRATCH_SLOT_SIZE
#define CHIP_SCRATCH_SLOT_SIZE                   0x00020000U
#endif

#ifndef CHIP_KDM_QUORUM_ABS_ADDR
#define CHIP_KDM_QUORUM_ABS_ADDR                 0x00060000U
#endif
#ifndef CHIP_KDM_QUORUM_SIZE
#define CHIP_KDM_QUORUM_SIZE                     0x00060000U
#endif

#ifndef CHIP_STAGE1A_ABS_ADDR
#define CHIP_STAGE1A_ABS_ADDR                    0x000C0000U
#endif
#ifndef CHIP_STAGE1A_SIZE
#define CHIP_STAGE1A_SIZE                        0x00020000U
#endif

#ifndef CHIP_STAGE1B_ABS_ADDR
#define CHIP_STAGE1B_ABS_ADDR                    0x000E0000U
#endif
#ifndef CHIP_STAGE1B_SIZE
#define CHIP_STAGE1B_SIZE                        0x00020000U
#endif

#ifndef CHIP_MAILBOX_ABS_ADDR
#define CHIP_MAILBOX_ABS_ADDR                    0x00100000U
#endif
#ifndef CHIP_MAILBOX_SIZE
#define CHIP_MAILBOX_SIZE                        0x00008000U
#endif
#ifndef CHIP_MAILBOX_SLOT_SIZE
#define CHIP_MAILBOX_SLOT_SIZE                   0x00004000U
#endif

#ifndef CHIP_CLOUD_CMD_SLOT_ABS_ADDR
#define CHIP_CLOUD_CMD_SLOT_ABS_ADDR             0x00108000U
#endif
#ifndef CHIP_CLOUD_CMD_SLOT_SIZE
#define CHIP_CLOUD_CMD_SLOT_SIZE                 0x00004000U
#endif

#ifndef CHIP_APP_SLOT_ABS_ADDR
#define CHIP_APP_SLOT_ABS_ADDR                   0x0010C000U
#endif
#ifndef CHIP_APP_SLOT_SIZE
#define CHIP_APP_SLOT_SIZE                       0x00034000U
#endif

#ifndef CHIP_RECOVERY_OS_ABS_ADDR
#define CHIP_RECOVERY_OS_ABS_ADDR                0x00180000U
#endif
#ifndef CHIP_RECOVERY_OS_SIZE
#define CHIP_RECOVERY_OS_SIZE                    0x00020000U
#endif

#ifndef CHIP_FORENSIC_SLOT_ABS_ADDR
#define CHIP_FORENSIC_SLOT_ABS_ADDR              0x001A0000U
#endif
#ifndef CHIP_FORENSIC_SLOT_SIZE
#define CHIP_FORENSIC_SLOT_SIZE                  0x00020000U
#endif

#ifndef CHIP_NETCORE_SLOT_ABS_ADDR
#define CHIP_NETCORE_SLOT_ABS_ADDR               0x00000000U
#endif
#ifndef CHIP_NETCORE_SLOT_SIZE
#define CHIP_NETCORE_SLOT_SIZE                   0x00000000U
#endif

#ifndef CHIP_FLASH_IMMUTABLE_BOOT_END
#define CHIP_FLASH_IMMUTABLE_BOOT_END            0x00004000U
#endif

#endif /* CBMC_ASYMMETRIC_SECTORS */

#endif /* BOOT_LAYOUT_H */
