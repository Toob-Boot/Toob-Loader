/**
 * ==============================================================================
 * Toob-Boot libtoob_config_sandbox.h (Mock Generiert Phase 3)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * - docs/dev_plan.md (Mandates a Phase 3 mock header for sandbox tests)
 * - docs/toobfuzzer_integration.md (Blueprint mapping for flash offsets and limits)
 * - docs/sandbox_setup.md (POSIX mapping limitations for the test environment)
 *
 * Temporärer Header zur Bereitstellung fiktiver Adressen für Phase 3 M-SANDBOX Tests.
 */

#ifndef LIBTOOB_CONFIG_SANDBOX_H
#define LIBTOOB_CONFIG_SANDBOX_H

#include <stdint.h>

/* M-SANDBOX Fuzzer Mock Values 
 * (In Produktion werden diese durch den Manifest Compiler injiziert) */
/* ==============================================================================
 * 2. Flash Memory Map (Asymmetric Flash Support)
 * ==============================================================================
 *
 * Um asymmetrische Flash-Architekturen (STM32, ESP32) nativ zu unterstützen,
 * generiert der Manifest_Compiler hier feste Sektor-Adressen, statt von einer
 * globalen Blockgröße auszugehen. Die OS-Seite (libtoob) nutzt nur Target-Nodes.
 */
#define CHIP_WAL_SECTORS 4
#define TOOB_WAL_SECTOR_ADDRS {0x4000, 0x5000, 0x6000, 0x10000}
#define TOOB_WAL_SECTOR_SIZES {4096,   4096,   4096,   16384}

#define CHIP_FLASH_WRITE_ALIGN 8
#define CHIP_FLASH_MAX_SECTOR_SIZE 16384
#define CHIP_FLASH_ERASURE_MAPPING 0xFFFFFFFF

/* Steering Macros (gem. TODO Spezifikation)
 * 1: TOOB_MOCK_CONFIRM_BACKEND_RTC
 * 2: TOOB_MOCK_CONFIRM_BACKEND_WAL
 */
#define TOOB_MOCK_CONFIRM_BACKEND_RTC 1
#define TOOB_MOCK_CONFIRM_BACKEND_WAL 2

#define TOOB_MOCK_CONFIRM_BACKEND TOOB_MOCK_CONFIRM_BACKEND_RTC

#if TOOB_MOCK_CONFIRM_BACKEND == TOOB_MOCK_CONFIRM_BACKEND_RTC
    /* Fake pointer for RTC testing in Host-Sandbox */
    extern uint64_t mock_rtc_ram;
    #define ADDR_CONFIRM_RTC_RAM ((volatile uint64_t*)(&mock_rtc_ram))
#endif

/* Cloud-Command Envelope Slot (1 Sektor, Bootloader evaluiert bei jedem Boot) */
#define TOOB_CLOUD_CMD_SLOT_ADDR  0x000F0000
#define TOOB_CLOUD_CMD_SLOT_SIZE  0x1000

/* KDM Quorum Store (Phase 4: 3 sectors for quorum-protected KDM) */
#define TOOB_KDM_QUORUM_ADDR     0x000F1000
#define TOOB_KDM_QUORUM_SIZE     0x3000

/* OS→Core Mailbox (2 sectors, Double-Slot: 2×SectorSize, torn-write safe) */
#define CHIP_MAILBOX_ABS_ADDR    0x000F4000
#define CHIP_MAILBOX_SLOT_SIZE   0x1000
#define CHIP_MAILBOX_SIZE        0x2000

#endif /* LIBTOOB_CONFIG_SANDBOX_H */
