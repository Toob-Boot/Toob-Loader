#ifndef BOOT_CONFIG_MOCK_H
#define BOOT_CONFIG_MOCK_H

/* Temporäre Phase 1-3 Mock-Konfiguration bis der Manifest-Compiler fertig ist */
#define TOOB_WAL_BASE_ADDR 0x000F0000
#define TOOB_WAL_SECTORS   4

/* FIX (Doublecheck): Missing Addresses for App Slot A & Recovery OS */
#define CHIP_APP_SLOT_ABS_ADDR    0x00010000 
#define CHIP_RECOVERY_OS_ABS_ADDR 0x000B0000

/* 
 * TODO (Phase 3.1): Kläre die endgültige physikalische Eigentümerschaft 
 * der crypto_arena. Sollte idealerweise via Linker-Script (flash_layout.ld) 
 * an das RAM-Ende gebunden werden (ohne statische Initialisierung).
 * Hier vorerst gemockt:
 */
#ifndef BOOT_CRYPTO_ARENA_SIZE
#define BOOT_CRYPTO_ARENA_SIZE 2048 /* Mock: Für Monocypher (~2KB) */
#endif

#include <stdint.h>
extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

#endif /* BOOT_CONFIG_MOCK_H */
