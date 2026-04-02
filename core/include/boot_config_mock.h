#ifndef BOOT_CONFIG_MOCK_H
#define BOOT_CONFIG_MOCK_H

/* Temporäre Phase 1-3 Mock-Konfiguration bis der Manifest-Compiler fertig ist */
#define TOOB_WAL_BASE_ADDR 0x000F0000
#define TOOB_WAL_SECTORS   4

/* FIX (Doublecheck): Missing Addresses for App Slot A & Recovery OS */
#define CHIP_APP_SLOT_ABS_ADDR    0x00010000 
#define CHIP_RECOVERY_OS_ABS_ADDR 0x000B0000

#endif /* BOOT_CONFIG_MOCK_H */
