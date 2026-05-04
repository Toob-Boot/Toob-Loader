#ifndef BOOT_MAIN_H
#define BOOT_MAIN_H

#include "boot_hal.h"
#include "boot_state.h"

/**
 * @brief Bootloader Main Orchestrator
 *
 * Verwaltet die vollständige Lifecycle-Init/Deinit Kaskade und ruft
 * die transaktionale State-Machine auf.
 *
 * @param platform Die mit Hardware-Pointern gefüllte Struct (Erstellt von boot_platform_init())
 * @param target_out Die zu befüllende Execution-Konfiguration (Entry Vector, Size, Nonce)
 * @return BOOT_OK wenn erfolgeich. Das Vendor-spezifische Startup-Skript (Assembly/C) 
 *         wertet target_out aus und triggert den physischen PC-Jump.
 */
boot_status_t boot_main(const boot_platform_t *platform, boot_target_config_t *target_out);

#endif /* BOOT_MAIN_H */
