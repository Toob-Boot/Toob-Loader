#ifndef INVARIANTS_H
#define INVARIANTS_H

#include "boot_hal.h"
#include "boot_state.h"

/**
 * @brief Führt alle Sicherheits-Invarianten nach einem Reboot aus.
 * @param plat Die Platform-HAL Instanz.
 * @param target_cfg Die vom Bootloader ermittelte OS Handoff Konfiguration.
 * @param boot_status Der Statuscode, den boot_state_run zurückgegeben hat.
 */
void assert_invariants(const boot_platform_t *plat, const boot_target_config_t *target_cfg, boot_status_t boot_status);

#endif /* INVARIANTS_H */
