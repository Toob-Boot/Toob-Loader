/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: SoC HAL Mock Implementation
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * 1. docs/hals.md -> soc_hal_t
 * 2. docs/concept_fusion.md -> Brownout-Penalties & Low-Power
 */

#include "mock_soc.h"
#include "mock_clock.h"
#include "chip_fault_inject.h"
#include "chip_config.h"
#include <stdio.h>
#include <stdlib.h>

static boot_status_t mock_soc_init(void) {
    fault_inject_init();
    return BOOT_OK; /* Keine physischen ADC Busse zum Vorbereiten */
}

static uint32_t mock_soc_battery_level_mv(void) {
    /* 
     * Liest die deterministisch konfigurierte Batterie-Spannung.
     * Repräsentiert die Spannung "unter Dummy-Load" (siehe docs/hals.md).
     */
    return g_fault_config.battery_level_mv;
}

static bool mock_soc_can_sustain_update(void) {
    /*
     * P10 Konform: Die Grenze wird nicht hardcodiert, sondern aus
     * den generierten device.toml Metadaten (CHIP_MIN_BATTERY_MV) geladen!
     * Die Architekturspezifikation fordert einen Reject bei zu kleinem Akku.
     * Darunter verweigern wir den Update-Puls, um plötzlichen Flash-Corruption
     * Brownouts beim massiven NAND-Erase auszuweichen!
     */
    return (mock_soc_battery_level_mv() >= CHIP_MIN_BATTERY_MV);
}

static void mock_soc_enter_low_power(uint32_t wakeup_s) {
    /*
     * P10 HIL-Simulation (Host-in-the-Loop):
     * Anstatt das PC-Executable sofort via exit(0) zu beenden (was Python-Runner 
     * verwirrt), simulieren wir harten C-System-Halt durch atomare Sleeps.
     * 
     * Das zwingt den Fuzzer in legitime PyTest Timeouts und erlaubt es dem 
     * Hintergrund-WDT Threads (z.B. in boot_panic.c) weiterhin authentisch zu feuern!
     */
    if (wakeup_s == 0) {
        /* Absoluter Brownout: CPU stoppt endlos bis extern ein Hardware Reset kommt */
        while (1) {
            sandbox_clock_hal.delay_ms(10000);
        }
    } else {
        /* Edge-Recovery Exponential Backoff (1h, 4h, 12h...) */
        uint32_t target_ms = wakeup_s * 1000;
        sandbox_clock_hal.delay_ms(target_ms);
        /* 
         * P10 Hard-Reset Security!
         * Laut Spec löst das Aufwachen aus dem Deep-Sleep zwingend einen 
         * asynchronen Hard-Reset aus. Wir blockieren hier den PC-State strikt
         * mit einer Endlosschleife, bis der Fuzzer/WDT das Binary abschießt!
         */
        while(1) {
            sandbox_clock_hal.delay_ms(10000);
        }
    }
}

static void mock_soc_assert_secondary_cores_reset(void) {
    /* 
     * Für die PC-Host Sandbox existieren keine Cortex-M0+ Secondary Radio-Cores.
     * Auf echten Multi-Core Targets wie dem nRF5340 hält S1 hier die Neben-Cores 
     * im rigorosen Hardware-Reset-Lockdown. Im Mock sicher als No-Op abgehakt!
     */
}

static void mock_soc_flush_bus_matrix(void) {
    /* 
     * P10-Bounded-Loop Implementierung für Matrix-Flush (max 5.000 Zyklen).
     * Auf dem Host-PC (Sandbox) ist das eigentlich Traffic-los, die Schleife beweist 
     * aber absolute P10-Konformität (Verhinderung von blockierten DMAs).
     */
    volatile uint32_t escape_counter = 0;
    while (escape_counter < 5000) {
        escape_counter++;
    }
}

static void mock_soc_deinit(void) {
    /* Peripherie-Trenner, im PC Leer-Stub */
}

void mock_soc_reset_state(void) {
    /* Keine State-Leaks vorhanden, der Mock ist komplett statusfrei */
}

const soc_hal_t sandbox_soc_hal = {
    .abi_version                  = 0x01000000,
    .init                         = mock_soc_init,
    .battery_level_mv             = mock_soc_battery_level_mv,
    .can_sustain_update           = mock_soc_can_sustain_update,
    .enter_low_power              = mock_soc_enter_low_power,
    .assert_secondary_cores_reset = mock_soc_assert_secondary_cores_reset,
    .flush_bus_matrix             = mock_soc_flush_bus_matrix,
    .deinit                       = mock_soc_deinit
};
