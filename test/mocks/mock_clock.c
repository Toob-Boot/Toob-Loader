/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Clock Mock Implementation
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * 1. docs/hals.md -> clock_hal_t
 * 2. docs/testing_requirements.md -> Deterministic Execution
 */

#include "mock_clock.h"
#include "chip_fault_inject.h"
#include <stdlib.h>
#include <stdio.h>

static uint32_t current_tick_ms = 0;
static reset_reason_t current_reset_reason = RESET_REASON_POWER_ON;

static boot_status_t mock_clock_init(void) {
    /* Architekturgetreue L1-Isolation: Reset Reason kommt vom globalen Emulator */
    fault_inject_init(); /* Redundant/Safe falls in anderen Mocks schon gerufen. Parst ENV. */
    
    uint32_t sim_val = g_fault_config.simulated_reset_reason;
    if (sim_val > 6) {
        fprintf(stderr, "\n[M-SANDBOX FATAL] TOOB_RESET_REASON is %u, but must be 0-6!\n\n", sim_val);
        fflush(stderr);
        abort();
    }
    
    current_reset_reason = (reset_reason_t)sim_val;
    return BOOT_OK;
}

static void mock_clock_deinit(void) {
    /* Keinerlei Hardware-Timer zu stoppen. */
}

static uint32_t mock_clock_get_tick_ms(void) {
    uint32_t ret = current_tick_ms;
    
    /* Determinismus-Trick (Deadlock Prevention):
     * Wir addieren pro Abfrage durch den C-Core exakt 1ms auf die Uhrzeit.
     * So entkommen wir Endlosschleifen wie "while(get_tick_ms() < timeout)" 
     * garantiert und rein deterministisch basierend auf O(n) Ausführungen! */
    current_tick_ms += 1;
    
    return ret;
}

static void mock_clock_delay_ms(uint32_t ms) {
    /* Flug durch die Zeit. Wir blockieren NICHT den POSIX-Thread!
     * So können wir Watchdog-Stalls in Nanosekunden Host-Laufzeit emulieren. */
    current_tick_ms += ms;
}

static reset_reason_t mock_clock_get_reset_reason(void) {
    /* Idempotenz (Caching Pflicht): Die Spec in hals.md Zeile 525 fordert, 
     * dass Hardware-Clear Bits nicht mehrfach getriggert werden.
     * Durch Returning der statischen `current_reset_reason` erfüllt der Mock diese
     * P10 Idempotenz-Pflicht systembedingt bereits in Perfektion. */
    return current_reset_reason;
}

/* --- Test-Runner Injection Utilities --- */

void mock_clock_set_tick(uint32_t exact_ms) {
    current_tick_ms = exact_ms;
}

void mock_clock_set_reset_reason(reset_reason_t reason) {
    current_reset_reason = reason;
}

void mock_clock_reset_to_factory(void) {
    current_tick_ms = 0;
    current_reset_reason = RESET_REASON_POWER_ON;
}

/* --- Trait Export --- */

const clock_hal_t sandbox_clock_hal = {
    .abi_version = 0x01000000,
    .init = mock_clock_init,
    .deinit = mock_clock_deinit,
    .get_tick_ms = mock_clock_get_tick_ms,
    .delay_ms = mock_clock_delay_ms,
    .get_reset_reason = mock_clock_get_reset_reason
};
