/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Watchdog Implementation
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS & GAPS:
 * 
 * 1. docs/hals.md
 *    - Parameter Padding (GAP-F22): Muss den maximalen Watchdog Timeout sauber runden und
 *      Fehler schmeißen, wenn der C-Logik-Prescaler den Pseudo-Hardware-Teiler übersteigt.
 * 
 * 2. docs/concept_fusion.md
 *    - WDT Prescaler / Brownout Loops: Der Watchdog MUSS strikt nachverfolgen, 
 *      wie viele ms zwischen den `kick()` Aufrufen verstreichen. Im Integration-Test
 *      muss die Sandbox bei Nichteinhaltung hart abstürzen (`exit(1)` oder sigabrt),
 *      um hängende Endlosschleifen der Boot-Logik in CI abzufangen.
 */

#include "mock_wdt.h"
#include "chip_config.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <unistd.h>
#endif

#ifndef TIMING_SAFETY_FACTOR
#define TIMING_SAFETY_FACTOR 2
#endif

static clock_t last_kick_clock = 0;
static uint32_t current_timeout_ms = 0;
static bool is_active = false;
static bool is_suspended = false;
static uint32_t total_kicks = 0;

static void wdt_arm_async_alarm(uint32_t ms_timeout) {
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    /* GAP-F21: Setze einen harten Kernel-Ebene Timeout als Defense-in-Depth
     * für den Fall, dass die C-Logik komplett hängt und kick() nie ruft. */
    if (ms_timeout == 0) {
        alarm(0);
    } else {
        uint32_t sec = (ms_timeout / 1000) + 2; /* 2 Sekunden Marge für OS-Scheduling */
        alarm(sec);
    }
#endif
}

static boot_status_t mock_wdt_init(uint32_t timeout_ms_required) {
    /* GAP-F22: Hardware Prescaler Abstraktion. 
     * In Sandbox emulieren wir, dass der Watchdog maximal BOOT_WDT_TIMEOUT_MS kann.
     * Wenn der C-Core mehr verlangt, schlagen wir fehl. */
#ifdef BOOT_WDT_TIMEOUT_MS
    if (timeout_ms_required > BOOT_WDT_TIMEOUT_MS) {
        return BOOT_ERR_INVALID_PARAM;
    }
#endif

    /* Phase 6 Policy: Padding-Application für den Hardware-Prescaler.
     * Zwingt M-SANDBOX, dem Hardware-Standard aus boot_hal.h zu entsprechen. */
    current_timeout_ms = timeout_ms_required * TIMING_SAFETY_FACTOR;

    last_kick_clock = clock();
    is_active = true;
    is_suspended = false;
    
    wdt_arm_async_alarm(current_timeout_ms);
    return BOOT_OK;
}

static void mock_wdt_deinit(void) {
    wdt_arm_async_alarm(0);
    is_active = false;
    is_suspended = false;
}

static void mock_wdt_kick(void) {
    if (!is_active || is_suspended) {
        return;
    }

    clock_t now = clock();
    
    /* P10 COMPLIANCE: 64-Bit Integer Math (Kein Floating Point!)
     * Die Latenzmessung rechnet in ms auf deterministischer CPU-Taktbasis. */
    uint32_t elapsed_ms = (uint32_t)(((uint64_t)(now - last_kick_clock) * 1000ULL) / CLOCKS_PER_SEC);

    if (elapsed_ms > current_timeout_ms) {
        fprintf(stderr, "\n[M-SANDBOX FATAL] WATCHDOG TRIGGERED!\n");
        fprintf(stderr, "-> Zeit seit letztem Kick: %u ms\n", elapsed_ms);
        fprintf(stderr, "-> Erlaubter Timeout:      %u ms\n", current_timeout_ms);
        fprintf(stderr, "-> Test-Environment stoppt Ausführung (simulierter PANIC Reset).\n\n");
        fflush(stderr);
        abort();
    }

    last_kick_clock = now;
    total_kicks++;
    wdt_arm_async_alarm(current_timeout_ms);
}

static void mock_wdt_suspend_for_critical_section(void) {
    if (!is_active) return;
    
    /* P10 Defense-in-Depth: Vor dem Suspend muss evaluiert werden, 
       ob der Watchdog nicht ohnehin schon abgelaufen wäre! */
    mock_wdt_kick();
    
    wdt_arm_async_alarm(0); /* OS-Alarm temporär aussetzen */
    is_suspended = true;
}

static void mock_wdt_resume(void) {
    if (!is_active) return;
    
    /* Reset Timer, damit die Suspension-Zeit nicht als Latenz zählt */
    last_kick_clock = clock();
    is_suspended = false;
    wdt_arm_async_alarm(current_timeout_ms);
}

/* --- Export Utilities --- */

uint32_t mock_wdt_get_kick_count(void) {
    return total_kicks;
}

void mock_wdt_reset_state(void) {
    is_active = false;
    is_suspended = false;
    total_kicks = 0;
    last_kick_clock = 0;
    current_timeout_ms = 0;
}

/* --- Trait Export --- */

const wdt_hal_t sandbox_wdt_hal = {
    .abi_version = 0x01000000,
    .init = mock_wdt_init,
    .deinit = mock_wdt_deinit,
    .kick = mock_wdt_kick,
    .suspend_for_critical_section = mock_wdt_suspend_for_critical_section,
    .resume = mock_wdt_resume
};
