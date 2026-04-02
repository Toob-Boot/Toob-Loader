/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Watchdog Implementation
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS & GAPS:
 * 1. docs/hals.md -> wdt_hal_t
 * 2. docs/concept_fusion.md -> Timer Kick Tracking
 * 3. docs/testing_requirements.md -> Deterministic Execution
 */

#include "mock_wdt.h"
#include "mock_clock.h"
#include "chip_fault_inject.h"
#include "chip_config.h"
#include <stdio.h>
#include <stdlib.h>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <unistd.h>
#endif

#ifndef TIMING_SAFETY_FACTOR
#define TIMING_SAFETY_FACTOR 2
#endif

static uint32_t last_kick_tick = 0;
static uint32_t current_timeout_ms = 0;
static bool is_active = false;
static bool is_suspended = false;
static uint32_t total_kicks = 0;

static void wdt_arm_async_alarm(uint32_t ms_timeout) {
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    /* GAP-F21: Setze einen harten Kernel-Ebene Timeout als Defense-in-Depth
     * für den Fall, dass die C-Logik aus dem P10 O(1) Limit bricht und in einer 
     * Endlosschleife hängt, die niemals M-CLOCK.get_tick_ms abfragt. */
    if (ms_timeout == 0) {
        alarm(0);
    } else {
        uint32_t sec = (ms_timeout / 1000) + 2; 
        alarm(sec);
    }
#endif
}

static boot_status_t mock_wdt_init(uint32_t timeout_ms_required) {
    fault_inject_init(); /* Sicherheitshalber ENV Config laden */

#ifdef BOOT_WDT_TIMEOUT_MS
    if (timeout_ms_required > BOOT_WDT_TIMEOUT_MS) {
        return BOOT_ERR_INVALID_ARG;
    }
#endif

    current_timeout_ms = timeout_ms_required * TIMING_SAFETY_FACTOR;

    last_kick_tick = sandbox_clock_hal.get_tick_ms();
    is_active = true;
    is_suspended = false;
    
    wdt_arm_async_alarm(current_timeout_ms);
    return BOOT_OK;
}

static void mock_wdt_deinit(void) {
    if (g_fault_config.wdt_disable_forbidden) {
        fprintf(stderr, "\n[M-SANDBOX FATAL] nRF52 WDT-LOCK VIOLATION!\n");
        fprintf(stderr, "-> Versuchter Aufruf von wdt_hal.deinit(), aber Config blockiert dies!\n\n");
        fflush(stderr);
        abort();
    }

    wdt_arm_async_alarm(0);
    is_active = false;
    is_suspended = false;
}

static void mock_wdt_kick(void) {
    if (!is_active || is_suspended) {
        return;
    }

    uint32_t now = sandbox_clock_hal.get_tick_ms();
    
    /* P10 COMPLIANCE: 32-Bit Unsigned Math.
       Rollover-sicher durch Modulo-Arithmetik (now - last). */
    uint32_t elapsed_ms = now - last_kick_tick;

    if (elapsed_ms > current_timeout_ms) {
        fprintf(stderr, "\n[M-SANDBOX FATAL] WATCHDOG TRIGGERED!\n");
        fprintf(stderr, "-> Zeit seit letztem Kick: %u ms\n", elapsed_ms);
        fprintf(stderr, "-> Erlaubter Timeout:      %u ms\n", current_timeout_ms);
        fprintf(stderr, "-> Test-Environment stoppt Ausführung (simulierter PANIC Reset).\n\n");
        fflush(stderr);
        abort();
    }

    last_kick_tick = now;
    total_kicks++;
    wdt_arm_async_alarm(current_timeout_ms);
}

static void mock_wdt_suspend_for_critical_section(void) {
    if (!is_active) return;
    
    mock_wdt_kick();
    
    wdt_arm_async_alarm(0); /* OS-Alarm temporär aussetzen */
    is_suspended = true;
}

static void mock_wdt_resume(void) {
    if (!is_active) return;
    
    last_kick_tick = sandbox_clock_hal.get_tick_ms();
    is_suspended = false;
    wdt_arm_async_alarm(current_timeout_ms);
}

/* --- Export Utilities --- */

uint32_t mock_wdt_get_kick_count(void) {
    return total_kicks;
}

void mock_wdt_reset_state(void) {
    wdt_arm_async_alarm(0); /* OS-Alarm abwürgen, um Leak zu vermeiden */
    is_active = false;
    is_suspended = false;
    total_kicks = 0;
    last_kick_tick = 0;
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
