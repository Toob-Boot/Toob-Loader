/*
 * ==============================================================================
 * Toob-Boot Core File: boot_delay.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/hals.md (Watchdog timeout during delay, Hardware Abstracted Clocks)
 * - docs/testing_requirements.md (Fault Injection / EMFI Resistance)
 * - docs/stage_1_5_spec.md (Brute-Force Penalty Enforcement)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Time-Warp Attack Shield: Verhindert das gewaltsame Überspringen der
 *    Verzögerungsschleife durch Voltage/Clock-Glitches. Zu große Zeitsprünge
 *    werden algorithmisch gekappt (Hardware-Timer Manipulation).
 * 2. Dual-Track Monotonicity: Führt einen logischen und physikalischen
 *    Zeit-Akkumulator. Verhindert Deadlocks durch defekte Timer-Register und
 *    überführt Instruction-Skips (Überspringen von delay_ms) in einen sicheren
 * Halt.
 * 3. ALU Dual-Accumulator Shield: Der Software-Zähler ist doppelt und invers
 *    ausgeführt. Bit-Flips in den Registern werden mathematisch sofort erkannt.
 * 4. Algebraic Overflow Proof: Die Obergrenze wird auf UINT32_MAX / 8
 * limitiert, was Integer-Wraparounds in der Fail-Safe-Berechnung unmöglich
 * macht.
 * 5. WDT Starvation Trap: Ein erkannter Zeit-Manipulationsangriff führt nicht
 *    zu einer Error-Propagation (Fail-Open), sondern zum absichtlichen
 * Einfrieren der CPU, bis der Hardware-Watchdog das System hart zurücksetzt.
 */

#include "boot_delay.h"
#include "boot_fih.h"
#include "boot_panic.h"
#include "boot_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifndef BOOT_DELAY_TOLERANCE_MULTIPLIER
#define BOOT_DELAY_TOLERANCE_MULTIPLIER 8
#endif

/* Mathematisches Glitch-Resistenz-Gating */
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK muss zwingend ein High-Hamming-Weight Pattern sein!");

boot_status_t boot_delay_with_wdt(const boot_platform_t *platform,
                                  uint32_t ms) {
  /* ====================================================================
   * 1. P10 POINTER & HAL CAPABILITY GATING
   * ==================================================================== */
  if (!platform || !platform->clock) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (!platform->clock->get_tick_ms || !platform->clock->delay_ms) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* O(1) Zero-Delay Fast-Path */
  if (ms == 0) {
    return BOOT_OK;
  }

  /* ====================================================================
   * 2. ALGEBRAIC BOUNDS PROOF (Overflow Prevention)
   * ====================================================================
   * max_sw_limit = target_ms * MULTIPLIER + 1001.
   * To guarantee no 32-bit wrap: target_ms <= (UINT32_MAX - 1001) / MULTIPLIER.
   * With MULTIPLIER=8: cap = 536870786, max_sw_limit = 4294966289 < UINT32_MAX.
   */
  uint32_t target_ms = ms;
  const uint32_t safe_cap = (UINT32_MAX - 1001U) / BOOT_DELAY_TOLERANCE_MULTIPLIER;
  if (target_ms > safe_cap) {
    target_ms = safe_cap;
  }

  /* ====================================================================
   * 3. DUAL-TRACK DELAY EXECUTION
   * ==================================================================== */
  uint32_t last_time = platform->clock->get_tick_ms();
  uint32_t elapsed_hw = 0;

  volatile uint32_t sw_accum = 0;
  volatile uint32_t sw_accum_inv = ~0U; /* Initialisiert mit 0xFFFFFFFF */

  /* P10 Anti-Endless-Loop Guard & Instruction Skip Trap.
   * Wenn das Hardware-Tick-Register physikalisch einfriert,
   * oder delay_ms() übersprungen wird, wächst sw_accum extrem schnell.
   * Toleranz: Margin (target_ms * BOOT_DELAY_TOLERANCE_MULTIPLIER) für ungenaue
   * Hardware-Delays + 1000 Ticks. */
  uint32_t max_sw_limit = (target_ms * BOOT_DELAY_TOLERANCE_MULTIPLIER) +
                          1001; /* PATCH TEST BUGFIX */

  while (1) {
    /* Anti-Starvation Guard für den regulären Lauf */
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }

    uint32_t current_time = platform->clock->get_tick_ms();

    /* C-Standard garantiert, dass diese unsigned Subtraktion
     * Timer-Überläufe (Wraparounds der Hardware) korrekt verarbeitet. */
    uint32_t iteration_delta = current_time - last_time;

    /* ------------------------------------------------------------------
     * TIME-WARP & VENDOR-WRAP DEFENSE (Die wichtigste Härtung)
     * Wenn das Delta gigantisch ist (> 1000ms),
     * liegt ein EMFI-Glitch ODER ein inkompatibler 16-Bit HAL Wrap vor.
     * In diesem Fall kappen wir das Delta auf 0.
     * ------------------------------------------------------------------ */
    if (iteration_delta > 1000) {
      iteration_delta = 0; /* Glitch bestraft! Zeit schreitet nicht voran. */
    }

    elapsed_hw += iteration_delta;
    last_time = current_time;

    /* ====================================================================
     * EXIT CONDITION 1: Target Time Reached (Glitch Protected)
     * ====================================================================
     * Die CPU darf die Schleife NUR verlassen, wenn Hardware-Zeit UND
     * Software-Akkumulator das Ziel legitim erreicht haben!
     */
    bool hw_ok = (elapsed_hw >= target_ms);
    bool sw_ok = (sw_accum >= target_ms);

    BOOT_SECURE_REQUIRE(hw_ok && sw_ok, {
      goto check_deadlock;
    });
    break; /* Successfully and legally delayed! */

check_deadlock:

    /* ====================================================================
     * EXIT CONDITION 2: Hardware Deadlock / Instruction Skip Trap
     * ==================================================================== */
    BOOT_SECURE_REQUIRE(sw_accum <= max_sw_limit, {
      /* FATAL TRAP: Der Software-Zähler ist explodiert, aber der Hardware-Timer
       * hat das Ziel nicht erreicht. */
      boot_terminal_halt(platform, BOOT_ERR_VERIFY, SITE_DELAY_WARP);
    });

    /* Größere Steps zur Reduktion des Bus-Overheads.
     * 50ms ist absolut sicher für jeden Hardware-WDT (typ. min 500ms). */
    uint32_t remaining = (target_ms > sw_accum) ? (target_ms - sw_accum) : 1;
    uint32_t step = (remaining > 50) ? 50 : remaining;
    if (step == 0)
      step = 1;

    /* Physikalische Sleep-Ausführung an die Vendor-HAL abgeben */
    platform->clock->delay_ms(step);

    /* ====================================================================
     * ALU GLITCH EVALUATION (Fault Injection Defense)
     * ==================================================================== */
    sw_accum += step;
    sw_accum_inv -= step;

    volatile uint32_t eval_1 = sw_accum;
    volatile uint32_t eval_2 = ~sw_accum_inv;

    BOOT_SECURE_REQUIRE(eval_1 == eval_2, {
      /* FATAL ALU GLITCH DETECTED! */
      boot_terminal_halt(platform, BOOT_ERR_VERIFY, SITE_DELAY_GLITCH);
    });
  }

  /* ====================================================================
   * 4. CFI LOOP-ABORTION SHIELD (Terminal Glitch Trap)
   * ====================================================================
   * Ein Angreifer induziert einen Voltage-Glitch und zwingt die CPU
   * physikalisch dazu, die gesamte 'while' Schleife zu überspringen.
   * Wenn er hier ankommt, beweisen die Akkumulatoren, dass er betrogen hat!
   */
  bool final_hw_ok = (elapsed_hw >= target_ms);
  bool final_sw_ok = (sw_accum >= target_ms);

  BOOT_SECURE_REQUIRE(final_hw_ok && final_sw_ok, {
    boot_terminal_halt(platform, BOOT_ERR_VERIFY, SITE_DELAY_GLITCH);
  });

  return BOOT_OK;
}