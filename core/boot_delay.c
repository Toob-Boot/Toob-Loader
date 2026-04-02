/*
 * Toob-Boot Core File: boot_delay.c
 * Relevant Spec-Dateien:
 * - docs/hals.md (Watchdog timeout during delay)
 * - docs/testing_requirements.md
 */

#include "boot_delay.h"

boot_status_t boot_delay_with_wdt(const boot_platform_t *platform, uint32_t ms) {
  if (!platform || !platform->clock) {
    return BOOT_ERR_INVALID_ARG; // P10-compliant: Fallback wenn Clock HAL fehlt
  }

  if (!platform->clock->get_tick_ms || !platform->clock->delay_ms) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint32_t start_time = platform->clock->get_tick_ms();

  /* FIX (Doublecheck): Overflow-Protection für max_iterations */
  if (ms > (UINT32_MAX / 2)) {
      ms = (UINT32_MAX / 2);
  }

  /* FIX (Doublecheck): Statisches P10 Upper-Bound (Schutz vor permanent
   * hängendem Clock-Tick-Register bei Hardware-Fehler) */
  uint32_t safe_iterations = 0;
  uint32_t max_iterations = ms * 2; /* 100% Margin für Clock-Drift */

  /* FIX (Doublecheck): Wrap-Around Sicherheit - Die unsigned Subtraktion 
   * (get_tick - start) ist per C-Standard sicher gegen uint32 Timer-Überläufe. */
  while (((platform->clock->get_tick_ms() - start_time) < ms) &&
         (safe_iterations < max_iterations)) {
    
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    
    /* FIX (Doublecheck): Größere Steps zur Reduktion des Bus-Overheads. 
     * 50ms ist absolut sicher für jeden Hardware-WDT (typ. min 500ms). */
    uint32_t elapsed = platform->clock->get_tick_ms() - start_time;
    uint32_t remaining = (ms > elapsed) ? (ms - elapsed) : 0;
    uint32_t step = (remaining > 50) ? 50 : remaining;
    if (step == 0) step = 1; /* Absicherung, falls Tick komplett gefroren ist */
    
    platform->clock->delay_ms(step);
    safe_iterations += step;
  }
  
  /* Return Timeout, falls der Loop durch die Hardware-Lock-Protection ausbrach */
  if (safe_iterations >= max_iterations) {
      return BOOT_ERR_TIMEOUT;
  }
  
  return BOOT_OK;
}
