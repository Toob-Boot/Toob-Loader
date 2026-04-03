/*
 * Toob-Boot Core File: boot_main.c
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md (Entry-Point, C-Kaskade)
 * - docs/structure_plan.md
 */

#include "boot_main.h"
#include "boot_delay.h"
#include "boot_panic.h"
#include "boot_state.h"
#include "boot_config_mock.h"
#include "boot_secure_zeroize.h"
#include "chip_config.h"
#include <string.h>
#include <stddef.h>
#include "boot_crc32.h"

#ifndef BOOT_UART_BAUDRATE
#define BOOT_UART_BAUDRATE 115200
#endif

/*
 * ==============================================================================
 * Handoff Areal (.noinit Shared-RAM) gemäß libtoob_api.md und toob_telemetry.md
 * ==============================================================================
 */
__attribute__((section(".noinit"))) toob_handoff_t toob_handoff_state;
__attribute__((section(".noinit"))) toob_boot_diag_t toob_diag_state;

boot_status_t boot_main(const boot_platform_t *platform,
                        boot_target_config_t *target_out) {
  /*
   * ==============================================================================
   * BLOCK 1 - P10 Guarding
   * ==============================================================================
   * - Prüfe ob platform und target_out != NULL sind.
   * - Prüfe ob platform->clock, flash, wdt, crypto, confirm != NULL sind.
   */
  if (platform == NULL || target_out == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* PFLICHT-Traits prüfen */
  if (platform->clock == NULL || platform->flash == NULL ||
      platform->wdt == NULL || platform->crypto == NULL ||
      platform->confirm == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Pflicht-Funktionspointer prüfen, die boot_main direkt aufruft (Init/Deinit
   * Kaskade & Clock/Delay) */
  if (platform->clock->init == NULL || platform->clock->deinit == NULL ||
      platform->clock->get_tick_ms == NULL || platform->clock->get_reset_reason == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->flash->init == NULL || platform->flash->deinit == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->wdt->init == NULL || platform->wdt->deinit == NULL ||
      platform->wdt->kick == NULL) {
    /* WDT Kick wird indirekt via boot_delay_with_wdt genutzt! */
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->confirm->init == NULL || platform->confirm->deinit == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->crypto->init == NULL || platform->crypto->deinit == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Optionale Traits absichern */
  if (platform->soc != NULL) {
    if (platform->soc->init == NULL || platform->soc->deinit == NULL ||
        platform->soc->assert_secondary_cores_reset == NULL ||
        platform->soc->flush_bus_matrix == NULL) {
      return BOOT_ERR_INVALID_ARG;
    }
  }

  if (platform->console != NULL) {
    if (platform->console->init == NULL || platform->console->deinit == NULL) {
      return BOOT_ERR_INVALID_ARG;
    }
  }

  /*
   * ==============================================================================
   * BLOCK 2 - Init Cascade (Strikt nach Spec)
   * ==============================================================================
   */
  boot_status_t status = BOOT_OK;

  bool clock_inited = false;
  bool flash_inited = false;
  bool wdt_inited = false;
  bool crypto_inited = false;
  bool confirm_inited = false;
  bool console_inited = false;
  bool soc_inited = false;

  if (platform->soc != NULL) {
    /* 
     * GAP Mitigiation: Bevor der Reset-Assert erfolgt, zwingend die Bus-Matrix
     * flushen, um hängende DMAs von Sub-Cores vor dem Reset abzuschließen! 
     */
    platform->soc->flush_bus_matrix();
    platform->soc->assert_secondary_cores_reset();
  }

  status = platform->clock->init();
  if (status != BOOT_OK) goto init_cleanup;
  clock_inited = true;

  status = platform->flash->init();
  if (status != BOOT_OK) goto init_cleanup;
  flash_inited = true;

  if (platform->flash->set_otfdec_mode != NULL) {
    status = platform->flash->set_otfdec_mode(false);
    if (status != BOOT_OK) goto init_cleanup;
  }

  status = platform->wdt->init(BOOT_WDT_TIMEOUT_MS);
  if (status != BOOT_OK) goto init_cleanup;
  wdt_inited = true;

  status = platform->crypto->init();
  if (status != BOOT_OK) goto init_cleanup;
  crypto_inited = true;

  status = platform->confirm->init();
  if (status != BOOT_OK) goto init_cleanup;
  confirm_inited = true;

  if (platform->console != NULL) {
    status = platform->console->init(BOOT_UART_BAUDRATE);
    if (status != BOOT_OK) goto init_cleanup;
    console_inited = true;
  }

  if (platform->soc != NULL) {
    status = platform->soc->init();
    if (status != BOOT_OK) goto init_cleanup;
    soc_inited = true;
  }

  goto init_success;

init_cleanup:
  /* Sauberes Rollback bei Initialisierungsfehlern: Deinit in umgekehrter Reihenfolge */
  if (soc_inited)     platform->soc->deinit();
  if (console_inited) platform->console->deinit();
  if (confirm_inited) platform->confirm->deinit();
  if (crypto_inited)  platform->crypto->deinit();
  if (flash_inited) {
    if (platform->flash->set_otfdec_mode != NULL) {
        (void)platform->flash->set_otfdec_mode(true);
    }
    platform->flash->deinit();
  }
  if (clock_inited)   platform->clock->deinit();
  if (wdt_inited)     platform->wdt->deinit();
  
  /* Hard-Exit zurück an Stage 0, da Hardware-Kaskade nicht benutzbar (Panic unsafe) */
  return status;

init_success:
  /*
   * ==============================================================================
   * BLOCK 2.5 - HW Recovery Pin Debouncing (Schicht 4a Trap)
   * ==============================================================================
   */
  if (platform->soc != NULL && platform->soc->get_recovery_pin_state != NULL) {
    if (platform->soc->get_recovery_pin_state()) {
      /* Debounce Wait: 500ms mit WDT Kicks (P10) */
      boot_delay_with_wdt(platform, 500);

      /* Erneuter Check: Ist der Pin immer noch High? */
      if (platform->soc->get_recovery_pin_state()) {
        /* Trap atomar in das Serial-Rescue, ohne Return! */
        boot_panic(platform, BOOT_RECOVERY_REQUESTED);
        /* Statische Kontrollflussklausel (NASA P10) */
        return BOOT_RECOVERY_REQUESTED;
      }
    }
  }

  /*
   * ==============================================================================
   * BLOCK 3 - Execution (State Machine)
   * ==============================================================================
   */
  uint32_t boot_start_time_ms = platform->clock->get_tick_ms();

  /* Betritt den Lebenszyklus des Bootloaders (WAL, Merkle, Swap, Confirm) */
  status = boot_state_run(platform, target_out);

  /* P10 O(1) Zeitmessung beenden und zwischenspeichern fuer Block 5 (Telemetrie) */
  uint32_t boot_end_time_ms = platform->clock->get_tick_ms();
  /* Wrap-around safe subtraction (UINT32) */
  uint32_t boot_duration_ms = boot_end_time_ms - boot_start_time_ms;

  /*
   * ==============================================================================
   * BLOCK 4 - Diagnostics, Panic Fallback & Bounds Validation
   * ==============================================================================
   */
  if (status != BOOT_OK) {
    toob_diag_state.fallback_occurred = true;
    boot_panic(platform, status);
    return status;
  }

  /* 
   * Strenger Bounds Check für den Ziel-Vektor. Verhindert Exekutions-Sprünge ins
   * bodenlose Nichts oder in invaliden SRAM. P10 Rule: Check immediately!
   */
  if (target_out->active_entry_point >= CHIP_FLASH_TOTAL_SIZE ||
      target_out->active_image_size == 0 ||
      /* Subtraktiver Check umgeht `uint32_t` Wrapping wenn OOB! */
      target_out->active_image_size > (CHIP_FLASH_TOTAL_SIZE - target_out->active_entry_point)) {
    toob_diag_state.fallback_occurred = true;
    boot_panic(platform, BOOT_ERR_FLASH_BOUNDS);
    return BOOT_ERR_FLASH_BOUNDS;
  }

  /*
   * ==============================================================================
   * BLOCK 5 - Handoff (.noinit Mapping & CRC-32 Sealing)
   * ==============================================================================
   * Bevor der RAM neutralisiert wird, muss Stage 1 die Zielkonfiguration (Nonce, Slot)
   * und Metriken in die designierten Abschnitte sichern und kryptographisch versiegeln.
   */
  /* 
   * Garbage aus unkontrolliertem Brownout-SRAM bereinigen, 
   * damit OS und Telemetrie saubere Daten bekommen. 
   */
  memset(&toob_diag_state, 0, sizeof(toob_diag_state));
  memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
  toob_diag_state.boot_duration_ms = boot_duration_ms;

  /* Basic Handoff Population */
  toob_handoff_state.magic = TOOB_STATE_COMMITTED; /* 0x55AA55AA */
  toob_handoff_state.struct_version = 0x01000000;  /* V1.0.0 */
  toob_handoff_state.boot_nonce = target_out->generated_nonce;
  toob_handoff_state.reset_reason = platform->clock->get_reset_reason();

  /* Die Wear-Counters und Failure-Counters uebernimmt boot_state.c, 
   * ebenso active_slot, da diese Logik tief im WAL Journal verankert ist.
   * Hier versiegeln wir am Ende unabhaengig C-State: */

  size_t hash_len = offsetof(toob_handoff_t, crc32_trailer);
  toob_handoff_state.crc32_trailer = compute_boot_crc32((const uint8_t*)&toob_handoff_state, hash_len);

  /*
   * ==============================================================================
   * BLOCK 6 - Deinit Cascade (Hardware Sicherung vor Handoff)
   * Systematisch absteigend, Zeitgeber und Watchdog als Letztes.
   * ==============================================================================
   */
  if (platform->flash->set_otfdec_mode != NULL) {
      (void)platform->flash->set_otfdec_mode(true);
  }
  platform->flash->deinit();

  /*
   * Kritischer Sicherheits-Exit: MPU / Crypto Clean-up
   * Zerstört kryptografische Residuen aus der Linker-Arena vor Ausführung
   * des Target-OS. (P10 O(1) Zeroize).
   * 
   * ANMERKUNG: `crypto_arena` wird über `boot_config_mock.h`
   * via System-Linker-Declaration aufgelöst.
   */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
  platform->crypto->deinit();

  platform->confirm->deinit();

  if (platform->console != NULL) {
      platform->console->deinit();
  }

  if (platform->soc != NULL) {
      /* MPU Core Data-Flush: Zeroize Shared-Cache Buffers/Matrices between boots! */
      platform->soc->flush_bus_matrix();
      platform->soc->deinit();
  }

  /* Zeitbasis abwerfen */
  platform->clock->deinit();

  /* Watchdog stirbt in der letzten Nanosekunde vor dem Assembler-Jump */
  platform->wdt->deinit();

  return BOOT_OK;
}
