/*
 * ==============================================================================
 * Toob-Boot Core File: boot_main.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/concept_fusion.md (Entry-Point, C-Kaskade, OS Boundary)
 * - docs/structure_plan.md (Lifecycle Orchestration & Linker Isolation)
 * - docs/testing_requirements.md (CFI-Tracking, P10 Bounds, TOCTOU Defense)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Global Lifecycle CFI: Ein Akkumulator beweist, dass Init, State-Machine,
 *    Bounds-Check und Deinit lückenlos durchlaufen wurden (Anti-Glitch).
 * 2. TOCTOU & Leakage Defense: Handoff-RAM wird im geschützten Stack
 * assembliert, mit CRC-32 versiegelt und erst atomar in den .noinit Memory
 * kopiert.
 * 3. Wrap-Around Bounds Proof: Der finale OS-Jump Vektor wird mathematisch
 *    doppelt abgesichert und gegen 32-bit Integer-Überläufe geschützt.
 * 4. Strict Cleanup Cascade: Bitmasken-Tracking für die Deinit-Routinen
 *    verhindert HardFaults bei asynchronen Init-Fehlern.
 * 5. P10 Hardware Alignment: Die .noinit Boundary erzwingt 8-Byte Alignments
 *    für Cortex-M und TrustZone Architektur-Sicherheit.
 */

#include "boot_main.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_delay.h"
#include "boot_diag.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "boot_state.h"
#include "boot_journal.h"
#include <stddef.h>
#include <string.h>


#ifndef BOOT_UART_BAUDRATE
#define BOOT_UART_BAUDRATE 115200
#endif

/* Mathematisches Glitch-Resistenz-Gating */
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK muss zwingend ein High-Hamming-Weight Pattern sein!");

/* Definition of the central zero-allocation memory block */
uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE] __attribute__((aligned(8)));

/* P10 Zero-Trust CFI Constants for Master Orchestrator */
#define CFI_MAIN_INIT 0x10101010
#define CFI_MAIN_HW_UP 0x20202020
#define CFI_MAIN_EXEC 0x40404040
#define CFI_MAIN_BOUNDS 0x80808080
#define CFI_MAIN_HANDOFF 0x01010101
#define CFI_MAIN_HW_DOWN 0x02020202

/* Init-Tracking Bitmask Flags für Fail-Safe Cleanup */
#define INIT_MASK_CLOCK (1U << 0)
#define INIT_MASK_FLASH (1U << 1)
#define INIT_MASK_OTFDEC (1U << 2)
#define INIT_MASK_WDT (1U << 3)
#define INIT_MASK_CRYPTO (1U << 4)
#define INIT_MASK_CONFIRM (1U << 5)
#define INIT_MASK_CONSOLE (1U << 6)
#define INIT_MASK_SOC (1U << 7)

/*
 * ==============================================================================
 * Handoff Areal (.noinit Shared-RAM) gemäß libtoob_api.md und toob_telemetry.md
 * ==============================================================================
 */
static inline toob_reset_reason_t
translate_reset_reason(reset_reason_t internal_reason) {
  /* Da das 1:1 Mapping zentral in boot_types.h per Static Assert verifiziert
   * ist, ist ein O(1) Cast C17 sicher und portabel. */
  return (toob_reset_reason_t)internal_reason;
}

/*
 * P10 Alignment Fix: Zwingend 8-Byte Alignment für 64-Bit Nonce Load/Stores
 * im Target OS, um Hardware-Traps zu verhindern.
 */
#if defined(__GNUC__) || defined(__clang__)
#define BOOT_NOINIT __attribute__((section(".noinit"), aligned(8)))
#elif defined(__ICCARM__) || defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define BOOT_NOINIT __attribute__((section(".bss.noinit"), aligned(8)))
#else
#define BOOT_NOINIT __attribute__((aligned(8)))
#endif

BOOT_NOINIT toob_handoff_t toob_handoff_state;
BOOT_NOINIT toob_boot_diag_t toob_diag_state;

boot_status_t boot_main(const boot_platform_t *platform,
                        boot_target_config_t *target_out) {

  volatile uint32_t main_cfi = CFI_MAIN_INIT;

  /* P10 Leakage Prevention: Zeroize the output immediately (Zero-Day Fallback)
   */
  if (target_out != NULL) {
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
  }

  /*
   * ==============================================================================
   * BLOCK 1 - P10 Guarding (Zero-Trust Platform Verification)
   * ==============================================================================
   */
  if (platform == NULL || target_out == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (platform->clock == NULL || platform->flash == NULL ||
      platform->wdt == NULL || platform->crypto == NULL ||
      platform->confirm == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* ABI & Constraint Checks */
  if (platform->clock->abi_version != TOOB_HAL_ABI_V2 ||
      platform->flash->abi_version != TOOB_HAL_ABI_V2 ||
      platform->wdt->abi_version != TOOB_HAL_ABI_V2 ||
      platform->crypto->abi_version != TOOB_HAL_ABI_V2 ||
      platform->confirm->abi_version != TOOB_HAL_ABI_V2) {
    return BOOT_ERR_ABI_MISMATCH;
  }
  if (platform->console != NULL &&
      platform->console->abi_version != TOOB_HAL_ABI_V2) {
    return BOOT_ERR_ABI_MISMATCH;
  }
  if (platform->soc != NULL && platform->soc->abi_version != TOOB_HAL_ABI_V2) {
    return BOOT_ERR_ABI_MISMATCH;
  }

  if (platform->flash->max_erase_cycles == 0) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Pflicht-Funktionspointer prüfen */
  if (platform->clock->init == NULL || platform->clock->deinit == NULL ||
      platform->clock->get_tick_ms == NULL ||
      platform->clock->get_reset_reason == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->flash->init == NULL || platform->flash->deinit == NULL ||
      platform->flash->read == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->wdt->init == NULL || platform->wdt->deinit == NULL ||
      platform->wdt->kick == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->confirm->init == NULL || platform->confirm->deinit == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->crypto->init == NULL || platform->crypto->deinit == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

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
   * BLOCK 2 - Hardware Init Cascade (Strikt nach Spec)
   * ==============================================================================
   */
  boot_status_t status = BOOT_OK;
  uint32_t init_mask = 0;

  if (platform->soc != NULL) {
    /* GAP Mitigation: Bus-Matrix flushen, um hängende DMAs von Sub-Cores vor
     * dem Reset abzuschließen! */
    platform->soc->flush_bus_matrix();
    platform->soc->assert_secondary_cores_reset();
  }

  status = platform->clock->init();
  if (status != BOOT_OK)
    goto init_cleanup;
  init_mask |= INIT_MASK_CLOCK;

  status = platform->flash->init();
  if (status != BOOT_OK)
    goto init_cleanup;
  init_mask |= INIT_MASK_FLASH;

  if (platform->flash->set_otfdec_mode != NULL) {
    status = platform->flash->set_otfdec_mode(false);
    if (status != BOOT_OK)
      goto init_cleanup;
    init_mask |= INIT_MASK_OTFDEC;
  }

  status = platform->wdt->init(BOOT_WDT_TIMEOUT_MS);
  if (status != BOOT_OK)
    goto init_cleanup;
  init_mask |= INIT_MASK_WDT;

  status = platform->crypto->init();
  if (status != BOOT_OK)
    goto init_cleanup;
  init_mask |= INIT_MASK_CRYPTO;

  status = platform->confirm->init();
  if (status != BOOT_OK)
    goto init_cleanup;
  init_mask |= INIT_MASK_CONFIRM;

  if (platform->console != NULL) {
    status = platform->console->init(BOOT_UART_BAUDRATE);
    if (status != BOOT_OK)
      goto init_cleanup;
    init_mask |= INIT_MASK_CONSOLE;
  }

  if (platform->soc != NULL) {
    status = platform->soc->init();
    if (status != BOOT_OK)
      goto init_cleanup;
    init_mask |= INIT_MASK_SOC;
  }

  main_cfi ^= CFI_MAIN_HW_UP;
  goto init_success;

init_cleanup:
  /* Sauberes Rollback: Deinit in exakt umgekehrter Reihenfolge anhand der
   * Bitmaske */
  if (init_mask & INIT_MASK_SOC)
    platform->soc->deinit();
  if (init_mask & INIT_MASK_CONSOLE)
    platform->console->deinit();
  if (init_mask & INIT_MASK_CONFIRM)
    platform->confirm->deinit();
  if (init_mask & INIT_MASK_CRYPTO)
    platform->crypto->deinit();
  if (init_mask & INIT_MASK_WDT)
    platform->wdt->deinit();
  if (init_mask & INIT_MASK_OTFDEC)
    (void)platform->flash->set_otfdec_mode(true);
  if (init_mask & INIT_MASK_FLASH)
    platform->flash->deinit();
  if (init_mask & INIT_MASK_CLOCK)
    platform->clock->deinit();

  boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
  return status; /* Hard-Exit zurück an Stage 0 (Panic unsafe) */

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

      /* Glitch-Resistenter Double Check: Ist der Pin immer noch High? */
      volatile uint32_t pin_shield_1 = 0, pin_shield_2 = 0;
      bool pin_active = platform->soc->get_recovery_pin_state();

      if (pin_active)
        pin_shield_1 = BOOT_OK;
      BOOT_GLITCH_DELAY();
      if (pin_shield_1 == BOOT_OK && pin_active)
        pin_shield_2 = BOOT_OK;

      if (pin_shield_1 == BOOT_OK && pin_shield_2 == BOOT_OK &&
          pin_shield_1 == pin_shield_2) {
        /* Trap atomar in das Serial-Rescue, ohne Return! */
        boot_panic(platform, BOOT_RECOVERY_REQUESTED);
        return BOOT_RECOVERY_REQUESTED; /* Unreachable P10 Safety */
      }
    }
  }

  /*
   * ==============================================================================
   * BLOCK 3 - Execution (State Machine Orchestration)
   * ==============================================================================
   */
  uint32_t boot_start_time_ms = platform->clock->get_tick_ms();

  /* Betritt den Lebenszyklus des Bootloaders (WAL, Merkle, Swap, Confirm) */
  status = boot_state_run(platform, target_out);

  /* P10 O(1) Zeitmessung beenden und Wrap-around safe ablegen */
  uint32_t boot_end_time_ms = platform->clock->get_tick_ms();
  uint32_t boot_duration_ms = 0;
  if (boot_end_time_ms >= boot_start_time_ms) {
    boot_duration_ms = boot_end_time_ms - boot_start_time_ms;
  } else {
    boot_duration_ms = (UINT32_MAX - boot_start_time_ms) + boot_end_time_ms + 1;
  }

  /* GLITCH-SHIELDED STATE EVALUATION
   * Verhindert das Ignorieren eines invaliden Boot-States durch EMFI Jumps! */
  volatile uint32_t sm_shield_1 = 0, sm_shield_2 = 0;
  if (status == BOOT_OK)
    sm_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (sm_shield_1 == BOOT_OK && status == BOOT_OK)
    sm_shield_2 = BOOT_OK;

  if (sm_shield_1 != BOOT_OK || sm_shield_2 != BOOT_OK ||
      sm_shield_1 != sm_shield_2) {
    goto panic_fallthrough;
  }

  main_cfi ^= CFI_MAIN_EXEC;

  /*
   * ==============================================================================
   * BLOCK 4 - Bounds Validation & XIP Safety
   * ==============================================================================
   */
  volatile uint32_t bounds_shield_1 = 0, bounds_shield_2 = 0;
  bool bounds_ok = false;

  /* Subtraktiver Check umgeht `uint32_t` Wrapping wenn OOB! */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
  if (CHIP_FLASH_BASE_ADDR == 0 || target_out->active_entry_point >= CHIP_FLASH_BASE_ADDR) {
#pragma GCC diagnostic pop
    uint32_t relative_offset =
        target_out->active_entry_point - CHIP_FLASH_BASE_ADDR;

    /* O(1) Wrap-Around proof: Limit verification against Chip Size */
    if (CHIP_FLASH_TOTAL_SIZE >= relative_offset) {
      uint32_t max_allowed_size = CHIP_FLASH_TOTAL_SIZE - relative_offset;
      if (target_out->active_image_size > 0 &&
          target_out->active_image_size <= max_allowed_size) {
        /* P10 Rule: OS Vector Tables müssen zwingend auf 4-Byte
         * Architektur-Grenzen liegen */
        if (target_out->active_entry_point % 4 == 0) {
          bounds_ok = true;
        }
      }
    }
  }

  if (bounds_ok)
    bounds_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (bounds_shield_1 == BOOT_OK && bounds_ok)
    bounds_shield_2 = BOOT_OK;

  if (bounds_shield_1 != BOOT_OK || bounds_shield_2 != BOOT_OK ||
      bounds_shield_1 != bounds_shield_2) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto panic_fallthrough;
  }

  main_cfi ^= CFI_MAIN_BOUNDS;

  /*
   * ==============================================================================
   * BLOCK 5 - Handoff (.noinit Mapping, TOCTOU-Proof & CRC-32 Sealing)
   * ==============================================================================
   * Bevor der RAM neutralisiert wird, muss Stage 1 die Zielkonfiguration
   * (Nonce, Slot) in die designierten Abschnitte sichern. FIX: Das passiert
   * lokal im C-Stack und wird in einem Rutsch (memcpy) transferiert!
   */
  boot_diag_set_boot_time(boot_duration_ms);

  wal_tmr_payload_t tmr __attribute__((aligned(8)));
  boot_secure_zeroize(&tmr, sizeof(tmr));
  if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
    boot_diag_set_recovery_events(tmr.boot_failure_counter);

    toob_ext_health_t wear = {
        .wal_erase_count = tmr.app_svn,
        .app_slot_erase_count = tmr.app_slot_erase_counter,
        .staging_slot_erase_count = tmr.staging_slot_erase_counter,
        .swap_buffer_erase_count = tmr.swap_buffer_erase_counter
    };
    boot_diag_set_wear_data(&wear);
  }
  boot_secure_zeroize(&tmr, sizeof(tmr));

  boot_diag_seal(); /* Kapselt CRC & Padding-Nulling perfekt ein */

  /* Handoff Struct Population */
  toob_handoff_t local_handoff __attribute__((aligned(8)));
  boot_secure_zeroize(&local_handoff, sizeof(local_handoff));

  local_handoff.magic = target_out->is_tentative_boot ? TOOB_STATE_TENTATIVE : TOOB_STATE_COMMITTED;
  local_handoff.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
  local_handoff.boot_nonce = target_out->generated_nonce;
  local_handoff.reset_reason = translate_reset_reason(platform->clock->get_reset_reason());
  local_handoff.booted_partition = target_out->boot_recovery_os ? TOOB_PARTITION_RECOVERY : TOOB_PARTITION_APP;
  local_handoff.net_search_accum_ms = target_out->net_search_accum_ms;
  local_handoff.resume_offset = target_out->resume_offset;

  platform->wdt->kick();

  size_t handoff_hash_len = offsetof(toob_handoff_t, crc32_trailer);
  local_handoff.crc32_trailer = compute_boot_crc32((const uint8_t *)&local_handoff, handoff_hash_len);

  /* Atomarer Transfer (toob_diag_state wurde schon in boot_diag_seal aktualisiert) */
  memcpy(&toob_handoff_state, &local_handoff, sizeof(toob_handoff_t));

  uint32_t ram_crc_handoff = compute_boot_crc32((const uint8_t *)&toob_handoff_state, handoff_hash_len);

  volatile uint32_t ram_shield_1 = 0, ram_shield_2 = 0;
  bool ram_ok = (ram_crc_handoff == local_handoff.crc32_trailer);

  if (ram_ok) ram_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (ram_shield_1 == BOOT_OK && ram_ok) ram_shield_2 = BOOT_OK;

  boot_secure_zeroize(&local_handoff, sizeof(local_handoff));

  if (ram_shield_1 != BOOT_OK || ram_shield_2 != BOOT_OK || ram_shield_1 != ram_shield_2) {
    status = BOOT_ERR_VERIFY;
    goto panic_fallthrough;
  }

  main_cfi ^= CFI_MAIN_HANDOFF;

  /*
   * ==============================================================================
   * BLOCK 6 - Deinit Cascade (Hardware Sicherung & RAM Wipe vor Handoff)
   * Systematisch absteigend, Zeitgeber und Watchdog als Letztes.
   * ==============================================================================
   */
  if (platform->flash->set_otfdec_mode != NULL) {
    (void)platform->flash->set_otfdec_mode(true);
  }
  platform->flash->deinit();

  /* KRITISCHER SICHERHEITS-EXIT (Anti Cold-Boot)
   * Zerstört kryptografische Residuen (Hashes, Keys) in der Arena. */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  /* P10 GLITCH SHIELD: Beweise physikalisch, dass die Arena aus 0x00 besteht!
   * Verhindert Memory-Extraction via Fault-Injection. */
  volatile uint32_t wipe_shield_1 = 0, wipe_shield_2 = 0;
  uint32_t wipe_acc = 0;

  /* Wir scannen stichprobenartig (O(1) begrenzt auf 32 Bytes) den Arena-Anfang,
   * da hier die heißesten Secrets (Root Keys) lagen. */
  for (size_t i = 0; i < 32 && i < BOOT_CRYPTO_ARENA_SIZE; i++) {
    wipe_acc |= crypto_arena[i];
  }

  if (wipe_acc == 0)
    wipe_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (wipe_shield_1 == BOOT_OK && wipe_acc == 0)
    wipe_shield_2 = BOOT_OK;

  if (wipe_shield_1 != BOOT_OK || wipe_shield_2 != BOOT_OK ||
      wipe_shield_1 != wipe_shield_2) {
    /* FATAL: RAM-Wipe wurde glitched! System für immer einfrieren! */
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
    if (platform->clock && platform->clock->deinit)
      platform->clock->deinit();
    while (1) {
      BOOT_GLITCH_DELAY();
    } /* Starve WDT for reset */
  }

  platform->crypto->deinit();
  platform->confirm->deinit();

  if (platform->console != NULL) {
    platform->console->deinit();
  }

  if (platform->soc != NULL) {
    /* MPU Core Data-Flush: Zeroize Shared-Cache Buffers/Matrices between boots!
     */
    if (platform->soc->flush_bus_matrix)
      platform->soc->flush_bus_matrix();
    platform->soc->deinit();
  }

  /* Zeitbasis abwerfen */
  platform->clock->deinit();

  main_cfi ^= CFI_MAIN_HW_DOWN;

  /* ==============================================================================
   * FINAL GLITCH-DEFENSE GATE (CFI VALIDATION)
   * ==============================================================================
   * Beweist mathematisch, dass die gesamte Architektur fehler- und lückenlos
   * durchlaufen wurde. Ein PC-Glitch wird hier in der finalen Taktstufe
   * abgefangen!
   */
  uint32_t expected_cfi = CFI_MAIN_INIT ^ CFI_MAIN_HW_UP ^ CFI_MAIN_EXEC ^
                          CFI_MAIN_BOUNDS ^ CFI_MAIN_HANDOFF ^ CFI_MAIN_HW_DOWN;

  volatile uint32_t final_shield_1 = 0, final_shield_2 = 0;

  if (main_cfi == expected_cfi)
    final_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (final_shield_1 == BOOT_OK && main_cfi == expected_cfi)
    final_shield_2 = BOOT_OK;

  if (final_shield_1 != BOOT_OK || final_shield_2 != BOOT_OK ||
      final_shield_1 != final_shield_2) {
    /* FATAL GLITCH TRAP:
     * Wir können hier NICHT mehr `boot_panic` rufen, da Flash, Console und SoC
     * bereits de-initialisiert wurden! Der einzige physisch sichere Ausweg ist
     * "Watchdog Starvation" - Endlosschleife, bis die Hardware den Strom
     * trennt. */
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
    while (1) {
      BOOT_GLITCH_DELAY();
    }
  }

  /* Watchdog stirbt in der letzten Nanosekunde vor dem Assembler-Jump */
  platform->wdt->deinit();

  return BOOT_OK;

panic_fallthrough:
  /* Fallback Path bei Hardware/State-Machine Error: Diag-State füllen und
   * Rescue rufen */
  boot_secure_zeroize(target_out, sizeof(boot_target_config_t));

  toob_boot_diag_t local_diag_err __attribute__((aligned(8)));
  boot_secure_zeroize(&local_diag_err, sizeof(local_diag_err));

  local_diag_err.struct_version = TOOB_DIAG_STRUCT_VERSION;
  local_diag_err.last_error_code = status;
  local_diag_err.boot_duration_ms = boot_duration_ms;

  size_t p_hash_len = offsetof(toob_boot_diag_t, crc32_trailer);
  local_diag_err.crc32_trailer =
      compute_boot_crc32((const uint8_t *)&local_diag_err, p_hash_len);

  memcpy(&toob_diag_state, &local_diag_err, sizeof(toob_boot_diag_t));
  boot_secure_zeroize(&local_diag_err, sizeof(local_diag_err));

  boot_panic(platform, status);
  return status; /* Unreachable due to _Noreturn */
}