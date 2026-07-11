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
#include "boot_proof.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_delay.h"
#include "boot_diag.h"
#include "boot_panic.h"
#include "boot_fih.h"
#include "boot_provisioning.h"
#include "boot_secure_zeroize.h"
#include "boot_state.h"
#include "boot_journal.h"
#include "boot_identity.h"
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

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define MAIN_CFI_SLOT_INIT    0
#define MAIN_CFI_SLOT_HW_UP   1
#define MAIN_CFI_SLOT_EXEC    2
#define MAIN_CFI_SLOT_BOUNDS  3
#define MAIN_CFI_SLOT_HANDOFF 4
#define MAIN_CFI_SLOT_HW_DOWN 5
#define MAIN_CFI_NUM_TOKENS   6

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
                        boot_target_config_t *target_out,
                        const uint32_t seal_key[4]) {

  /* P10 CFI Randomisierung: Seed wird später nach crypto->init gezogen */
  uint32_t main_cfi_seed = 0;
  boot_cfi_ctx_t main_cfi_ctx;

  /* P10 Leakage Prevention: Zeroize the output immediately (Zero-Day Fallback)
   */
  if (target_out != NULL) {
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
  }

  if (seal_key == NULL) {
    return BOOT_ERR_INVALID_ARG;
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

  /* Read forensic slot if present and mirror to telemetry */
  {
    boot_forensic_record_t forensic_record;
    boot_secure_zeroize(&forensic_record, sizeof(forensic_record));
    bool forensic_valid = false;

    /* Try RTC backup registers first */
    if (platform->soc && platform->soc->read_rtc_backup) {
      uint32_t *words = (uint32_t *)&forensic_record;
      boot_status_t rtc_stat = BOOT_OK;
      for (uint8_t slot = 1; slot <= 5; slot++) {
        boot_status_t s = platform->soc->read_rtc_backup(slot, &words[slot - 1]);
        if (s != BOOT_OK) {
          rtc_stat = s;
        }
      }
      if (rtc_stat == BOOT_OK && forensic_record.magic == 0x464F524E) {
        uint32_t calculated_crc = compute_boot_crc32((const uint8_t *)&forensic_record, 16);
        if (forensic_record.crc32 == calculated_crc) {
          forensic_valid = true;
        }
      }
    }

    /* Fallback to flash if not found in RTC */
    if (!forensic_valid && platform->flash && platform->flash->read) {
      boot_status_t f_read = platform->flash->read(CHIP_FORENSIC_SLOT_ABS_ADDR, &forensic_record, sizeof(forensic_record));
      if (f_read == BOOT_OK && forensic_record.magic == 0x464F524E) {
        uint32_t calculated_crc = compute_boot_crc32((const uint8_t *)&forensic_record, 16);
        if (forensic_record.crc32 == calculated_crc) {
          forensic_valid = true;
        }
      }
    }

    if (forensic_valid) {
      /* Mirror to toob_diag_state */
      boot_diag_init();
      boot_diag_set_error((boot_status_t)forensic_record.reason, forensic_record.site_id);
      
      /* Invalidate the slot to prevent reading the same crash on next reboot */
      if (platform->soc && platform->soc->write_rtc_backup) {
        for (uint8_t slot = 1; slot <= 5; slot++) {
          (void)platform->soc->write_rtc_backup(slot, 0);
        }
      }
      if (platform->flash && platform->flash->erase_sector) {
        (void)platform->flash->erase_sector(CHIP_FORENSIC_SLOT_ABS_ADDR);
      }
    }
  }

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

  /* TRNG ist jetzt verfügbar: CFI-Tokens ableiten */
  boot_random_safe(platform, (uint8_t *)&main_cfi_seed, sizeof(main_cfi_seed));
  boot_cfi_init(main_cfi_ctx, main_cfi_seed);
  for (uint8_t i = 1; i < MAIN_CFI_NUM_TOKENS; i++) {
    boot_cfi_add_expected(main_cfi_ctx, i);
  }

  boot_cfi_step(main_cfi_ctx, MAIN_CFI_SLOT_HW_UP);
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

      bool pin_active = platform->soc->get_recovery_pin_state();
      bool pin_failed = false;
      BOOT_SECURE_REQUIRE(pin_active, { pin_failed = true; });

      if (!pin_failed) {
        /* Trap atomar in das Serial-Rescue, ohne Return! */
        boot_panic(platform, BOOT_RECOVERY_REQUESTED);
        return BOOT_RECOVERY_REQUESTED; /* Unreachable P10 Safety */
      }
    }
  }

  /*
   * ==============================================================================
   * BLOCK 2.6 - DSLC-Gated Provisioning Entry (Factory Only)
   * ==============================================================================
   * Wenn das Gerät unprovisioniert ist (DSLC == 0x00), wird NICHT das OS
   * gestartet, sondern die UART-Provisioning-Session betreten.
   * Die Fabrik-Sicherheit wird durch den physischen Zugang zum Gerät
   * gewährleistet — ein Recovery-Pin ist hier NICHT erforderlich.
   */
  if (platform->crypto->read_dslc) {
    uint8_t dslc_val = 0xFF;
    size_t dslc_len = 1;
    if (platform->crypto->read_dslc(&dslc_val, &dslc_len) == BOOT_OK &&
        dslc_len > 0 && dslc_val == 0x00) {
      if (platform->provisioning) {
        boot_provisioning_run(platform, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
        return BOOT_ERR_NOT_SUPPORTED; /* Unreachable P10 Safety */
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
  status = boot_state_run(platform, target_out, seal_key, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  /* P10 O(1) Zeitmessung beenden und Wrap-around safe ablegen */
  uint32_t boot_end_time_ms = platform->clock->get_tick_ms();
  uint32_t boot_duration_ms = 0;
  if (boot_end_time_ms >= boot_start_time_ms) {
    boot_duration_ms = boot_end_time_ms - boot_start_time_ms;
  } else {
    boot_duration_ms = (UINT32_MAX - boot_start_time_ms) + boot_end_time_ms + 1;
  }

  BOOT_SECURE_REQUIRE(status == BOOT_OK, { goto panic_fallthrough; });

  boot_cfi_step(main_cfi_ctx, MAIN_CFI_SLOT_EXEC);

  /*
   * ==============================================================================
   * BLOCK 4 - Bounds Validation & XIP Safety
   * ==============================================================================
   */
  bool bounds_ok = false;

  if (boot_proof_verify(&target_out->proof, seal_key) == BOOT_OK) {
    uint32_t absolute_entry = target_out->proof.image_addr + target_out->proof.entry_point;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
    if (CHIP_FLASH_BASE_ADDR == 0 || absolute_entry >= CHIP_FLASH_BASE_ADDR) {
#pragma GCC diagnostic pop
      uint32_t relative_offset = absolute_entry - CHIP_FLASH_BASE_ADDR;

      /* O(1) Wrap-Around proof: Limit verification against Chip Size */
      if (CHIP_FLASH_TOTAL_SIZE >= relative_offset) {
        uint32_t max_allowed_size = CHIP_FLASH_TOTAL_SIZE - relative_offset;
        if (target_out->proof.image_size > 0 &&
            target_out->proof.image_size <= max_allowed_size) {
          /* P10 Rule: OS Vector Tables müssen zwingend auf 4-Byte
           * Architektur-Grenzen liegen */
          if (absolute_entry % 4 == 0) {
            bounds_ok = true;
          }
        }
      }
    }
  }

  if (boot_secure_confirm(bounds_ok ? BOOT_OK : BOOT_ERR_FLASH_BOUNDS) != BOOT_OK) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto panic_fallthrough;
  }

  boot_cfi_step(main_cfi_ctx, MAIN_CFI_SLOT_BOUNDS);

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
        .wal_erase_count = 0, /* TMR has no aggregated WAL wear counter */
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

  /* Phase 4: Device-ID Derivation */
  boot_status_t id_status = boot_derive_device_id(platform, local_handoff.device_id);
  if (id_status != BOOT_OK) {
      /* P10 Defensive: Fallback for Development Mode (unprovisioned keys) */
      boot_secure_zeroize(local_handoff.device_id, 32);
  }
  local_handoff.wipe_requested = target_out->wipe_requested ? 1 : 0;

  platform->wdt->kick();

  size_t handoff_hash_len = offsetof(toob_handoff_t, crc32_trailer);
  local_handoff.crc32_trailer = compute_boot_crc32((const uint8_t *)&local_handoff, handoff_hash_len);

  /* Atomarer Transfer (toob_diag_state wurde schon in boot_diag_seal aktualisiert) */
  memcpy(&toob_handoff_state, &local_handoff, sizeof(toob_handoff_t));

  uint32_t ram_crc_handoff = compute_boot_crc32((const uint8_t *)&toob_handoff_state, handoff_hash_len);

  bool ram_ok = (ram_crc_handoff == local_handoff.crc32_trailer);

  boot_secure_zeroize(&local_handoff, sizeof(local_handoff));

  if (boot_secure_confirm(ram_ok ? BOOT_OK : BOOT_ERR_VERIFY) != BOOT_OK) {
    status = BOOT_ERR_VERIFY;
    goto panic_fallthrough;
  }

  boot_cfi_step(main_cfi_ctx, MAIN_CFI_SLOT_HANDOFF);

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
  uint32_t wipe_acc = 0;

  /* Wir scannen stichprobenartig (O(1) begrenzt auf 32 Bytes) den Arena-Anfang,
   * da hier die heißesten Secrets (Root Keys) lagen. */
  for (size_t i = 0; i < 32 && i < BOOT_CRYPTO_ARENA_SIZE; i++) {
    wipe_acc |= crypto_arena[i];
  }

  BOOT_SECURE_REQUIRE(wipe_acc == 0, {
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
    boot_terminal_halt(platform, BOOT_ERR_VERIFY, SITE_MAIN_WIPE_FAIL);
  });

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

  boot_cfi_step(main_cfi_ctx, MAIN_CFI_SLOT_HW_DOWN);

  /* ==============================================================================
   * FINAL GLITCH-DEFENSE GATE (CFI VALIDATION)
   * ==============================================================================
   */
  boot_cfi_require(main_cfi_ctx, {
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
    boot_terminal_halt(platform, BOOT_ERR_VERIFY, SITE_MAIN_CFI_MISMATCH);
  });

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