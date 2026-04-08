/*
 * ==============================================================================
 * Toob-Boot Core File: boot_rollback.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/concept_fusion.md (OS Recovery nach Fehlversuch, Anti-Downgrade)
 * - docs/testing_requirements.md (P10 Bound Validation, CFI Glitch-Resistance)
 * - docs/libtoob_api.md (Failure Edge Cases)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Glitch-Resistant Downgrade Shield: Doppelte boolesche Akkumulatoren
 * verhindern Voltage-Fault Skips bei der kritischen SVN-Prüfung.
 * 2. Zero-Allocation 1-Way Copy: Nutzt die crypto_arena iterativ. Ersetzt 16KB
 *    statischen RAM durch intelligente Tearing- und Verschleiß-resistente
 * Kopierschleifen.
 * 3. Algebraic Backoff Proofs: Saturation Arithmetic verhindert Wraparounds im
 * Crash-Loop.
 * 4. Phase-Bound Verify: On-the-Fly CRC32 Check nach physikalischen
 * Hardware-Writes.
 */

#include "boot_rollback.h"
#include "boot_config_mock.h"
#include "boot_crc32.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "boot_swap.h"
#include <string.h>

_Static_assert(BOOT_CONFIG_MAX_RETRIES > 0,
               "Invalid Configuration: Target Retries must be positive");
_Static_assert((BOOT_CONFIG_BACKOFF_BASE_S * 24ULL) <= UINT32_MAX,
               "Exponential Backoff Configuration will overflow");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK MUST be high-hamming distance for Glitch Shielding");

extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

/*
 * ============================================================================
 * BLOCK 1: Hybrid SVN Verification (Anti-Downgrade Shield)
 * ============================================================================
 */
boot_status_t boot_rollback_verify_svn(const boot_platform_t *platform,
                                       uint32_t manifest_svn,
                                       bool is_recovery_os) {
  if (!platform || !platform->crypto || !platform->wdt) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* 1. Lese persistierte SVN Werte sicher aus WAL TMR Payload */
  wal_tmr_payload_t tmr;
  boot_secure_zeroize(&tmr, sizeof(tmr)); /* P10: Stack Residuen verhindern */

  boot_status_t status = boot_journal_get_tmr(platform, &tmr);

  /* Boot_Journal Toleranz: Bei Initial Flash (Blank Device) existiert noch kein
   * TMR. In diesem Sonderfall ist Baseline SVN = 0. */
  if (status != BOOT_OK && status != BOOT_ERR_STATE &&
      status != BOOT_ERR_NOT_FOUND) {
    return status; /* Hardware Fehler sofort propagieren */
  }

  uint32_t persisted_wal_svn =
      is_recovery_os ? tmr.svn_recovery_counter : tmr.app_svn;
  boot_secure_zeroize(&tmr, sizeof(tmr)); /* Sensible Daten umgehend abräumen */

  /* 2. Hardware-Root-of-Trust (eFuse Epoch) abrufen */
  uint32_t efuse_epoch = 0;
  if (platform->crypto->read_monotonic_counter) {
    platform->wdt->kick();
    boot_status_t efuse_status =
        platform->crypto->read_monotonic_counter(&efuse_epoch);
    platform->wdt->kick();

    if (efuse_status != BOOT_OK && efuse_status != BOOT_ERR_NOT_SUPPORTED) {
      return efuse_status;
    }
  }

  /* 3. MATHEMATISCHER GLITCH-BEWEIS (Voltage Skip Protection)
   * Verweigert Downgrades rigoros. Identische Versionen (Re-Flashes) sind für
   * Reparaturen zulässig. Statt einem simplen Branch (manifest < persisted)
   * nutzen wir das O(1) Double-Check Pattern. */
  bool valid_wal = (manifest_svn >= persisted_wal_svn);
  bool valid_efuse = (manifest_svn >= efuse_epoch);

  volatile uint32_t downgrade_shield_1 = 0;
  volatile uint32_t downgrade_shield_2 = 0;

  if (valid_wal && valid_efuse) {
    downgrade_shield_1 = BOOT_OK; /* 0x55AA55AA */
  }

  /* Timing/Branch Delay Injection gegen EMFI / Instruction-Skips */
  __asm__ volatile("nop; nop; nop;");

  if (downgrade_shield_1 == BOOT_OK && valid_wal && valid_efuse) {
    downgrade_shield_2 = BOOT_OK;
  }

  /* Finale Akkumulation der Sicherheits-Checks (schließt asynchrone
   * Manipulationen aus) */
  if (downgrade_shield_1 != BOOT_OK || downgrade_shield_2 != BOOT_OK ||
      downgrade_shield_1 != downgrade_shield_2) {
    return BOOT_ERR_DOWNGRADE;
  }

  return BOOT_OK;
}

/*
 * ============================================================================
 * BLOCK 2: Crash Cascade & Edge Mitigation (CFI Tracked)
 * ============================================================================
 */
boot_status_t boot_rollback_evaluate_os(const boot_platform_t *platform,
                                        const wal_tmr_payload_t *tmr,
                                        bool *boot_recovery_os_out) {
  if (!platform || !platform->wdt || !tmr || !boot_recovery_os_out) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* P10 Rule: Initialize out variables immediately to prevent random state
   * vulnerabilities */
  *boot_recovery_os_out = false;

  uint32_t counter = tmr->boot_failure_counter;

  /* P10 Safe Math: Overflow Verhindern für Limit Recovery */
  uint32_t limit_normal = BOOT_CONFIG_MAX_RETRIES;
  uint32_t limit_rec = limit_normal;
  if (UINT32_MAX - limit_rec >= BOOT_CONFIG_MAX_RECOVERY_RETRIES) {
    limit_rec += BOOT_CONFIG_MAX_RECOVERY_RETRIES;
  } else {
    limit_rec = UINT32_MAX;
  }

  /* Control Flow Integrity (CFI) Kaskaden-Auswertung
   * 0x11111111 = Boot App (Normal)
   * 0x22222222 = Boot Recovery OS
   * 0x44444444 = Terminal State (Panic / Deep Sleep) */
  volatile uint32_t path_flag_1 = 0;
  volatile uint32_t path_flag_2 = 0;

  if (counter <= limit_normal) {
    path_flag_1 = 0x11111111;
  } else if (counter <= limit_rec) {
    path_flag_1 = 0x22222222;
  } else {
    path_flag_1 = 0x44444444;
  }

  __asm__ volatile("nop; nop; nop;");

  if (path_flag_1 == 0x11111111 && counter <= limit_normal) {
    path_flag_2 = 0x11111111;
  } else if (path_flag_1 == 0x22222222 && counter > limit_normal &&
             counter <= limit_rec) {
    path_flag_2 = 0x22222222;
  } else if (path_flag_1 == 0x44444444 && counter > limit_rec) {
    path_flag_2 = 0x44444444;
  }

  /* P10 Defense: Wenn die CPU physikalisch manipuliert wurde (State Confusion
   * Attack), halte an! */
  if (path_flag_1 != path_flag_2 || path_flag_1 == 0) {
    boot_panic(platform, BOOT_ERR_INVALID_STATE);
  }

  /* O(1) Zuweisung der bewiesenen CFI Flags */
  if (path_flag_1 == 0x11111111) {
    *boot_recovery_os_out = false;
    return BOOT_OK;
  }

  if (path_flag_1 == 0x22222222) {
    *boot_recovery_os_out = true;
    return BOOT_OK;
  }

  /* CASE 3 (0x44444444): Zero-Day Brick / Double Failure Terminal State */
#if BOOT_CONFIG_EDGE_UNATTENDED_MODE
  if (!platform->soc || !platform->soc->enter_low_power) {
    /* Fallback Hardware-Limit: Panic / Serial Rescue falls SoC-Feature fehlt */
    boot_panic(platform, BOOT_RECOVERY_REQUESTED);
  }

  /* P10 Safe Math: Overflow- und Underflow-geschützte Exponential Backoff
   * Berechnung. Nutzt Saturation Arithmetic, um Endlos-Loops bei extremen
   * Fuzzing-Attacks abzusichern. */
  uint32_t excess_fails = (counter > limit_rec) ? (counter - limit_rec) : 1;
  uint32_t multiplier = 1;

  if (excess_fails == 1)
    multiplier = 4; /* 4h */
  else if (excess_fails == 2)
    multiplier = 12; /* 12h */
  else
    multiplier = 24; /* 24h MAX-CAP Limitierung */

  uint32_t wakeup_s = BOOT_CONFIG_BACKOFF_BASE_S;

  if (UINT32_MAX / multiplier < BOOT_CONFIG_BACKOFF_BASE_S) {
    wakeup_s = UINT32_MAX; /* Saturate auf theoretisches Limit (136 Jahre) */
  } else {
    wakeup_s = BOOT_CONFIG_BACKOFF_BASE_S * multiplier;
  }

  /* TMR-State/Intent MUSS ins WAL, BEVOR wir den SoC physikalisch schlafen
   * legen! Dadurch weiß das System nach dem Wakeup, dass es aus einem gezielten
   * Penalty-Sleep kommt. */
  wal_entry_payload_t sleep_intent;
  boot_secure_zeroize(&sleep_intent, sizeof(sleep_intent));
  sleep_intent.magic = WAL_ENTRY_MAGIC;
  sleep_intent.intent = WAL_INTENT_SLEEP_BACKOFF;
  sleep_intent.offset = wakeup_s;

  if (boot_journal_append(platform, &sleep_intent) != BOOT_OK) {
    /* Falls Flash defekt/WAL voll: Blockiere System mit Hard-Panic, um Akku-Tod
     * durch Endlos-Reboots zu verhindern */
    boot_panic(platform, BOOT_ERR_WAL_FULL);
  }

  /* System einfrieren - Hardware-Watchdog sollte hiervon entkoppelt sein laut
   * HAL-Config */
  platform->soc->enter_low_power(wakeup_s);

  /* Halt-Guard, falls Hardware enter_low_power den C-Flow unerwartet zurückgibt
   */
  while (1) {
    platform->wdt->kick();
  }
#else
  /* Attended Mode (FALSE): Bootloader blockiert. Springe in die Schicht 4a
   * Serial Rescue */
  boot_panic(platform, BOOT_RECOVERY_REQUESTED);
#endif

  return BOOT_OK; /* Unreachable */
}

/*
 * ============================================================================
 * BLOCK 3: Reverse Copy Orchestration (Zero-Allocation & Zero-Wear)
 * ============================================================================
 */
boot_status_t boot_rollback_trigger_revert(const boot_platform_t *platform) {
  if (!platform || !platform->flash || !platform->wdt) {
    return BOOT_ERR_INVALID_ARG;
  }

  boot_status_t status = BOOT_OK;
  uint32_t physical_app_erases = 0;

  /* 1. Lese den Magic-Header aus dem Staging-Slot (Source) */
  toob_image_header_t backup_header;
  boot_secure_zeroize(&backup_header, sizeof(backup_header));

  platform->wdt->kick();
  status =
      platform->flash->read(CHIP_STAGING_SLOT_ABS_ADDR,
                            (uint8_t *)&backup_header, sizeof(backup_header));
  platform->wdt->kick();

  if (status != BOOT_OK) {
    return status;
  }

  /* 2. P10 Glitch-Proof Bounds Check (Verhindert Flash-Exploits durch
   * Header-Fakes) */
  volatile uint32_t hdr_shield_1 = 0;
  volatile uint32_t hdr_shield_2 = 0;

  if (backup_header.magic == TOOB_MAGIC_HEADER &&
      backup_header.image_size > 0 && backup_header.image_size != 0xFFFFFFFF) {
    hdr_shield_1 = BOOT_OK;
  }

  __asm__ volatile("nop; nop;");

  if (hdr_shield_1 == BOOT_OK && backup_header.magic == TOOB_MAGIC_HEADER) {
    hdr_shield_2 = BOOT_OK;
  }

  if (hdr_shield_1 != BOOT_OK || hdr_shield_2 != BOOT_OK) {
    return BOOT_ERR_NOT_FOUND;
  }

  if (backup_header.image_size > CHIP_APP_SLOT_SIZE) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  /* Subtraktiver OOB-Check zum Schutz vor 32-Bit Adress-Wrapping */
  if ((UINT32_MAX - CHIP_STAGING_SLOT_ABS_ADDR < backup_header.image_size) ||
      (UINT32_MAX - CHIP_APP_SLOT_ABS_ADDR < backup_header.image_size)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  /* 3. Resume-Logik (Brownout-Recovery) & Intent-Checkpointing */
  wal_entry_payload_t pending_intent;
  boot_secure_zeroize(&pending_intent, sizeof(pending_intent));

  uint32_t dummy_accum = 0;
  status =
      boot_journal_reconstruct_txn(platform, &pending_intent, &dummy_accum);
  if (status != BOOT_OK && status != BOOT_ERR_STATE) {
    return status;
  }

  uint32_t current_offset = 0;

  if (pending_intent.intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
    /* Brownout Recovery: Wir spulen auf den letzten sicheren WAL-Zustand vor */
    current_offset = pending_intent.delta_chunk_id;
    if (current_offset > backup_header.image_size) {
      current_offset = backup_header.image_size;
    }
  } else {
    /* Initialisiere neuen Rollback-Prozess atomar im WAL (Tearing-Schild) */
    boot_secure_zeroize(&pending_intent, sizeof(pending_intent));
    pending_intent.magic = WAL_ENTRY_MAGIC;
    pending_intent.intent = WAL_INTENT_TXN_ROLLBACK_PENDING;
    pending_intent.delta_chunk_id = 0;
    status = boot_journal_append(platform, &pending_intent);
    if (status != BOOT_OK)
      return status;
  }

  const uint32_t MAX_LOOP_GUARD = 100000;
  uint32_t loop_iter = 0;

  /* 4. ZERO-ALLOCATION Copy-Schleife (Nutzt die ohnehin freie crypto_arena) */
  while (current_offset < backup_header.image_size) {
    if (++loop_iter > MAX_LOOP_GUARD) {
      boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
      return BOOT_ERR_FLASH_HW; /* Anti-Endless-Loop Guard */
    }

    platform->wdt->kick();

    uint32_t src = CHIP_STAGING_SLOT_ABS_ADDR + current_offset;
    uint32_t dst = CHIP_APP_SLOT_ABS_ADDR + current_offset;

    size_t dst_sec_size = 0;
    status = platform->flash->get_sector_size(dst, &dst_sec_size);
    if (status != BOOT_OK || dst_sec_size == 0 ||
        dst_sec_size > CHIP_FLASH_MAX_SECTOR_SIZE) {
      boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
      return BOOT_ERR_FLASH_HW;
    }

    size_t copy_size = dst_sec_size;
    if (current_offset + copy_size > backup_header.image_size) {
      copy_size = backup_header.image_size - current_offset;
      /* Padding Alignment Guard für den finalen Block */
      if (platform->flash->write_align > 0) {
        uint32_t align = platform->flash->write_align;
        uint32_t rem = copy_size % align;
        if (rem != 0)
          copy_size += (align - rem);
      }
    }

    /* ====================================================================
     * 4.a O(1) ZERO-WEAR IDENTITY CHECK
     * Schützt das Dateisystem vor Burnout. Chunk-weiser Abgleich im RAM.
     * ==================================================================== */
    bool is_identical = true;
    uint32_t chk_off = 0;

    while (chk_off < copy_size) {
      platform->wdt->kick();

      /* Splitten der crypto_arena in zwei Hälften für Source/Dest Check */
      size_t step = (copy_size - chk_off > (BOOT_CRYPTO_ARENA_SIZE / 2))
                        ? (BOOT_CRYPTO_ARENA_SIZE / 2)
                        : (copy_size - chk_off);
      uint8_t *buf_dst = crypto_arena;
      uint8_t *buf_src = crypto_arena + step;

      if (platform->flash->read(dst + chk_off, buf_dst, step) != BOOT_OK ||
          platform->flash->read(src + chk_off, buf_src, step) != BOOT_OK) {
        is_identical = false;
        break;
      }

      if (memcmp(buf_dst, buf_src, step) != 0) {
        is_identical = false;
        break;
      }
      chk_off += step;
    }

    if (is_identical) {
      /* Identisch: Fast-Forward zum nächsten Sektor ohne Erase/Write Last! */
      current_offset += dst_sec_size;
      continue;
    }

    /* ====================================================================
     * 4.b Physikalische Wiederherstellung & WAL-Checkpointing
     * ==================================================================== */

    /* WAL Checkpoint VOR der Destruktion des App-Sektors setzen! */
    pending_intent.delta_chunk_id = current_offset;
    status = boot_journal_append(platform, &pending_intent);
    if (status != BOOT_OK) {
      boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
      return status;
    }

    /* Hardware Erase mit WDT Protection (Tearing-Tracked) */
    status = boot_swap_erase_safe(platform, dst, dst_sec_size);
    if (status != BOOT_OK) {
      boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
      return status;
    }
    physical_app_erases++;

    /* 4.c Chunk-weiser Copy & Phase-Bound Verify (ECC-Proof) */
    uint32_t wr_off = 0;
    while (wr_off < copy_size) {
      platform->wdt->kick();
      size_t step = (copy_size - wr_off > BOOT_CRYPTO_ARENA_SIZE)
                        ? BOOT_CRYPTO_ARENA_SIZE
                        : (copy_size - wr_off);

      /* Lese Source in gesamte Arena */
      status = platform->flash->read(src + wr_off, crypto_arena, step);
      if (status != BOOT_OK) {
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
        return status;
      }

      uint32_t src_crc = compute_boot_crc32(crypto_arena, step);

      /* Schreibe Target */
      status = platform->flash->write(dst + wr_off, crypto_arena, step);
      if (status != BOOT_OK) {
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
        return status;
      }

      /* Phase-Bound Verify: Lese Dest zurück und prüfe ECC-Integrität! */
      status = platform->flash->read(dst + wr_off, crypto_arena, step);
      if (status != BOOT_OK) {
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
        return status;
      }

      uint32_t dst_crc = compute_boot_crc32(crypto_arena, step);
      if (src_crc != dst_crc) {
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
        return BOOT_ERR_FLASH_HW; /* FATAL: Bit-Rot bei Hardware Write! */
      }

      wr_off += step;
    }

    current_offset += dst_sec_size;
  }

  /* O(1) Zeroize des Scratchpads, das unverschlüsselte Firmware hielt */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  /* 5. Telemetrie & Isolierter Rollback-Intent Abschluss
   * Signalisiert dem nächsten Reset, dass das Rescue-Image verankert ist und
   * die Failure-Counters wieder regulär anlaufen dürfen. */
  if (physical_app_erases > 0) {
    wal_tmr_payload_t update_tmr;
    if (boot_journal_get_tmr(platform, &update_tmr) == BOOT_OK) {
      update_tmr.app_slot_erase_counter += physical_app_erases;
      (void)boot_journal_update_tmr(platform, &update_tmr);
    }
  }

  wal_entry_payload_t revert_intent;
  boot_secure_zeroize(&revert_intent, sizeof(revert_intent));
  revert_intent.magic = WAL_ENTRY_MAGIC;
  revert_intent.intent = WAL_INTENT_TXN_ROLLBACK;

  status = boot_journal_append(platform, &revert_intent);

  return status;
}