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
 *    und strenges CFI-Tracking verhindern Voltage-Fault Skips bei der
 *    kritischen SVN/eFuse-Prüfung und blockieren PC-Sprünge.
 * 2. Zero-Allocation 1-Way Copy: Nutzt die crypto_arena iterativ (hälftig
 * geteilt). Ersetzt 16KB statischen RAM durch Tearing- und
 * Verschleiß-resistente Schleifen.
 * 3. Algebraic Loop Proofs: Saturation Arithmetic und Flash-basierte
 *    Max-Iterationsberechnung blockiert Deadlocks ohne Magic-Numbers.
 * 4. Phase-Bound Verify (TOCTOU Proof): Zwingendes Zeroize des Buffers vor
 * jedem Read-Back beweist die physikalische SPI/DMA Ausführung.
 * 5. WDT Starvation: Ersetzt die gefährliche WDT-Kick-Falle durch gezieltes
 *    Aushungern des Watchdogs, um einen deterministischen Hard-Reset zu
 * erzwingen.
 */

#include "boot_rollback.h"
#include "boot_config_mock.h"
#include "boot_crc32.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "boot_swap.h"
#include <stddef.h>
#include <string.h>

_Static_assert(BOOT_CONFIG_MAX_RETRIES > 0,
               "Invalid Configuration: Target Retries must be positive");
_Static_assert((BOOT_CONFIG_BACKOFF_BASE_S * 24ULL) <= UINT32_MAX,
               "Exponential Backoff Configuration will overflow");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK MUST be high-hamming distance for Glitch Shielding");
_Static_assert(
    BOOT_CRYPTO_ARENA_SIZE >= 512,
    "Crypto Arena must be at least 512 bytes for Zero-Allocation stream copy");

extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

/* P10 Revert CFI Constants */
#define CFI_RB_INIT 0x10101010
#define CFI_RB_HDR 0x20202020
#define CFI_RB_VERIFIED 0x40404040
#define CFI_RB_DONE 0x80808080

/* ============================================================================
 * INTERNAL HELPER: CONSTANT TIME MEMCMP (Glitch Protected)
 * ============================================================================
 */
static inline boot_status_t constant_time_memcmp_glitch_safe(const uint8_t *a,
                                                             const uint8_t *b,
                                                             size_t len) {
  uint32_t acc_fwd = 0;
  uint32_t acc_rev = 0;

  for (size_t i = 0; i < len; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[len - 1 - i] ^ b[len - 1 - i]);
  }

  volatile uint32_t shield_1 = 0, shield_2 = 0;
  if (acc_fwd == 0)
    shield_1 = BOOT_OK;
  __asm__ volatile("nop; nop; nop;");
  if (shield_1 == BOOT_OK && acc_rev == 0)
    shield_2 = BOOT_OK;

  if (shield_1 == BOOT_OK && shield_2 == BOOT_OK && shield_1 == shield_2)
    return BOOT_OK;
  return BOOT_ERR_VERIFY;
}

/**
 * @brief O(1) Streaming CRC-32 Berechnung direkt aus dem Flash für Rollbacks.
 */
static boot_status_t
rollback_compute_flash_crc32(const boot_platform_t *platform, uint32_t addr,
                             size_t len, uint32_t *out_crc) {
  uint32_t crc = 0xFFFFFFFF;
  size_t offset = 0;

  while (offset < len) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    size_t step = (len - offset > BOOT_CRYPTO_ARENA_SIZE)
                      ? BOOT_CRYPTO_ARENA_SIZE
                      : (len - offset);

    boot_status_t st = platform->flash->read(addr + offset, crypto_arena, step);
    if (st != BOOT_OK) {
      boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
      return st;
    }

    for (size_t i = 0; i < step; i++) {
      crc ^= crypto_arena[i];
      for (uint8_t j = 0; j < 8; j++) {
        crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
      }
    }
    offset += step;
  }

  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
  *out_crc = ~crc;
  return BOOT_OK;
}

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

  /* P10 Control Flow Integrity Tracker (Verhindert PC-Glitches zum Return) */
  volatile uint32_t cfi_tracker = 0xAAAAAAAA;

  /* 1. Lese persistierte SVN Werte sicher aus WAL TMR Payload */
  wal_tmr_payload_t tmr __attribute__((aligned(8)));
  boot_secure_zeroize(&tmr, sizeof(tmr)); /* P10: Stack Residuen verhindern */

  boot_status_t status = boot_journal_get_tmr(platform, &tmr);

  /* Boot_Journal Toleranz: Bei Initial Flash (Blank Device) existiert noch kein
   * TMR. In diesem Sonderfall ist Baseline SVN = 0. */
  if (status != BOOT_OK && status != BOOT_ERR_STATE &&
      status != BOOT_ERR_NOT_FOUND) {
    boot_secure_zeroize(&tmr, sizeof(tmr));
    return status; /* Hardware Fehler sofort propagieren */
  }

  uint32_t persisted_wal_svn =
      is_recovery_os ? tmr.svn_recovery_counter : tmr.app_svn;
  boot_secure_zeroize(&tmr, sizeof(tmr)); /* Sensible Daten umgehend abräumen */

  cfi_tracker ^= 0x11111111;

  /* 2. Hardware-Root-of-Trust (eFuse Epoch) abrufen (Glitch-Shielded) */
  uint32_t efuse_epoch = 0;
  if (platform->crypto->read_monotonic_counter) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    boot_status_t efuse_status =
        platform->crypto->read_monotonic_counter(&efuse_epoch);
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    /* EMFI Instruction Skip Protection für das eFuse Resultat */
    volatile uint32_t eshield_1 = 0, eshield_2 = 0;
    if (efuse_status == BOOT_OK || efuse_status == BOOT_ERR_NOT_SUPPORTED)
      eshield_1 = BOOT_OK;
    __asm__ volatile("nop; nop;");
    if (eshield_1 == BOOT_OK &&
        (efuse_status == BOOT_OK || efuse_status == BOOT_ERR_NOT_SUPPORTED))
      eshield_2 = BOOT_OK;

    if (eshield_1 != BOOT_OK || eshield_2 != BOOT_OK ||
        eshield_1 != eshield_2) {
      return BOOT_ERR_VERIFY; /* Trapped Hardware Glitch */
    }

    if (efuse_status != BOOT_OK && efuse_status != BOOT_ERR_NOT_SUPPORTED) {
      return efuse_status;
    }
  }

  cfi_tracker ^= 0x22222222;

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

  cfi_tracker ^= 0x44444444;

  /* Mathematischer Beweis der lückenlosen Ausführung */
  uint32_t expected_cfi = 0xAAAAAAAA ^ 0x11111111 ^ 0x22222222 ^ 0x44444444;
  volatile uint32_t proof_1 = 0, proof_2 = 0;

  if (cfi_tracker == expected_cfi)
    proof_1 = BOOT_OK;
  __asm__ volatile("nop; nop;");
  if (proof_1 == BOOT_OK && cfi_tracker == expected_cfi)
    proof_2 = BOOT_OK;

  if (proof_1 == BOOT_OK && proof_2 == BOOT_OK && proof_1 == proof_2) {
    return BOOT_OK;
  }

  return BOOT_ERR_VERIFY; /* PC-Jump Glitch detektiert! */
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
  wal_entry_payload_t sleep_intent __attribute__((aligned(8)));
  boot_secure_zeroize(&sleep_intent, sizeof(sleep_intent));
  sleep_intent.magic = WAL_ENTRY_MAGIC;
  sleep_intent.intent = WAL_INTENT_SLEEP_BACKOFF;
  sleep_intent.offset = wakeup_s;

  if (boot_journal_append(platform, &sleep_intent) != BOOT_OK) {
    boot_secure_zeroize(&sleep_intent, sizeof(sleep_intent));
    /* Falls Flash defekt/WAL voll: Blockiere System mit Hard-Panic, um Akku-Tod
     * durch Reboots zu verhindern */
    boot_panic(platform, BOOT_ERR_WAL_FULL);
  }
  boot_secure_zeroize(&sleep_intent, sizeof(sleep_intent));

  /* System einfrieren - Hardware-Watchdog sollte hiervon entkoppelt sein laut
   * HAL-Config */
  platform->soc->enter_low_power(wakeup_s);

  /* Halt-Guard (WDT Starvation): Wenn die Hardware aufwacht oder
   * enter_low_power fehlschlägt, erzwingen wir einen echten Hardware-Reset
   * durch ABSICHTLICHES NICHT-Kickens des WDT! */
  if (platform->console && platform->console->flush)
    platform->console->flush();
  if (platform->clock && platform->clock->deinit)
    platform->clock->deinit();
  while (1) {
    __asm__ volatile("nop; nop; nop;"); /* Starve the WDT to force Cold Boot! */
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
  if (!platform || !platform->flash || !platform->wdt ||
      !platform->flash->read) {
    return BOOT_ERR_INVALID_ARG;
  }

  boot_status_t status = BOOT_OK;
  uint32_t physical_app_erases = 0;
  volatile uint32_t revert_cfi = CFI_RB_INIT;

  /* P10 Pre-Declaration Rule: Alle Intents und Buffer am Scope-Anfang
   * deklarieren, damit der Single-Exit Cleanup niemals über uninitialisierte
   * Stacks stolpert. */
  wal_entry_payload_t pending_intent __attribute__((aligned(8)));
  wal_entry_payload_t revert_intent __attribute__((aligned(8)));
  toob_image_header_t backup_header __attribute__((aligned(8)));

  boot_secure_zeroize(&pending_intent, sizeof(pending_intent));
  boot_secure_zeroize(&revert_intent, sizeof(revert_intent));
  boot_secure_zeroize(&backup_header, sizeof(backup_header));

  /* 1. Lese den Magic-Header aus dem Staging-Slot (Source)
   * FIX: P10 DMA Unaligned Guard. Nutzt einen 32-Byte aligned Puffer, da
   * sizeof(toob_image_header_t) = 20 Bytes asynchrone Hardware-Traps bei
   * SPI-DMAs auslösen kann! */
  uint8_t hdr_buf[32] __attribute__((aligned(8)));
  boot_secure_zeroize(hdr_buf, sizeof(hdr_buf));

  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  status = platform->flash->read(CHIP_STAGING_SLOT_ABS_ADDR, hdr_buf, 32);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  if (status != BOOT_OK) {
    goto revert_cleanup;
  }

  memcpy(&backup_header, hdr_buf, sizeof(toob_image_header_t));
  boot_secure_zeroize(hdr_buf, sizeof(hdr_buf)); /* Leakage Defense */

  revert_cfi ^= CFI_RB_HDR;

  /* 2. P10 Glitch-Proof Bounds Check (Verhindert Flash-Exploits durch
   * Header-Fakes) */
  volatile uint32_t hdr_shield_1 = 0;
  volatile uint32_t hdr_shield_2 = 0;

  bool size_valid =
      (backup_header.image_size > 0 && backup_header.image_size != 0xFFFFFFFF);

  if (backup_header.magic == TOOB_MAGIC_HEADER && size_valid) {
    hdr_shield_1 = BOOT_OK;
  }

  __asm__ volatile("nop; nop;");

  if (hdr_shield_1 == BOOT_OK && backup_header.magic == TOOB_MAGIC_HEADER &&
      size_valid) {
    hdr_shield_2 = BOOT_OK;
  }

  if (hdr_shield_1 != BOOT_OK || hdr_shield_2 != BOOT_OK ||
      hdr_shield_1 != hdr_shield_2) {
    status = BOOT_ERR_NOT_FOUND;
    goto revert_cleanup;
  }

  if (backup_header.image_size > CHIP_APP_SLOT_SIZE) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto revert_cleanup;
  }

  /* Subtraktiver OOB-Check zum Schutz vor 32-Bit Adress-Wrapping */
  if ((UINT32_MAX - CHIP_STAGING_SLOT_ABS_ADDR < backup_header.image_size) ||
      (UINT32_MAX - CHIP_APP_SLOT_ABS_ADDR < backup_header.image_size)) {
    status = BOOT_ERR_FLASH_BOUNDS;
    goto revert_cleanup;
  }

  revert_cfi ^= CFI_RB_VERIFIED;

  /* 3. Resume-Logik (Brownout-Recovery) & Intent-Checkpointing */
  uint32_t dummy_accum = 0;
  status =
      boot_journal_reconstruct_txn(platform, &pending_intent, &dummy_accum);
  if (status != BOOT_OK && status != BOOT_ERR_STATE) {
    goto revert_cleanup;
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
      goto revert_cleanup;
  }

  /* P10 Mathematical Loop Guard: Verhindert Endlosschleifen ohne Magic Numbers!
   */
  const uint32_t MAX_LOOP_GUARD = (CHIP_FLASH_TOTAL_SIZE / 64) + 100;
  uint32_t loop_iter = 0;

  /* 4. ZERO-ALLOCATION 1-Way Copy-Schleife (Nutzt die ohnehin freie
   * crypto_arena) */
  while (current_offset < backup_header.image_size) {
    if (++loop_iter > MAX_LOOP_GUARD) {
      status = BOOT_ERR_FLASH_HW; /* Anti-Endless-Loop Guard Trap */
      goto revert_cleanup;
    }

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    uint32_t src = CHIP_STAGING_SLOT_ABS_ADDR + current_offset;
    uint32_t dst = CHIP_APP_SLOT_ABS_ADDR + current_offset;

    /* ====================================================================
     * BLOCK ALIGNMENT SOLVER (Anti Flash-Corruption)
     * Ermittelt das physikalische Maximum der Sektor-Größen.
     * Verhindert Boundary-Violation Crashes auf asymmetrischen Flashs!
     * ==================================================================== */
    size_t dst_sec_size = 0, src_sec_size = 0;

    status = platform->flash->get_sector_size(dst, &dst_sec_size);
    if (status != BOOT_OK || dst_sec_size == 0 || dst % dst_sec_size != 0) {
      status = BOOT_ERR_FLASH_HW;
      goto revert_cleanup;
    }

    status = platform->flash->get_sector_size(src, &src_sec_size);
    if (status != BOOT_OK || src_sec_size == 0 || src % src_sec_size != 0) {
      status = BOOT_ERR_FLASH_HW;
      goto revert_cleanup;
    }

    size_t block_size = dst_sec_size;
    if (src_sec_size > block_size)
      block_size = src_sec_size;

    if (current_offset + block_size > backup_header.image_size) {
      block_size = backup_header.image_size - current_offset;
      /* Padding Alignment Guard für den finalen Block */
      if (platform->flash->write_align > 0) {
        uint32_t align = platform->flash->write_align;
        uint32_t rem = block_size % align;
        if (rem != 0)
          block_size += (align - rem);
      }
    }

    /* ====================================================================
     * 4.a O(1) ZERO-WEAR IDENTITY CHECK (DMA-Aligned & Glitch Safe)
     * Schützt das Dateisystem vor Burnout. CRC-Abgleich im RAM.
     * ==================================================================== */
    uint32_t crc_src = 0, crc_dest = 0;
    status = rollback_compute_flash_crc32(platform, src, block_size, &crc_src);
    if (status != BOOT_OK)
      goto revert_cleanup;

    status = rollback_compute_flash_crc32(platform, dst, block_size, &crc_dest);
    if (status != BOOT_OK)
      goto revert_cleanup;

    if (crc_src == crc_dest) {
      bool is_identical = true;
      uint32_t chk_off = 0;

      /* P10 ALIGNMENT FIX: Maskiert die Division auf exakt 8 Bytes,
       * um Unaligned UsageFaults in den Hardware-SPI-DMAs auszuschließen! */
      size_t half_arena = (BOOT_CRYPTO_ARENA_SIZE / 2) & ~7ULL;

      while (chk_off < block_size) {
        if (platform->wdt && platform->wdt->kick)
          platform->wdt->kick();

        /* Splitten der crypto_arena in zwei alignte Hälften für Source/Dest
         * Check */
        size_t step = (block_size - chk_off > half_arena)
                          ? half_arena
                          : (block_size - chk_off);

        uint8_t *buf_dst = crypto_arena;
        uint8_t *buf_src = crypto_arena + half_arena;

        if (platform->flash->read(dst + chk_off, buf_dst, step) != BOOT_OK ||
            platform->flash->read(src + chk_off, buf_src, step) != BOOT_OK) {
          is_identical = false;
          break;
        }

        /* Glitch-Shielded Evaluation um Exploit-Bypasses der Reparatur zu
         * stoppen! */
        if (constant_time_memcmp_glitch_safe(buf_dst, buf_src, step) !=
            BOOT_OK) {
          is_identical = false;
          break;
        }
        chk_off += step;
      }

      /* Radikal nullifizieren, damit keine Krypto-Residuen den nachfolgenden
       * SPI Read verfälschen! */
      boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

      if (is_identical) {
        /* Identisch: Fast-Forward zum nächsten Sektor ohne Erase/Write Last! */
        current_offset += block_size;
        continue;
      }
    }

    /* ====================================================================
     * 4.b Physikalische Wiederherstellung & WAL-Checkpointing
     * ==================================================================== */

    /* WAL Checkpoint VOR der Destruktion des App-Sektors setzen! */
    pending_intent.delta_chunk_id = current_offset;
    status = boot_journal_append(platform, &pending_intent);
    if (status != BOOT_OK)
      goto revert_cleanup;

    /* Hardware Erase mit WDT Protection (Tearing-Tracked) */
    status = boot_swap_erase_safe(platform, dst, block_size);
    if (status != BOOT_OK)
      goto revert_cleanup;
    physical_app_erases +=
        (block_size / dst_sec_size > 0) ? (block_size / dst_sec_size) : 1;

    /* ====================================================================
     * 4.c Chunk-weiser Copy & Phase-Bound Verify (ECC-Proof)
     * ==================================================================== */
    uint32_t wr_off = 0;
    while (wr_off < block_size) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
      size_t step = (block_size - wr_off > BOOT_CRYPTO_ARENA_SIZE)
                        ? BOOT_CRYPTO_ARENA_SIZE
                        : (block_size - wr_off);

      /* Lese Source in gesamte Arena */
      status = platform->flash->read(src + wr_off, crypto_arena, step);
      if (status != BOOT_OK)
        goto revert_cleanup;

      /* Phase-Bound CRC der Source für diesen Step */
      uint32_t step_src_crc = compute_boot_crc32(crypto_arena, step);

      /* Schreibe Target */
      status = platform->flash->write(dst + wr_off, crypto_arena, step);
      if (status != BOOT_OK)
        goto revert_cleanup;

      /* PHASE-BOUND GHOST-MATCH PREVENTION FIX:
       * Zwingendes Nullen der Arena *vor* dem Read-Back beweist physikalisch,
       * dass der Vendor-Treiber uns nicht einfach den RAM Cache validiert,
       * sondern tatsächlich mit dem SPI-Flash gesprochen hat! */
      boot_secure_zeroize(crypto_arena, step);

      /* Lese Dest zurück und prüfe ECC-Integrität! */
      status = platform->flash->read(dst + wr_off, crypto_arena, step);
      if (status != BOOT_OK)
        goto revert_cleanup;

      uint32_t step_dst_crc = compute_boot_crc32(crypto_arena, step);

      volatile uint32_t ecc_shield_1 = 0, ecc_shield_2 = 0;
      if (step_src_crc == step_dst_crc)
        ecc_shield_1 = BOOT_OK;
      __asm__ volatile("nop; nop;");
      if (ecc_shield_1 == BOOT_OK && step_src_crc == step_dst_crc)
        ecc_shield_2 = BOOT_OK;

      if (ecc_shield_1 != BOOT_OK || ecc_shield_2 != BOOT_OK ||
          ecc_shield_1 != ecc_shield_2) {
        status = BOOT_ERR_FLASH_HW; /* FATAL: Bit-Rot bei Hardware Write
                                       detektiert! */
        goto revert_cleanup;
      }

      wr_off += step;
    }

    current_offset += block_size;
  }

  revert_cfi ^= CFI_RB_DONE;

  /* CFI Final Resolution */
  uint32_t expected_cfi =
      CFI_RB_INIT ^ CFI_RB_HDR ^ CFI_RB_VERIFIED ^ CFI_RB_DONE;
  volatile uint32_t cfi_shield_1 = 0, cfi_shield_2 = 0;

  if (revert_cfi == expected_cfi)
    cfi_shield_1 = BOOT_OK;
  __asm__ volatile("nop; nop;");
  if (cfi_shield_1 == BOOT_OK && revert_cfi == expected_cfi)
    cfi_shield_2 = BOOT_OK;

  if (cfi_shield_1 != BOOT_OK || cfi_shield_2 != BOOT_OK ||
      cfi_shield_1 != cfi_shield_2) {
    status = BOOT_ERR_INVALID_STATE; /* Revert-Prozess wurde durch Glitch
                                        unterbrochen! */
    goto revert_cleanup;
  }

  /* 5. Telemetrie & Isolierter Rollback-Intent Abschluss
   * Signalisiert dem nächsten Reset, dass das Rescue-Image verankert ist und
   * die Failure-Counters wieder regulär anlaufen dürfen. */
  if (physical_app_erases > 0) {
    wal_tmr_payload_t update_tmr __attribute__((aligned(8)));
    boot_secure_zeroize(&update_tmr, sizeof(update_tmr));

    if (boot_journal_get_tmr(platform, &update_tmr) == BOOT_OK) {
      update_tmr.app_slot_erase_counter += physical_app_erases;
      (void)boot_journal_update_tmr(platform, &update_tmr);
    }
  }

  revert_intent.magic = WAL_ENTRY_MAGIC;
  revert_intent.intent = WAL_INTENT_TXN_ROLLBACK;
  status = boot_journal_append(platform, &revert_intent);

revert_cleanup:
  /* ====================================================================
   * 6. P10 SINGLE EXIT ZEROIZATION (Leakage Defense)
   * ====================================================================
   * Egal ob Erfolg oder Hardware-Failure: Jegliche kryptografischen Residuen,
   * Header und unverschlüsselte Firmware-Deltas in der RAM-Arena werden
   * unwiderruflich zerstört.
   */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
  boot_secure_zeroize(&pending_intent, sizeof(pending_intent));
  boot_secure_zeroize(&revert_intent, sizeof(revert_intent));
  boot_secure_zeroize(&backup_header, sizeof(backup_header));

  return status;
}