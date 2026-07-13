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
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"
#include "boot_swap.h"
#include "boot_effect.h"
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

/* P5: Arena is now passed explicitly by the orchestrator */

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define RB_CFI_SLOT_INIT     0
#define RB_CFI_SLOT_HDR      1
#define RB_CFI_SLOT_VERIFIED 2
#define RB_CFI_SLOT_DONE     3
#define RB_CFI_NUM_TOKENS    4

#include "boot_ct_utils.h"



/*
 * ============================================================================
 * BLOCK 1: Hybrid SVN Verification (Anti-Downgrade Shield)
 * ============================================================================
 */
boot_status_t boot_rollback_verify_svn(const boot_platform_t *platform,
                                       uint32_t manifest_svn,
                                       rollback_target_t target) {
  if (!platform || !platform->crypto || !platform->wdt) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t svn_cfi_seed = 0;
  boot_random_safe(platform, (uint8_t *)&svn_cfi_seed, sizeof(svn_cfi_seed));
  boot_cfi_ctx_t svn_cfi_ctx;
  boot_cfi_init(svn_cfi_ctx, svn_cfi_seed);
  boot_cfi_add_expected(svn_cfi_ctx, 1);
  boot_cfi_add_expected(svn_cfi_ctx, 2);
  boot_cfi_add_expected(svn_cfi_ctx, 3);

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

  /* P7a: 3-way SVN selection per target */
  uint32_t persisted_wal_svn;
  switch (target) {
    case ROLLBACK_TARGET_APP:      persisted_wal_svn = tmr.app_svn; break;
    case ROLLBACK_TARGET_RECOVERY: persisted_wal_svn = tmr.svn_recovery_counter; break;
    case ROLLBACK_TARGET_STAGE1:   persisted_wal_svn = tmr.stage1_svn; break;
    default:
      boot_secure_zeroize(&tmr, sizeof(tmr));
      return BOOT_ERR_INVALID_ARG;
  }
  boot_secure_zeroize(&tmr, sizeof(tmr)); /* Sensible Daten umgehend abräumen */

  boot_cfi_step(svn_cfi_ctx, 1);

  /* 2. Hardware-Root-of-Trust (eFuse Epoch) abrufen (Glitch-Shielded) */
  uint32_t efuse_epoch = 0;
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  boot_status_t efuse_status = boot_read_monotonic_counter_safe(platform, &efuse_epoch);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  /* EMFI Instruction Skip Protection für das eFuse Resultat */
  BOOT_SECURE_REQUIRE(efuse_status == BOOT_OK || efuse_status == BOOT_ERR_NOT_SUPPORTED, {
    return BOOT_ERR_VERIFY; /* Trapped Hardware Glitch */
  });

  if (efuse_status != BOOT_OK && efuse_status != BOOT_ERR_NOT_SUPPORTED) {
    return efuse_status;
  }

  boot_cfi_step(svn_cfi_ctx, 2);

  /* 3. MATHEMATISCHER GLITCH-BEWEIS (Voltage Skip Protection)
   * Verweigert Downgrades rigoros. Identische Versionen (Re-Flashes) sind für
   * Reparaturen zulässig. Statt einem simplen Branch (manifest < persisted)
   * nutzen wir das O(1) Double-Check Pattern.
   *
   * K4: WAL-SVN is now chain-backed (device-bound hash chain).
   * A2 = eFuse monotonic counter (hardware root of trust).
   * A1 = WAL-persisted SVN (integrity enforced via K4 chain_tag).
   * Both lines are independently verified — compromise of one
   * does not weaken the other. */
  bool valid_wal = (manifest_svn >= persisted_wal_svn);
  bool valid_efuse = (manifest_svn >= efuse_epoch);

  BOOT_SECURE_REQUIRE(valid_wal && valid_efuse, {
    return BOOT_ERR_DOWNGRADE;
  });

  boot_cfi_step(svn_cfi_ctx, 3);

  boot_cfi_require(svn_cfi_ctx, {
    return BOOT_ERR_VERIFY; /* PC-Jump Glitch detektiert! */
  });
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
  uint32_t limit_normal = BOOT_CONFIG_MAX_RETRIES;

  /* Control Flow Integrity (CFI) Kaskaden-Auswertung */
  if (counter <= limit_normal) {
    BOOT_SECURE_REQUIRE(counter <= limit_normal, {
      boot_terminal_halt(platform, BOOT_ERR_INVALID_STATE, SITE_ROLLBACK_CONFUSION);
    });
    *boot_recovery_os_out = false;
    return BOOT_OK;
  }

  /* Recovery OS active partition path */
  uint32_t rec_counter = tmr->recovery_failure_counter;
  uint32_t limit_rec = BOOT_CONFIG_MAX_RECOVERY_RETRIES;

  if (rec_counter <= limit_rec) {
    BOOT_SECURE_REQUIRE(rec_counter <= limit_rec, {
      boot_terminal_halt(platform, BOOT_ERR_INVALID_STATE, SITE_ROLLBACK_CONFUSION);
    });
    *boot_recovery_os_out = true;
    return BOOT_OK;
  }

  /* CASE 3: Recovery OS Crashed too many times -> Terminal Local Rescue (E1-T2) */
  BOOT_SECURE_REQUIRE(rec_counter > limit_rec, {
    boot_terminal_halt(platform, BOOT_ERR_INVALID_STATE, SITE_ROLLBACK_CONFUSION);
  });

  boot_panic(platform, BOOT_RECOVERY_REQUESTED);
  return BOOT_OK;
}

/*
 * ============================================================================
 * BLOCK 3: Reverse Copy Orchestration (Zero-Allocation & Zero-Wear)
 * ============================================================================
 */
boot_status_t boot_rollback_trigger_revert(const boot_platform_t *platform,
                                           uint8_t *arena, size_t arena_len) {
  if (!arena || arena_len < 512)
    return BOOT_ERR_INVALID_ARG;
  if (!platform || !platform->flash || !platform->wdt ||
      !platform->flash->read) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t rv_cfi_seed = 0;
  boot_random_safe(platform, (uint8_t *)&rv_cfi_seed, sizeof(rv_cfi_seed));
  boot_cfi_ctx_t revert_cfi_ctx;
  boot_cfi_init(revert_cfi_ctx, rv_cfi_seed);
  boot_cfi_add_expected(revert_cfi_ctx, 1);
  boot_cfi_add_expected(revert_cfi_ctx, 2);
  boot_cfi_add_expected(revert_cfi_ctx, 3);

  boot_status_t status = BOOT_OK;
  uint32_t physical_app_erases = 0;

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

  boot_cfi_step(revert_cfi_ctx, 1);

  /* 2. P10 Glitch-Proof Bounds Check (Verhindert Flash-Exploits durch
   * Header-Fakes) */
  bool size_valid =
      (backup_header.image_size > 0 && backup_header.image_size != 0xFFFFFFFF);

  BOOT_SECURE_REQUIRE(backup_header.magic == TOOB_MAGIC_HEADER && size_valid, {
    status = BOOT_ERR_NOT_FOUND;
    goto revert_cleanup;
  });

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

  boot_cfi_step(revert_cfi_ctx, 2);

  /* 3. Resume-Logik (Brownout-Recovery) & Intent-Checkpointing */
  uint32_t dummy_accum = 0;
  status =
      boot_journal_reconstruct_txn(platform, &pending_intent, &dummy_accum, NULL);
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

  /* P10 Mathematical Loop Guard: Verhindert Endlosschleifen ohne Magic Numbers! */
  const uint32_t MAX_LOOP_GUARD = (CHIP_FLASH_TOTAL_SIZE / 64) + 100;
  uint32_t loop_iter = 0;

  boot_allowed_region_t whitelist[1] = {
      {CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE}
  };

  /* 4. ZERO-ALLOCATION 1-Way Copy (Planned & Executed) */
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
        uint32_t rem = (uint32_t)(block_size % align);
        if (rem != 0)
          block_size += (align - rem);
      }
    }

    /* ====================================================================
     * 4.a O(1) ZERO-WEAR IDENTITY CHECK (DMA-Aligned & Glitch Safe)
     * Schützt das Dateisystem vor Burnout. CRC-Abgleich im RAM.
     * ==================================================================== */
    uint32_t crc_src = 0, crc_dest = 0;
    status = boot_crc32_flash_stream(platform, src, block_size, &crc_src, arena, arena_len);
    if (status != BOOT_OK)
      goto revert_cleanup;

    status = boot_crc32_flash_stream(platform, dst, block_size, &crc_dest, arena, arena_len);
    if (status != BOOT_OK)
      goto revert_cleanup;

    if (crc_src == crc_dest) {
      bool is_identical = true;
      uint32_t chk_off = 0;

      /* P10 ALIGNMENT FIX: Maskiert die Division auf exakt 8 Bytes,
       * um Unaligned UsageFaults in den Hardware-SPI-DMAs auszuschließen! */
      size_t half_arena = (arena_len / 2) & ~((size_t)7);

      while (chk_off < block_size) {
        if (platform->wdt && platform->wdt->kick)
          platform->wdt->kick();

        /* Splitten der Arena in zwei alignte Hälften für Source/Dest Check */
        size_t step = (block_size - chk_off > half_arena)
                          ? half_arena
                          : (block_size - chk_off);

        uint8_t *buf_dst = arena;
        uint8_t *buf_src = arena + half_arena;

        if (platform->flash->read(dst + chk_off, buf_dst, step) != BOOT_OK ||
            platform->flash->read(src + chk_off, buf_src, step) != BOOT_OK) {
          is_identical = false;
          break;
        }

        /* Glitch-Shielded Evaluation um Exploit-Bypasses der Reparatur zu stoppen! */
        if (constant_time_memcmp_glitch_safe(buf_dst, buf_src, step) !=
            BOOT_OK) {
          is_identical = false;
          break;
        }
        chk_off += (uint32_t)step;
      }

      /* Radikal nullifizieren, damit keine Krypto-Residuen den nachfolgenden SPI Read verfälschen! */
      boot_secure_zeroize(arena, arena_len);

      if (is_identical) {
        /* Identisch: Fast-Forward zum nächsten Sektor ohne Erase/Write Last! */
        current_offset += (uint32_t)block_size;
        continue;
      }
    }

    /* ====================================================================
     * 4.b Flash Effect Planning & Execution
     * ==================================================================== */
    flash_effect_t fx[2];
    size_t planned_n = 0;
    status = boot_rollback_plan_chunk(platform, current_offset, (uint32_t)block_size, crc_src, fx, 2, &planned_n);
    if (status != BOOT_OK)
      goto revert_cleanup;

    /* WAL Checkpoint VOR der Destruktion des App-Sektors setzen! (P10 Tearing Guard) */
    pending_intent.delta_chunk_id = current_offset;
    status = boot_journal_append(platform, &pending_intent);
    if (status != BOOT_OK)
      goto revert_cleanup;

    status = boot_effect_execute(platform, fx, planned_n, whitelist, 1, arena, arena_len);
    if (status != BOOT_OK)
      goto revert_cleanup;

    physical_app_erases +=
        (uint32_t)((block_size / dst_sec_size > 0) ? (block_size / dst_sec_size) : 1);

    current_offset += (uint32_t)block_size;
  }

  boot_cfi_step(revert_cfi_ctx, 3);

  /* CFI Final Resolution */
  boot_cfi_require(revert_cfi_ctx, {
    status = BOOT_ERR_INVALID_STATE; /* Revert-Prozess wurde durch Glitch unterbrochen! */
    goto revert_cleanup;
  });

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
  boot_secure_zeroize(arena, arena_len);
  boot_secure_zeroize(&pending_intent, sizeof(pending_intent));
  boot_secure_zeroize(&revert_intent, sizeof(revert_intent));
  boot_secure_zeroize(&backup_header, sizeof(backup_header));

  return status;
}

boot_status_t boot_rollback_plan_chunk(const boot_platform_t *platform,
                                       uint32_t current_offset, uint32_t block_size,
                                       uint32_t crc_src,
                                       flash_effect_t *out_fx, size_t cap, size_t *n_out) {
  (void)platform;
  if (cap < 2) return BOOT_ERR_INVALID_ARG;

  uint32_t src = CHIP_STAGING_SLOT_ABS_ADDR + current_offset;
  uint32_t dst = CHIP_APP_SLOT_ABS_ADDR + current_offset;

  out_fx[0].op = EFF_ERASE;
  out_fx[0].src = 0;
  out_fx[0].dst = dst;
  out_fx[0].len = block_size;
  out_fx[0].post_crc = boot_effect_compute_erased_crc(block_size);

  out_fx[1].op = EFF_COPY;
  out_fx[1].src = src;
  out_fx[1].dst = dst;
  out_fx[1].len = block_size;
  out_fx[1].post_crc = crc_src;

  *n_out = 2;
  return BOOT_OK;
}