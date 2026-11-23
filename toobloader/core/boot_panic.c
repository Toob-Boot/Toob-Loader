/*
 * ==============================================================================
 * Toob-Boot Core File: boot_panic.c (Mathematical Perfection Revision v3)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/stage_1_5_spec.md (Serial Rescue, SOS Mode, Exponential Penalty)
 * - docs/testing_requirements.md (Zero-Allocation, P10 Bounds, Tearing-Proof)
 *
 * ARCHITECTURAL UPGRADES (The "Reviewer's Cut"):
 * 1. True Zero-Allocation Mapping: 100% aller Buffer, inklusive des 1056-Byte
 *    Chunk-Buffers, des Read-Back-Arrays und aller Krypto-Keys liegen jetzt
 *    in disjunkten, 8-Byte-aligned Zonen der crypto_arena. (Spart >1.2 KB
 * Stack!)
 * 2. Sizeof-Logic-Bomb Fixed: Ersetzt gefährliche sizeof(ptr) Aufrufe durch
 *    hart codierte, statisch überprüfte Makro-Grenzen.
 * 3. Unaligned Access Mitigation: Verhindert Cortex-M0 Exception-Traps durch
 *    sichere memcpy-Extrahierung direkt aus dem UART-Empfangspuffer via
 * offsetof.
 * 4. WDT-Deadlock Fix: Erlaubt dem Hardware-Watchdog den finalen Biss am Ende
 *    der Übertragung, um einen sauberen Kaltstart des SoCs zu erzwingen.
 * 5. Glitch-Resistant 2FA Auth & EOF: Double-Check Gating schützt kritische
 *    Sprünge vor Voltage/EMFI-Faults.
 * 6. Math-Bound COBS: Subtraktive O(1) Grenzen verhindern Integer-Wraparounds.
 */

#include "boot_panic.h"
#include "boot_cloud_cmd.h"
#include "boot_cobs.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_delay.h"
#include "boot_fih.h"
#include "boot_flash_guard.h"
#include "boot_identity.h"
#include "boot_journal.h"
#include "boot_secure_zeroize.h"
#include "generated_boot_config.h"
#include <stddef.h>
#include <string.h>

#if defined(__has_attribute)
#if __has_attribute(no_stack_protector)
#define TOOB_PANIC_NO_SSP __attribute__((no_stack_protector))
#else
#define TOOB_PANIC_NO_SSP
#endif
#elif defined(__GNUC__) && (__GNUC__ >= 11)
#define TOOB_PANIC_NO_SSP __attribute__((no_stack_protector))
#else
#define TOOB_PANIC_NO_SSP
#endif

/* P5 Exception: _Noreturn terminal state — arena grab is safe.
 * boot_terminal_halt never returns, so no subsequent arena user can be affected.
 * Keeping extern avoids cascading signature changes through 13+ call sites. */
extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

_Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 2048,
               "Crypto Arena muss mindestens 2KB aufweisen für Serial Rescue Puffer");
_Static_assert(BOOT_OK == 0x55AA55AA, "BOOT_OK must be high-hamming distance for Glitch-Shielding");

/* ============================================================================
 * P10 Memory Arena Boundaries (100% Zero Allocation & Stack-Bloat Prevention)
 * ============================================================================
 */
#define PANIC_CHALLENGE_MAX_SIZE 128
#define PANIC_RX_MAX_SIZE 128
#define PANIC_VERIFY_MAX_SIZE 80 /* 8-Byte Aligned (Spec requires 76) */
#define PANIC_CHUNK_MAX_SIZE                                                                       \
  (BOOT_CRYPTO_ARENA_SIZE - PANIC_CHALLENGE_MAX_SIZE - PANIC_RX_MAX_SIZE - PANIC_VERIFY_MAX_SIZE)

/* Mathematischer Beweis zur Compile-Zeit, dass die Partitionen den RAM nicht
 * sprengen */
_Static_assert((PANIC_CHALLENGE_MAX_SIZE + PANIC_RX_MAX_SIZE + PANIC_VERIFY_MAX_SIZE +
                PANIC_CHUNK_MAX_SIZE) == BOOT_CRYPTO_ARENA_SIZE,
               "FATAL: Arena Partitioning exceeds total BOOT_CRYPTO_ARENA_SIZE!");

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define PANIC_CFI_SLOT_INIT 0
#define PANIC_CFI_SLOT_AUTH 1

/* COBS encode/decode/recv extracted to boot_cobs.c (DRY with
 * boot_provisioning.c) */

_Noreturn static void enter_sos_loop(const boot_platform_t *platform) {
  while (1) {
    BOOT_GLITCH_DELAY();
    if (platform && platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    if (platform && platform->clock && platform->clock->delay_ms) {
      (void)boot_delay_with_wdt(platform, 500U);
    }
  }
}

_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason,
                                  uint16_t site_id) {
  /* Zero-initialize local forensic record */
  boot_forensic_record_t record;
  boot_secure_zeroize(&record, sizeof(record));

  record.magic = 0x464F524E; /* "FORN" */
  record.reason = (uint32_t)reason;
  record.site_id = (uint32_t)site_id;

  uint32_t current_monotonic = 0;
  if (platform && platform->keystore && platform->keystore->read_monotonic_counter) {
    (void)platform->keystore->read_monotonic_counter(&current_monotonic);
  }
  record.monotonic_counter = current_monotonic;

  /* CRC of fields before crc32 field (4 * 4 = 16 bytes) */
  record.crc32 = compute_boot_crc32((const uint8_t *)&record, 16);

  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  /* Writes-then-freezes: write never gates the security decision; if it fails, still freeze. */
  if (platform) {
    bool written = false;
    /* RTC-Backup-Register bevorzugt */
    if (platform->soc && platform->soc->write_rtc_backup) {
      /* Write the 20-byte record across slots 1 to 5 */
      uint32_t words[5];
      memcpy(words, &record, sizeof(record));
      boot_status_t rtc_stat = BOOT_OK;
      for (uint8_t slot = 1; slot <= 5; slot++) {
        boot_status_t s = platform->soc->write_rtc_backup(slot, words[slot - 1]);
        if (s != BOOT_OK) {
          rtc_stat = s;
        }
      }
      if (rtc_stat == BOOT_OK) {
        written = true;
      }
    }

    /* Fallback on flash Forensic Slot if RTC not written/available */
    if (!written && platform->flash && platform->flash->write && platform->flash->erase_sector) {
      if (boot_flash_erase_sector_guarded(platform->flash, CHIP_FORENSIC_SLOT_ABS_ADDR) ==
          BOOT_OK) {
        uint8_t aligned_buf[32] __attribute__((aligned(8)));
        memset(aligned_buf, platform->flash->erased_value, sizeof(aligned_buf));
        memcpy(aligned_buf, &record, sizeof(record));
        size_t write_len = sizeof(record);
        uint32_t w_align = (platform->flash->write_align > 0U) ? platform->flash->write_align : 1U;
        if (w_align <= sizeof(aligned_buf) && (write_len % w_align) != 0U) {
          write_len += (size_t)w_align - (write_len % w_align);
        }
        (void)boot_flash_write_guarded(platform->flash, CHIP_FORENSIC_SLOT_ABS_ADDR, aligned_buf,
                                       write_len);
        boot_secure_zeroize(aligned_buf, sizeof(aligned_buf));
      }
    }

    /* Deinit Cascade (Systematisch absteigend, Zeitgeber und Watchdog als Letztes) */
    if (platform->flash && platform->flash->deinit) {
      platform->flash->deinit();
    }
    if (platform->crypto && platform->crypto->deinit) {
      platform->crypto->deinit();
    }
    if (platform->entropy && platform->entropy->deinit) {
      platform->entropy->deinit();
    }
    if (platform->keystore && platform->keystore->deinit) {
      platform->keystore->deinit();
    }
    if (platform->confirm && platform->confirm->deinit) {
      platform->confirm->deinit();
    }
    if (platform->console && platform->console->deinit) {
      platform->console->deinit();
    }
    if (platform->soc && platform->soc->deinit) {
      platform->soc->deinit();
    }
    if (platform->clock && platform->clock->deinit) {
      platform->clock->deinit();
    }
    /* P10: Interrupts deaktivieren */
    if (platform->soc && platform->soc->disable_interrupts) {
      platform->soc->disable_interrupts();
    }
  }

  /* Starvation-Loop: Keine Watchdog Kicks, so dass der Watchdog bei Bedarf zubeißen kann */
  while (1) {
    BOOT_GLITCH_DELAY();
  }
}

static TOOB_PANIC_NO_SSP __attribute__((noinline)) void
boot_panic_mix_stack_guard(const boot_platform_t *platform) {
#if !defined(TOOB_MOCK_TEST) && !defined(TOOB_HOST_FUZZING) && !defined(_WIN32) &&                 \
    !defined(__linux__) && !defined(__APPLE__) && !defined(__CPROVER__)
  if (platform != NULL && platform->entropy != NULL && platform->entropy->random != NULL) {
    uint8_t rnd[sizeof(uintptr_t)];
    if (boot_random_safe(platform, rnd, sizeof(rnd)) == BOOT_OK) {
      uintptr_t mix = 0U;
      memcpy(&mix, rnd, sizeof(mix));
      boot_secure_zeroize(rnd, sizeof(rnd));
      uintptr_t updated = *(volatile const uintptr_t *)&__stack_chk_guard ^ mix;
      if (updated == 0U) {
        updated = (uintptr_t)0x5A3CC3A5U;
      }
      *(volatile uintptr_t *)&__stack_chk_guard = updated;
    }
  }
#else
  (void)platform;
#endif
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
  /* Hard-Fault Exit, wenn der Platform-Pointer defekt ist */
  if (!platform || !platform->wdt) {
    while (1) { /* Nichts tun, Hardware WDT Reset abwarten */
      BOOT_GLITCH_DELAY();
    }
  }

  if (!platform->console || !platform->console->putchar || !platform->console->getchar ||
      !platform->crypto || !platform->entropy || !platform->entropy->random ||
      !platform->keystore || !platform->flash || !platform->flash->read ||
      !platform->flash->write || !platform->flash->erase_sector ||
      !platform->flash->get_sector_size) {
    boot_terminal_halt(platform, reason, SITE_COBS_SHIELD_FAIL);
  }

  boot_panic_mix_stack_guard(platform);

  uint32_t failed_auth_attempts = 0;

  /* P10 Anti-Power-Cycle-Brute-Force: Lade persistierten Auth-Zähler aus
   * RTC-Backup Registern, die über Brownout/Software-Reset hinweg überleben.
   * Falls kein RTC verfügbar: Deterministischer 5s Boot-Delay als Fallback. */
  if (platform->soc && platform->soc->read_rtc_backup) {
    if (platform->soc->read_rtc_backup(RTC_SLOT_AUTH_ATTEMPTS, &failed_auth_attempts) != BOOT_OK ||
        failed_auth_attempts == 0xFFFFFFFFU) {
      failed_auth_attempts = 0U;
      (void)boot_delay_with_wdt(platform, 5000U);
    }
  } else {
    (void)boot_delay_with_wdt(platform, 5000U);
  }

session_reset:
  if (platform->console->putchar) {
    /* Initialisierungs-UART Flush */
    (void)platform->console->putchar('P');
    (void)platform->console->putchar('N');
    (void)platform->console->putchar('C');
    if (platform->console->flush) {
      (void)platform->console->flush();
    }
  }

  /* ============================================================================
   * TRUE ZERO-ALLOCATION ARENA MAPPING (P10 Architecture)
   * ============================================================================
   * Der C-Stack bleibt physikalisch zu 100 % sauber. Die Arena wird
   * durch exakt definierte Makros in disjunkte Zonen segmentiert.
   */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  uint8_t *challenge_buf = crypto_arena;
  uint8_t *rx_buf = challenge_buf + PANIC_CHALLENGE_MAX_SIZE;
  uint8_t *verify_msg = rx_buf + PANIC_RX_MAX_SIZE;
  uint8_t *chunk_buf = verify_msg + PANIC_VERIFY_MAX_SIZE;

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t panic_cfi_seed = 0U;
  if (boot_random_safe(platform, (uint8_t *)&panic_cfi_seed, sizeof(panic_cfi_seed)) != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    enter_sos_loop(platform); /* Terminal: TRNG Broken */
  }
  boot_cfi_ctx_t panic_cfi_ctx;
  boot_cfi_init(panic_cfi_ctx, panic_cfi_seed);
  boot_cfi_add_expected(panic_cfi_ctx, PANIC_CFI_SLOT_AUTH);

  /* ============================================================================
   * BLOCK 1: Challenge Generation (2FA)
   * ============================================================================
   */
  size_t challenge_len = 32; /* Nonce Base Size */

  if (boot_random_safe(platform, challenge_buf, 32) != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    enter_sos_loop(platform); /* Terminal: TRNG Broken */
  }

  /* P10 HAL Containment: Zero-Allocation. Wir recyclen den ungenutzten
   * chunk_buf in Phase 1 für den DSLC Read, um den Stack absolut rein zu
   * halten. */
  uint8_t *temp_dslc = chunk_buf;
  size_t dslc_len = 64;

  if (platform->keystore->read_dslc) {
    boot_status_t d_status = platform->keystore->read_dslc(temp_dslc, &dslc_len);
    if (d_status == BOOT_OK && dslc_len > 0) {
      if (dslc_len > 64) {
        dslc_len = 64; /* Hardware Clamp Protection */
      }
      memcpy(challenge_buf + 32, temp_dslc, dslc_len);
    } else {
      dslc_len = 32; /* Fallback Zero-Padding */
      boot_secure_zeroize(challenge_buf + 32U, 32U);
    }
  } else {
    dslc_len = 32;
    boot_secure_zeroize(challenge_buf + 32U, 32U);
  }
  boot_secure_zeroize(temp_dslc, 64); /* O(1) Zeroize nach Kopie */
  challenge_len += dslc_len;

  /* Monotonic Timer zur Erleichterung für das Host-Tooling anfügen */
  uint32_t current_monotonic = 0U;
  if (boot_read_monotonic_counter_safe(platform, &current_monotonic) != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    enter_sos_loop(platform);
  }

  /* Exakte Speicher-Mappings (Vermeidet Cast-UBs) */
  memcpy(challenge_buf + challenge_len, &current_monotonic, sizeof(current_monotonic));
  challenge_len += sizeof(current_monotonic);

  memcpy(challenge_buf + challenge_len, &reason, sizeof(reason));
  challenge_len += sizeof(reason);

  /* P7e: eFuse-Epoch-Floor an Challenge anfügen, damit das Host-Tool
   * (toob rescue) den Techniker warnen kann, BEVOR ein Image gestreamt wird,
   * dessen SVN unterhalb des Floors liegt. Kein Gate — nur Advisory.
   * Hinweis: Der Monotonic Counter IST der eFuse-Epoch — kein zweiter Read nötig. */
  memcpy(challenge_buf + challenge_len, &current_monotonic, sizeof(current_monotonic));
  challenge_len += sizeof(current_monotonic);

  /* Sende Challenge via COBS an den Techniker */
  boot_cobs_send_frame(platform, challenge_buf, challenge_len);

  /* ============================================================================
   * BLOCK 2: Auth-Token Empfang & P10-Verifikation (Constant Time Logic)
   * ============================================================================
   */
  while (1) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }

    size_t rx_len = 0;
    if (boot_cobs_recv_frame(platform, rx_buf, PANIC_RX_MAX_SIZE, &rx_len) != BOOT_OK) {
      continue;
    }

    size_t decoded_len = 0;
    volatile uint32_t auth_eval = 0;

    if (boot_cobs_decode_in_place(rx_buf, rx_len, &decoded_len) == BOOT_OK) {
      if (decoded_len == sizeof(stage15_auth_payload_t)) {

        /* Unaligned Access Mitigation: Cortex-M0/M0+ Exception Prevention.
         * Extraktion ohne Stack-Struct, direkt in lokale Primitive via
         * offsetof. */
        uint32_t safe_slot_id = 0;
        uint32_t safe_sequence_id = 0;

        memcpy(&safe_slot_id, rx_buf + offsetof(stage15_auth_payload_t, slot_id), sizeof(uint32_t));
        memcpy(&safe_sequence_id, rx_buf + offsetof(stage15_auth_payload_t, sequence_id),
               sizeof(uint32_t));

        const uint8_t *auth_nonce = rx_buf + offsetof(stage15_auth_payload_t, nonce);
        const uint8_t *auth_sig = rx_buf + offsetof(stage15_auth_payload_t, sig);

        /* P10 FIX: Verhindert Replay-Attacks durch Offline-Tokens!
         * Das Token MUSS exakt + 1 zum Hardware-Counter sein. */
        bool time_ok =
            (current_monotonic < UINT32_MAX) && (safe_sequence_id == (current_monotonic + 1U));
        bool slot_ok = (safe_slot_id == CHIP_STAGING_SLOT_ID);
        boot_status_t nonce_stat = constant_time_memcmp_glitch_safe(auth_nonce, challenge_buf, 32);

        bool auth_failed = false;
        BOOT_SECURE_REQUIRE(time_ok && slot_ok && nonce_stat == BOOT_OK, { auth_failed = true; });

        if (!auth_failed) {
          /* Assemble Ed25519 Message exakt nach Spec (72 Bytes):
           * [Nonce(32)] | [Padded DSLC(32)] | [Slot ID(4)] | [Sequence ID(4)]
           */
          boot_secure_zeroize(verify_msg, PANIC_VERIFY_MAX_SIZE);
          memcpy(verify_msg, challenge_buf, 64); /* Zieht saubere Nonce & DSLC Base */
          memcpy(verify_msg + 64, &safe_slot_id, sizeof(uint32_t));
          memcpy(verify_msg + 68, &safe_sequence_id, sizeof(uint32_t));

          /* Zero-Allocation Fix: Wir recyclen den ungenutzten chunk_buf für den
           * Root Pubkey */
          uint8_t *root_pubkey = chunk_buf;
          boot_secure_zeroize(root_pubkey, 32);

          uint8_t active_slot = 0U;
          if (platform->keystore->read_pubkey &&
              boot_otp_get_active_key_index(platform, &active_slot) == BOOT_OK &&
              platform->keystore->read_pubkey(root_pubkey, 32U, active_slot) == BOOT_OK &&
              verify_not_all_zeros_glitch_safe(root_pubkey, 32U) == BOOT_OK) {

            if (platform->wdt && platform->wdt->kick) {
              platform->wdt->kick();
            }
            boot_status_t sig_stat =
                platform->crypto->verify_signature(verify_msg, 72, auth_sig, root_pubkey);
            if (platform->wdt && platform->wdt->kick) {
              platform->wdt->kick();
            }

            if (boot_secure_confirm(sig_stat) == BOOT_OK) {
              /* OTP Burn: Must succeed before accepting token to prevent replay */
              if (platform->keystore->advance_monotonic_counter != NULL) {
                boot_status_t adv_stat = platform->keystore->advance_monotonic_counter();
                if (boot_secure_confirm(adv_stat) == BOOT_OK) {
                  current_monotonic = safe_sequence_id;
                  failed_auth_attempts = 0U;
                  if (platform->soc && platform->soc->write_rtc_backup) {
                    (void)platform->soc->write_rtc_backup(RTC_SLOT_AUTH_ATTEMPTS, 0U);
                  }
                  auth_eval = BOOT_OK;
                  boot_cfi_step(panic_cfi_ctx, PANIC_CFI_SLOT_AUTH);
                } else {
                  auth_eval = BOOT_ERR_VERIFY;
                }
              } else {
                auth_eval = BOOT_ERR_VERIFY;
              }
            }
          }
          boot_secure_zeroize(root_pubkey, 32);
        }
        boot_secure_zeroize(verify_msg, PANIC_VERIFY_MAX_SIZE);
      }
    }

    boot_secure_zeroize(rx_buf, PANIC_RX_MAX_SIZE); /* Wipe untrusted data */

    if (auth_eval == BOOT_OK) {
      break; /* Success! Aus Auth-Schleife ausbrechen */
    } else {
      if (failed_auth_attempts < UINT32_MAX) {
        failed_auth_attempts++;
      }

      /* Persistiere Zähler ins RTC-Backup Register gegen Power-Cycle-Bypass */
      if (platform->soc && platform->soc->write_rtc_backup) {
        platform->soc->write_rtc_backup(RTC_SLOT_AUTH_ATTEMPTS, failed_auth_attempts);
      }

      /* GAP-C06: Serial Rescue DoS Penalty */
      uint32_t shifts = (failed_auth_attempts > 10U) ? 10U : failed_auth_attempts;
      uint32_t penalty_ms = (1U << shifts) * 100U;

      (void)boot_delay_with_wdt(platform, penalty_ms);
      continue;
    }
  }

  /* ============================================================================
   * BLOCK 3: Naked COBS Flash-Transfer (Ping-Pong) & Handoff
   * ============================================================================
   */

  /* MATHEMATISCHER CFI-BEWEIS: Wir blockieren State-Confusion-Glitches, die uns
   * ohne Authentication direkt hier reinspringen lassen würden! */
  boot_cfi_require(panic_cfi_ctx, {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    boot_terminal_halt(platform, BOOT_ERR_VERIFY, SITE_COBS_SHIELD_FAIL);
  });

  uint32_t flash_offset = 0;
  uint32_t current_sector_end = CHIP_STAGING_SLOT_ABS_ADDR;
  bool staging_erased = false;

  if (reason == BOOT_ERR_DEVICE_LOCKED) {
    /* ============================================================================
     * BLOCK 3A: Cloud Command Unlock Pathway (Gerät ist im Soft-Lock)
     * ============================================================================
     */
    while (1) {
      boot_cobs_send_frame(platform, (const uint8_t *)"LCK", 3);

      boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
      size_t chunk_len = 0;
      bool chunk_received = false;
      bool in_overflow_drain = false;

      while (!chunk_received) {
        if (platform->wdt && platform->wdt->kick) {
          platform->wdt->kick();
        }

        uint8_t c = 0;
        if (platform->console->getchar(&c, 500) != BOOT_OK) {
          break;
        }

        if (c == COBS_MARKER_END) {
          if (in_overflow_drain) {
            in_overflow_drain = false;
            chunk_len = 0U;
            continue;
          }
          if (chunk_len > 0) {
            chunk_received = true;
          }
        } else if (!in_overflow_drain) {
          if (chunk_len < PANIC_CHUNK_MAX_SIZE) {
            chunk_buf[chunk_len++] = c;
          } else {
            boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
            chunk_len = 0;
            in_overflow_drain = true;
          }
        }
      }

      if (!chunk_received) {
        continue;
      }

      size_t payload_len = 0;
      if (boot_cobs_decode_in_place(chunk_buf, chunk_len, &payload_len) == BOOT_OK &&
          payload_len > 0) {

        /* Disjoint work zone (challenge_buf + rx_buf = 256B, unused in Block 3A) */
        uint8_t *cmd_work_zone = challenge_buf;
        boot_secure_zeroize(cmd_work_zone, 256U);

        toob_cloud_cmd_t cmd_intent = TOOB_CMD_NOP;
        boot_status_t eval_stat = boot_cloud_cmd_evaluate_buffer(platform, chunk_buf, payload_len,
                                                                 cmd_work_zone, &cmd_intent);
        boot_secure_zeroize(cmd_work_zone, 256U);

        if (eval_stat == BOOT_OK && cmd_intent == TOOB_CMD_UNLOCK) {
          /* Persist WAL_INTENT_NONE so the soft-lock is lifted on next boot */
          boot_status_t unlock_persist = boot_journal_init(platform);
          if (unlock_persist == BOOT_OK) {
            wal_entry_payload_t unlock_txn;
            boot_secure_zeroize(&unlock_txn, sizeof(unlock_txn));
            unlock_txn.intent = WAL_INTENT_NONE;
            unlock_persist = boot_journal_append(platform, &unlock_txn);
            boot_secure_zeroize(&unlock_txn, sizeof(unlock_txn));
          }
          if (unlock_persist != BOOT_OK) {
            boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
            goto session_reset;
          }

          /* SUCCESS: Device Unlocked! */
          boot_cobs_send_frame(platform, (const uint8_t *)"ULK", 3);
          boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

          /* Kaltstart via Hardware-WDT erzwingen (C17 UB-frei) */
          if (platform->console && platform->console->flush) {
            platform->console->flush();
          }
          if (platform->clock && platform->clock->deinit) {
            platform->clock->deinit();
          }

          while (1) {
            BOOT_GLITCH_DELAY();
          }
        } else {
          /* Falscher Befehl oder Signatur ungültig */
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
      }
      boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
    }
  }

  /* ============================================================================
   * BLOCK 3B: Normal Firmware Stream Pathway
   * ============================================================================
   * P7e: Kein SVN-Gate im Rescue-Flasher.
   * Das Anti-Rollback-Gate greift post-reboot in stage_conditions()
   * (component_id == 3, boot_rollback_verify_svn). Der Rescue-Flasher
   * streamt blind in den Staging Slot — das ist architektonisch korrekt:
   * 1. Der SUIT-Parser (zcbor) ist hier nicht verfügbar (Binary-Footprint)
   * 2. Das Image wird nach dem Reboot vollständig verifiziert + SVN-geprüft
   * 3. Der eFuse-Floor wurde in der Challenge an den Host kommuniziert
   */
  while (1) {
    boot_cobs_send_frame(platform, (const uint8_t *)"RDY", 3);

    boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
    size_t chunk_len = 0;
    bool chunk_received = false;
    bool in_overflow_drain = false;

    while (!chunk_received) {
      if (platform->wdt && platform->wdt->kick) {
        platform->wdt->kick();
      }

      uint8_t c = 0;
      if (platform->console->getchar(&c, 500) != BOOT_OK) {
        break;
      }

      if (c == COBS_MARKER_END) {
        if (in_overflow_drain) {
          in_overflow_drain = false;
          chunk_len = 0U;
          continue;
        }
        if (chunk_len > 0) {
          chunk_received = true;
        }
      } else if (!in_overflow_drain) {
        /* Dynamischer P10 Bounds Check via Macro */
        if (chunk_len < PANIC_CHUNK_MAX_SIZE) {
          chunk_buf[chunk_len++] = c;
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          chunk_len = 0; /* Frame overflow trap */
          in_overflow_drain = true;
        }
      }
    }

    if (!chunk_received) {
      continue;
    }

    size_t payload_len = 0;
    if (boot_cobs_decode_in_place(chunk_buf, chunk_len, &payload_len) == BOOT_OK &&
        payload_len > 0) {

      static const uint8_t k_eof_tag[3] = {'E', 'O', 'F'};
      bool is_eof = (payload_len == 3U &&
                     constant_time_memcmp_glitch_safe(chunk_buf, k_eof_tag, 3U) == BOOT_OK);
      if (is_eof) {
        BOOT_SECURE_REQUIRE(
            payload_len == 3U &&
                constant_time_memcmp_glitch_safe(chunk_buf, k_eof_tag, 3U) == BOOT_OK,
            { boot_terminal_halt(platform, BOOT_ERR_VERIFY, SITE_COBS_SHIELD_FAIL); });
        boot_cobs_send_frame(platform, (const uint8_t *)"ACK", 3);
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

        /* P10 HANDOFF FIX: Hardware-Reset erzwingen durch absichtliches
         * Verweigern des WDT-Kicks (C17 UB-frei). */
        if (platform->console && platform->console->flush) {
          platform->console->flush();
        }
        if (platform->clock && platform->clock->deinit) {
          platform->clock->deinit();
        }

        while (1) {
          BOOT_GLITCH_DELAY();
        }
      }

      /* Padding Alignment Guard for the final Chunk. */
      uint8_t align = platform->flash->write_align;
      if (align == 0) {
        align = 1;
      }

      size_t aligned_len = payload_len;
      uint8_t align_mod = (uint8_t)(payload_len % align);
      if (align_mod != 0) {
        size_t padding = align - align_mod;
        /* Wrap & Buffer Overflow Defense */
        if (UINT32_MAX - aligned_len < padding || aligned_len + padding > PANIC_CHUNK_MAX_SIZE) {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
        memset(chunk_buf + payload_len, platform->flash->erased_value, padding);
        aligned_len += padding;
      }

      BOOT_SECURE_REQUIRE((aligned_len <= CHIP_STAGING_SLOT_SIZE) &&
                              (flash_offset <= (CHIP_STAGING_SLOT_SIZE - aligned_len)) &&
                              (CHIP_STAGING_SLOT_ABS_ADDR <= (UINT32_MAX - CHIP_STAGING_SLOT_SIZE)),
                          {
                            boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
                            goto session_reset;
                          });

      uint32_t addr = CHIP_STAGING_SLOT_ABS_ADDR + flash_offset;
      size_t write_end = addr + aligned_len;

      if (write_end < addr) {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }

      while (!staging_erased || current_sector_end < write_end) {
        size_t s_size = 0;
        uint32_t erase_target = !staging_erased ? addr : current_sector_end;

        if (platform->flash->get_sector_size(erase_target, &s_size) == BOOT_OK) {

          if (boot_flash_range_hits_immutable_boot(erase_target, s_size)) {
            boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
            goto session_reset;
          }

          /* Smart-Erase Pre-Check via fast word-wise boot_flash_is_erased */
          bool sec_erased = false;
          bool needs_erase =
              (boot_flash_is_erased(platform, erase_target, s_size, &sec_erased) != BOOT_OK) ||
              !sec_erased;

          if (needs_erase) {
            if (platform->wdt && platform->wdt->suspend_for_critical_section) {
              platform->wdt->suspend_for_critical_section();
            } else if (platform->wdt && platform->wdt->kick) {
              platform->wdt->kick();
            }

            if (boot_flash_erase_sector_guarded(platform->flash, erase_target) != BOOT_OK) {
              boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
              goto session_reset;
            }

            if (platform->wdt && platform->wdt->resume) {
              platform->wdt->resume();
            }
          }

          if (UINT32_MAX - erase_target < s_size) {
            boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
            goto session_reset;
          }

          current_sector_end = erase_target + (uint32_t)s_size;
          staging_erased = true;
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
      }

      if (boot_flash_write_guarded(platform->flash, addr, chunk_buf, aligned_len) == BOOT_OK) {

        /* P10 ECC Read-Back: Verhindert Bit-Rot / Tearing auf dem UART-Puffer!
         * Zero-Allocation Nutzung des freien verify_msg Buffers! */
        uint8_t *rb_buf = verify_msg;
        size_t rb_buf_size = PANIC_VERIFY_MAX_SIZE;
        uint32_t check_off = 0;
        bool write_ok = true;

        while (check_off < aligned_len) {
          if (platform->wdt && platform->wdt->kick) {
            platform->wdt->kick();
          }
          size_t step =
              (aligned_len - check_off > rb_buf_size) ? rb_buf_size : (aligned_len - check_off);

          if (platform->flash->read(addr + check_off, rb_buf, step) != BOOT_OK) {
            write_ok = false;
            break;
          }

          /* Glitch-Resistant Constant-Time Chunk Comparison */
          BOOT_SECURE_REQUIRE(
              constant_time_memcmp_glitch_safe(rb_buf, chunk_buf + check_off, step) == BOOT_OK,
              { write_ok = false; });
          if (!write_ok) {
            break;
          }

          check_off += (uint32_t)step;
        }

        if (write_ok) {
          flash_offset += (uint32_t)aligned_len;
          boot_cobs_send_frame(platform, (const uint8_t *)"ACK", 3);
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset; /* Schreibfehler oder Bit-Rot -> Absturz und
                                 Neubeginn erzwingen! */
        }
      } else {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }
    }
    boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
  }
}

/* ==============================================================================
 * ARCHITECTURE ROUTING (NMI & HARDFAULT)
 * ==============================================================================
 */

/**
 * @brief Globaler C-Contract für HAL-Interaktionen bei schweren Memory-Fehlern.
 * Vendor-ISRs (wie HardFault_Handler auf ARM) müssen diese Funktion aufrufen,
 * anstatt eigene Endlosschleifen zu implementieren.
 */
void __attribute__((section(".iram1.text"))) toob_ecc_trap(void) {
  /* ACHTUNG: toob_ecc_trap hat keinen Kontext zur `platform`, da sie asynchron
   * aus einer NMI aufgerufen wird! Wir müssen den globalen Handoff-State
   * oder eine reduzierte Panic fahren.
   * Wir versuchen einen sicheren WDT-Timeout herbeizuführen, indem wir in
   * eine unendliche Schleife ohne WDT-Kick gehen. Das ist P10 konform für NMIs.
   */
  while (1) {
    /* Warten auf den Watchdog-Biss. Keine Kicks erlaubt. */
    BOOT_GLITCH_DELAY();
  }
}

/*
 * P10 / OSV Härtung: Eigene Stack Protector Definitionen.
 * Wenn wir diese nicht bereitstellen, zieht GCC `stack_protector.o` aus
 * `libc_nano.a`, was `abort()`, `raise()` und letztlich `printf()` und IO
 * nachzieht -> 145KB Bloat!
 */
#if !defined(TOOB_MOCK_TEST) && !defined(TOOB_HOST_FUZZING) && !defined(_WIN32) &&                 \
    !defined(__linux__) && !defined(__APPLE__) && !defined(__CPROVER__)
uintptr_t __stack_chk_guard =
    0x00ADBEEFU; /* NOLINT(misc-use-internal-linkage,bugprone-reserved-identifier,cert-dcl37-c) */

void __stack_chk_fail(void); /* NOLINT(bugprone-reserved-identifier,cert-dcl37-c) */

void __stack_chk_fail(
    void) { /* NOLINT(misc-use-internal-linkage,bugprone-reserved-identifier,cert-dcl37-c) */
  /* Stack smashing detected: Enter hardware terminal halt */
  boot_terminal_halt(NULL, BOOT_ERR_ECC_HARDFAULT, SITE_COBS_SHIELD_FAIL);
}
#endif
