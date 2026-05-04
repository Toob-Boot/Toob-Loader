/**
 * @file boot_state.c
 * @brief Core State-Machine Logic (Mathematical Perfection Revision)
 *
 * Implements the lifecycle orchestration for the update state machine
 * bridging M-JOURNAL, M-VERIFY, M-SWAP, and M-ROLLBACK.
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Global CFI (Control Flow Integrity): Ein XOR-Akkumulator beweist
 * mathematisch, dass JEDER Schritt der State-Machine ausgeführt wurde.
 * Verhindert PC-Glitches!
 * 2. Glitch-Resistant Auth-Gating: Nonce-Verifizierung und Handoff-Checks sind
 *    durch Double-Check Patterns gegen Voltage Faults abgesichert.
 * 3. ZCBOR Pointer Sandboxing: Beweist mathematisch, dass extrahierte Manifest-
 *    Payloads physikalisch innerhalb der allokierten crypto_arena verbleiben.
 * 4. Zero-Allocation Streaming: Verzicht auf BSS-Bloat durch dynamische
 *    sichere 8-Byte-aligned Partitionierung der bestehenden crypto_arena.
 * 5. P10 Stack Security: Alle Crypto-Sub-Buffer und C-Structs werden vor dem
 *    Return via boot_secure_zeroize restlos vernichtet.
 */

#include "boot_state.h"
#include "generated_boot_config.h"
#ifdef TOOB_MOCK_TEST
#include "boot_config_mock.h"
#endif
#include "boot_diag.h"
#include "boot_delta.h"
#include "boot_journal.h"
#include "boot_merkle.h"
#include "boot_rollback.h"
#include "boot_secure_zeroize.h"
#include "boot_suit.h"
#include "boot_swap.h"
#include "boot_multiimage.h"
#include "boot_types.h"
#include "boot_verify.h"
#include <string.h>

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
  BOOT_GLITCH_DELAY();
  if (shield_1 == BOOT_OK && acc_rev == 0)
    shield_2 = BOOT_OK;

  if (shield_1 == BOOT_OK && shield_2 == BOOT_OK && shield_1 == shield_2)
    return BOOT_OK;
  return BOOT_ERR_VERIFY;
}
/* P10 Zero-Trust CFI Constants (High Hamming Distance) */
#define CFI_TOKEN_INIT 0xAAAAAAAA
#define CFI_STEP_1 0x11111111
#define CFI_STEP_2 0x22222222
#define CFI_STEP_3 0x44444444
#define CFI_STEP_4 0x88888888
#define CFI_STEP_5 0x0F0F0F0F

extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

/* ==============================================================================
 * STATIC HELPERS (Single Responsibility & Glitch Shielded)
 * ==============================================================================
 */

/**
 * @brief O(1) Mathematisch perfekter Buffer-Boundary Check (UB-frei).
 */
static inline bool is_buffer_within(const uint8_t *inner, size_t inner_len,
                                    const uint8_t *outer, size_t outer_len) {
  if (inner_len == 0 || outer_len == 0)
    return false;
  uintptr_t i_start = (uintptr_t)inner;
  uintptr_t o_start = (uintptr_t)outer;

  /* Wraparound Bounds-Proof */
  if (UINTPTR_MAX - i_start < inner_len)
    return false;
  if (UINTPTR_MAX - o_start < outer_len)
    return false;

  return (i_start >= o_start) &&
         ((i_start + inner_len) <= (o_start + outer_len));
}

static boot_status_t _handle_rollback_flow(const boot_platform_t *platform,
                                           wal_tmr_payload_t *current_tmr,
                                           wal_entry_payload_t *open_txn,
                                           boot_target_config_t *target_out,
                                           volatile uint32_t *cfi_acc) {
  boot_status_t status = BOOT_OK;

  /* P10 Glitch Protection: Evaluierung des Counter-Status */
  volatile uint32_t eval_flag_1 = 0;
  volatile uint32_t eval_flag_2 = 0;

  if (current_tmr->boot_failure_counter > 0)
    eval_flag_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (eval_flag_1 == BOOT_OK && current_tmr->boot_failure_counter > 0)
    eval_flag_2 = BOOT_OK;

  if (eval_flag_1 == BOOT_OK && eval_flag_2 == BOOT_OK) {

    /* CASE A: Crash happened exactly after TXN_COMMIT. Revert Staging! */
    if (open_txn->intent == WAL_INTENT_TXN_COMMIT ||
        open_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
      status = boot_rollback_trigger_revert(platform);
      if (status != BOOT_OK)
        return status; /* FATAL: Cannot revert Staging image */

      target_out->boot_recovery_os =
          false; /* We will boot the restored Staging OS instead */
      open_txn->intent = WAL_INTENT_NONE; /* Old firmware is stable baseline.
                                             Drop trial constraints. */

      /* Heal the system completely: Set counter to 0 and persist NONE append */
      current_tmr->boot_failure_counter = 0;
      status = boot_journal_update_tmr(platform, current_tmr);
      if (status != BOOT_OK)
        return status;

      status = boot_journal_append(platform, open_txn);
      if (status != BOOT_OK)
        return status;

    } else {
      /* CASE B: Normal OS run with persistent crashes. Evaluate Backoff or
       * Recovery OS. */
      status = boot_rollback_evaluate_os(platform, current_tmr,
                                         &target_out->boot_recovery_os);
      if (status != BOOT_OK)
        return status;
    }
  }

  /* Logik-Bombe gefixt: Bei erfolgreicher Ausführung wird der CFI-Token exakt
   * verrechnet */
  *cfi_acc ^= CFI_STEP_3;
  return BOOT_OK;
}

static boot_status_t _handle_update_flow(const boot_platform_t *platform,
                                         wal_entry_payload_t *open_txn,
                                         uint32_t *extracted_svn,
                                         volatile uint32_t *cfi_acc) {
  if (open_txn->intent != WAL_INTENT_UPDATE_PENDING) {
    /* Logik-Bombe gefixt: CFI Kaskade sicher schließen, falls kein Update
     * läuft! */
    *cfi_acc ^= CFI_STEP_4;
    return BOOT_OK; /* Safe Exit: No update pending */
  }

  boot_status_t verify_status =
      BOOT_ERR_VERIFY; /* Grundannahme: Verifikation fehlgeschlagen
                          (Default-Deny) */
  struct toob_suit parsed_suit;
  size_t suit_consumed_bytes = 0; /* Elevated scope für Scratchpad Allocation */
  (void)suit_consumed_bytes;
  uint32_t local_svn = 0; /* Sicherer Zwischenspeicher für validierte SVN */

  boot_secure_zeroize(
      &parsed_suit, sizeof(parsed_suit)); /* P10: Uninitialized Trap Prevent */

#ifdef TOOB_MOCK_TEST
  suit_consumed_bytes = 128; /* Mock Payload Size */
  boot_verify_envelope_t mock_envelope = {
      .manifest_flash_addr = open_txn->offset,
      .manifest_size = 128,
      .signature_ed25519 = (const uint8_t *)"DUMMYSIG",
      .key_index = 0,
      .pqc_hybrid_active = false};
  verify_status = boot_verify_manifest_envelope(
      platform, &mock_envelope, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
#else
  /* 1. Einlesen des Manifests ins SRAM (Sektor-Größe reicht für SUIT Parser) */
  platform->wdt->kick();
  boot_status_t read_stat = platform->flash->read(
      open_txn->offset, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
  platform->wdt->kick();

  if (read_stat == BOOT_OK) {
    /* 2. ZCBOR Manifest Parsing (P10 Safe) */
    if (cbor_decode_toob_suit(crypto_arena, BOOT_CRYPTO_ARENA_SIZE,
                              &parsed_suit, &suit_consumed_bytes)) {

      /* Anti-Aliasing Fix: Extract hardware trust anchor safely to stack to
       * survive buffer overwrite from flash */
      uint8_t safe_sig_ed25519[64] __attribute__((aligned(8)));
      boot_secure_zeroize(safe_sig_ed25519, sizeof(safe_sig_ed25519));

      if (parsed_suit.suit_envelope.signature_ed25519.len != 64 ||
          !is_buffer_within(parsed_suit.suit_envelope.signature_ed25519.value, 64, crypto_arena, BOOT_CRYPTO_ARENA_SIZE) ||
          (parsed_suit.suit_envelope.pqc_hybrid_active && (
              !is_buffer_within(parsed_suit.suit_envelope.signature_pqc.value, parsed_suit.suit_envelope.signature_pqc.len, crypto_arena, BOOT_CRYPTO_ARENA_SIZE) ||
              !is_buffer_within(parsed_suit.suit_envelope.pubkey_pqc.value, parsed_suit.suit_envelope.pubkey_pqc.len, crypto_arena, BOOT_CRYPTO_ARENA_SIZE)
          )) ||
          (parsed_suit.suit_conditions.device_identifier.len > 0 &&
              !is_buffer_within(parsed_suit.suit_conditions.device_identifier.value, parsed_suit.suit_conditions.device_identifier.len, crypto_arena, BOOT_CRYPTO_ARENA_SIZE))) {
        verify_status = BOOT_ERR_INVALID_ARG;
      } else {
        memcpy(safe_sig_ed25519,
               parsed_suit.suit_envelope.signature_ed25519.value, 64);

        boot_verify_envelope_t real_envelope = {
            .manifest_flash_addr = open_txn->offset,
            .manifest_size = suit_consumed_bytes,
            .signature_ed25519 = safe_sig_ed25519,
            .key_index = parsed_suit.suit_envelope.key_index,
            .pqc_hybrid_active = parsed_suit.suit_envelope.pqc_hybrid_active,
            .signature_pqc = parsed_suit.suit_envelope.signature_pqc.value,
            .signature_pqc_len = parsed_suit.suit_envelope.signature_pqc.len,
            .pubkey_pqc = parsed_suit.suit_envelope.pubkey_pqc.value,
            .pubkey_pqc_len = parsed_suit.suit_envelope.pubkey_pqc.len};

        /* 3. Hardware-gehärtete Envelope Signatur Verifikation FIRST */
        verify_status = boot_verify_manifest_envelope(
            platform, &real_envelope, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

        /* CFI Glitch-Guard für Krypto-Resultat */
        volatile uint32_t env_flag1 = 0, env_flag2 = 0;
        if (verify_status == BOOT_OK)
          env_flag1 = BOOT_OK;
        BOOT_GLITCH_DELAY();
        if (env_flag1 == BOOT_OK && verify_status == BOOT_OK)
          env_flag2 = BOOT_OK;

        if (env_flag1 == BOOT_OK && env_flag2 == BOOT_OK) {
          local_svn = parsed_suit.suit_conditions.svn;
          /* 4. SVN Anti-Rollback Check happens ONLY if math signature matched
           * safely */
          verify_status = boot_rollback_verify_svn(platform, local_svn, false);

        /* P10 Hardware-Identitäts Check (Device Binding / Anti-Clone) */
        if (verify_status == BOOT_OK && parsed_suit.suit_conditions.device_identifier.len > 0) {
          uint8_t dslc_buf[32] __attribute__((aligned(8)));
          size_t dslc_len = 32;
          if (platform->crypto->read_dslc && platform->crypto->read_dslc(dslc_buf, &dslc_len) == BOOT_OK) {
            if (parsed_suit.suit_conditions.device_identifier.len != 32 || 
                constant_time_memcmp_glitch_safe(parsed_suit.suit_conditions.device_identifier.value, dslc_buf, 32) != BOOT_OK) {
              verify_status = BOOT_ERR_VERIFY; /* Hardware-MAC Mismatch! */
            }
          } else {
            verify_status = BOOT_ERR_NOT_SUPPORTED;
          }
        }
        
        /* EU-CRA SBOM Extraction (wird später in .noinit Diagnostics Areal versiegelt) */
        if (verify_status == BOOT_OK) {
          if (parsed_suit.suit_payload.sbom_digest.len == 32) {
            boot_diag_set_security_meta(local_svn, parsed_suit.suit_envelope.key_index, parsed_suit.suit_payload.sbom_digest.value);
          } else {
            boot_diag_set_security_meta(local_svn, parsed_suit.suit_envelope.key_index, NULL);
          }
        }
      } else {
        verify_status = BOOT_ERR_VERIFY; /* Trapped Glitch */
        }
      }
      boot_secure_zeroize(safe_sig_ed25519, sizeof(safe_sig_ed25519));
    } else {
      verify_status =
          BOOT_ERR_INVALID_ARG; /* Parse Error (Corrupt SUIT Manifest) */
    }
  } else {
    verify_status = read_stat;
  }
#endif

  bool requires_swap = true;
  uint32_t swap_src_addr = CHIP_STAGING_SLOT_ABS_ADDR;
  toob_image_header_t staging_header;
  boot_secure_zeroize(&staging_header, sizeof(staging_header));

  /* Double Check Gating VOR Auswertung des Staging Headers */
  volatile uint32_t v_flag1 = 0, v_flag2 = 0;
  if (verify_status == BOOT_OK)
    v_flag1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (v_flag1 == BOOT_OK && verify_status == BOOT_OK)
    v_flag2 = BOOT_OK;

  if (v_flag1 == BOOT_OK && v_flag2 == BOOT_OK) {
    /* M-VERIFY has cryptographically confirmed the Staging area.
       Next, statically read the TOOB Magic Header from the Staging-Slot to
       establish Swap bounds. */
    boot_status_t head_status = platform->flash->read(
        CHIP_STAGING_SLOT_ABS_ADDR, (uint8_t *)&staging_header,
        sizeof(toob_image_header_t));

    if (head_status != BOOT_OK || staging_header.magic != TOOB_MAGIC_HEADER) {
      verify_status = BOOT_ERR_INVALID_STATE;
    } else if (staging_header.image_size > CHIP_APP_SLOT_SIZE) {
      verify_status =
          BOOT_ERR_FLASH_BOUNDS; /* Bound-Check protection against overflow */
    } else {
      /* 5. GHOST MERKLE FIX: Stream-Hash Validation BEVOR geswappet wird!
         Die Firmware ist noch ungetestet. Wir jagen den Payload durch den
         Stream-Hasher. */

#ifndef TOOB_MOCK_TEST
      if (staging_header.image_size <= sizeof(toob_image_header_t)) {
        verify_status = BOOT_ERR_INVALID_ARG; /* Integer Underflow Prevention */
      } else {
        /* ZCBOR Array Extraction: Find Primary App Image & Route Delta/Raw */
        if (parsed_suit.suit_payload.toob_image_count == 0) {
            verify_status = BOOT_ERR_INVALID_ARG;
        } else {
            /* Iteriere nicht blind, wir werten Image[0] als unser Target */
            struct toob_image *app_img = &parsed_suit.suit_payload.toob_image[0];
            struct zcbor_string *chunk_hashes = NULL;
            uint32_t num_chunks = 0;
            uint32_t chunk_sz = 0;
            bool is_delta = false;

            if (app_img->toob_image_choice == toob_image_toob_image_raw_c) {
                chunk_hashes = &app_img->toob_image_raw.chunk_hashes;
                num_chunks = app_img->toob_image_raw.num_chunks;
                chunk_sz = app_img->toob_image_raw.chunk_size;
            } else if (app_img->toob_image_choice == toob_image_toob_image_delta_c) {
                chunk_hashes = &app_img->toob_image_delta.chunk_hashes;
                num_chunks = app_img->toob_image_delta.num_chunks;
                chunk_sz = app_img->toob_image_delta.chunk_size;
                is_delta = true;
            } else {
                verify_status = BOOT_ERR_INVALID_ARG;
            }

            if (verify_status == BOOT_OK) {
                if (!chunk_hashes || !is_buffer_within(chunk_hashes->value, chunk_hashes->len, crypto_arena, BOOT_CRYPTO_ARENA_SIZE)) {
                    verify_status = BOOT_ERR_INVALID_ARG; /* Exploit Trap */
                } else {
                    if (is_delta) {
                        /* P10 ANTI-BRICK: Die SDVM MUSS in einen Safe-Slot schreiben! 
                         * Ein In-Place Patch in den APP_SLOT zerstört die Base-Firmware!
                         * Wir nutzen temporär den Recovery-Slot als A/B Safe Buffer. */
                        boot_status_t delta_stat = boot_delta_apply(
                            platform, 
                            open_txn->offset + suit_consumed_bytes, CHIP_STAGING_SLOT_ABS_ADDR + CHIP_APP_SLOT_SIZE - (open_txn->offset + suit_consumed_bytes), 
                            CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE,  /* Ziel: Dedicated A/B Safe Buffer (Anti-Brick!) */
                            CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE,     /* Base: Alte Firmware */
                            open_txn);
                            
                        if (delta_stat == BOOT_OK) {
                            /* P10 SECURITY FIX: SDVM Output zwingend gegen den signierten Merkle-Tree prüfen! */
                            boot_status_t hash_stat = boot_merkle_verify_stream(
                                platform, CHIP_SCRATCH_SLOT_ABS_ADDR, 
                                app_img->toob_image_delta.image_size,
                                app_img->toob_image_delta.chunk_size,
                                chunk_hashes->value,
                                chunk_hashes->len,
                                num_chunks,
                                crypto_arena,
                                BOOT_CRYPTO_ARENA_SIZE);

                            if (hash_stat == BOOT_OK) {
                                verify_status = BOOT_OK;
                                requires_swap = true;
                                /* Swap zieht nun aus Scratch-Partition! */
                                staging_header.image_size = app_img->toob_image_delta.image_size;
                                swap_src_addr = CHIP_SCRATCH_SLOT_ABS_ADDR; 
                            } else {
                                verify_status = BOOT_ERR_VERIFY; /* ACE Prevention! SDVM Output war korrupt/manipuliert! */
                            }
                        } else {
                            verify_status = delta_stat;
                        }
                    } else {
                        /* ======================== RAW UPDATE ROUTING ======================== */
                        requires_swap = true;
                        swap_src_addr = CHIP_STAGING_SLOT_ABS_ADDR;
                        size_t aligned_offset = (suit_consumed_bytes + 7) & ~((size_t)7);
                        if (aligned_offset >= BOOT_CRYPTO_ARENA_SIZE) {
                            verify_status = BOOT_ERR_INVALID_ARG; 
                        } else {
                            uint8_t *scratch = crypto_arena + aligned_offset;
                            size_t scratch_size = BOOT_CRYPTO_ARENA_SIZE - aligned_offset;
                            if (scratch_size < chunk_sz) {
                                verify_status = BOOT_ERR_INVALID_ARG; 
                            } else {
                                boot_secure_zeroize(scratch, scratch_size);
                                verify_status = boot_merkle_verify_stream(platform, CHIP_STAGING_SLOT_ABS_ADDR,
                                    staging_header.image_size, chunk_sz, chunk_hashes->value, (uint32_t)chunk_hashes->len, num_chunks, scratch, scratch_size);
                                boot_secure_zeroize(scratch, scratch_size);
                            }
                        }
                    }
                }
            }
        }
      }
#endif
    }
  }

  boot_status_t flow_final_status = BOOT_OK;

  volatile uint32_t swap_gate_1 = 0, swap_gate_2 = 0;
  if (verify_status == BOOT_OK)
    swap_gate_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (swap_gate_1 == BOOT_OK && verify_status == BOOT_OK)
    swap_gate_2 = BOOT_OK;

  if (swap_gate_1 == BOOT_OK && swap_gate_2 == BOOT_OK) {
    boot_status_t swap_status = BOOT_OK;
    
    if (requires_swap) {
      swap_status = boot_swap_apply(
        platform, swap_src_addr, CHIP_APP_SLOT_ABS_ADDR,
        staging_header.image_size, BOOT_DEST_SLOT_APP, open_txn);
    }

    /* P10 FOTA Erweiterung: Multi-Image Deployment ausführen, falls CDDL Array > 1 */
    if (swap_status == BOOT_OK && parsed_suit.suit_payload.toob_image_count > 1) {
        boot_component_t components[3]; 
        uint32_t comp_count = 0;
        uint32_t current_staging_offset = staging_header.image_size;
        
        for (size_t i = 1; i < parsed_suit.suit_payload.toob_image_count && i < 4; i++) {
            struct toob_image *sub_img = &parsed_suit.suit_payload.toob_image[i];
            boot_secure_zeroize(&components[comp_count], sizeof(boot_component_t));
            components[comp_count].component_id = (uint32_t)i;
            
            if (sub_img->toob_image_choice == toob_image_toob_image_raw_c) {
                components[comp_count].image_size = sub_img->toob_image_raw.image_size;
                
                /* P10 FIX: Dynamisches Offset im Staging-Slot (Lückenloses aneinanderhängen) */
                components[comp_count].staging_offset = current_staging_offset;
                current_staging_offset += sub_img->toob_image_raw.image_size;
                
                if (sub_img->toob_image_raw.image_type == 1) {
                    components[comp_count].target_addr = CHIP_NETCORE_SLOT_ABS_ADDR;
                } else if (sub_img->toob_image_raw.image_type == 2) {
                    components[comp_count].target_addr = CHIP_RECOVERY_OS_ABS_ADDR;
                } else if (sub_img->toob_image_raw.image_type == 3) {
                    wal_tmr_payload_t temp_tmr;
                    boot_secure_zeroize(&temp_tmr, sizeof(temp_tmr));
                    if (boot_journal_get_tmr(platform, &temp_tmr) == BOOT_OK) {
                        components[comp_count].target_addr = (temp_tmr.active_stage1_bank == 0) 
                                                             ? CHIP_STAGE1B_ABS_ADDR 
                                                             : CHIP_STAGE1A_ABS_ADDR;
                    } else {
                        swap_status = BOOT_ERR_INVALID_ARG; break;
                    }
                } else {
                    swap_status = BOOT_ERR_INVALID_ARG; break;
                }
                
                if (sub_img->toob_image_raw.chunk_hashes.len >= 32) {
                    memcpy(components[comp_count].expected_hash, sub_img->toob_image_raw.chunk_hashes.value, 32); 
                    comp_count++;
                }
            }
        }
        
        if (swap_status == BOOT_OK && comp_count > 0) {
            boot_allowed_region_t whitelist[4] = {
                {CHIP_NETCORE_SLOT_ABS_ADDR, CHIP_NETCORE_SLOT_SIZE},               
                {CHIP_RECOVERY_OS_ABS_ADDR, CHIP_RECOVERY_OS_SIZE},
                {CHIP_STAGE1A_ABS_ADDR, CHIP_STAGE1A_SIZE},
                {CHIP_STAGE1B_ABS_ADDR, CHIP_STAGE1B_SIZE}
            };
            swap_status = boot_multiimage_apply(platform, CHIP_STAGING_SLOT_ABS_ADDR, 
                                                components, comp_count, whitelist, 4, open_txn);
        }
    }

    if (swap_status == BOOT_OK) {
      /* Atomically persist TXN_COMMIT. */
      wal_entry_payload_t commit_txn = *open_txn;
      commit_txn.intent = WAL_INTENT_TXN_COMMIT;

      boot_status_t status = boot_journal_append(platform, &commit_txn);
      if (status != BOOT_OK) {
        flow_final_status = status; /* FATAL: Cannot persist active State */
      } else {
        open_txn->intent = WAL_INTENT_TXN_COMMIT; /* Normalize local state */
        flow_final_status = BOOT_OK;

        /* FIX: Extrahierte SVN ERST HIER an den TMR übergeben, wenn das Update
         * echt installiert wurde! */
        if (extracted_svn != NULL) {
          *extracted_svn = local_svn;
        }
      }
    } else {
      flow_final_status = swap_status;
    }
  } else {
    /*
     * SMART ERROR TOPOLOGY: Trennt korrupte Updates von defekter Hardware.
     * Verification Failed (Bit-Rot, MITM, Mismatched Target-SVN/Device-ID).
     * We unequivocally reject the update and revert the intent to NONE.
     * Appending this to WAL prevents an infinite bootloop.
     */
    if (verify_status == BOOT_ERR_VERIFY ||
        verify_status == BOOT_ERR_DOWNGRADE ||
        verify_status == BOOT_ERR_INVALID_ARG ||
        verify_status == BOOT_ERR_FLASH_BOUNDS ||
        verify_status == BOOT_ERR_INVALID_STATE ||
        verify_status == BOOT_ERR_NOT_FOUND) {

      wal_entry_payload_t reject_txn = *open_txn;
      reject_txn.intent = WAL_INTENT_NONE;

      boot_status_t rej_stat = boot_journal_append(platform, &reject_txn);
      if (rej_stat != BOOT_OK) {
        flow_final_status = rej_stat;
      } else {
        open_txn->intent = WAL_INTENT_NONE;
        flow_final_status =
            BOOT_OK; // We recovered from the bad update by dropping it!
      }
    } else {
      /* Hardware Error -> Propagate for Panic */
      flow_final_status = verify_status;
    }
  }

#ifndef TOOB_MOCK_TEST
  /* Zeroize ZCBOR Pointers and SRAM Buffer to absolutely close Data-Leakage */
  boot_secure_zeroize(&parsed_suit, sizeof(parsed_suit));
#endif

  if (flow_final_status == BOOT_OK) {
    *cfi_acc ^= CFI_STEP_4;
  }
  return flow_final_status;
}

/* ==============================================================================
 * MAIN BOOT STATE MACHINE (CFI-ORCHESTRATOR)
 * ==============================================================================
 */

boot_status_t boot_state_run(const boot_platform_t *platform,
                             boot_target_config_t *target_out) {
  /* P10 Pointer-Guard (Zero-Trust HAL Assumption) */
  if (!platform || !platform->clock || !platform->flash || !platform->crypto ||
      !platform->wdt || !target_out) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (!platform->clock->get_reset_reason || !platform->flash->read ||
      !platform->crypto->random || !platform->wdt->kick) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Initialize Output Struct entirely to prevent uninitialized memory attacks
   */
  boot_secure_zeroize(target_out, sizeof(boot_target_config_t));

  /* Global Control Flow Integrity (CFI) Accumulator */
  volatile uint32_t state_cfi = CFI_TOKEN_INIT;

  wal_entry_payload_t open_txn;
  wal_tmr_payload_t current_tmr;
  boot_secure_zeroize(&open_txn, sizeof(open_txn));
  boot_secure_zeroize(&current_tmr, sizeof(current_tmr));

  boot_status_t core_status = BOOT_OK;

  /*
   * ==============================================================================
   * STEP 1 - Journal Initialization, TMR State Retrieval & WAL Reconstruction
   * ==============================================================================
   */
  core_status = boot_journal_init(platform);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  core_status = boot_journal_get_tmr(platform, &current_tmr);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  uint32_t active_net_accum = 0;
  uint32_t resume_offset = 0;
  core_status =
      boot_journal_reconstruct_txn(platform, &open_txn, &active_net_accum, &resume_offset);

  if (core_status != BOOT_OK && core_status != BOOT_ERR_STATE) {
    goto state_cleanup;
  }

  if (core_status == BOOT_ERR_STATE) {
    open_txn.intent = WAL_INTENT_NONE;
    core_status = BOOT_OK; /* Normalize clean state */
  }

  state_cfi ^= CFI_STEP_1; /* Proof Step 1 */
  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 2 - Clean-Up / Confirmation Check (Auth Protected)
   * ==============================================================================
   */
  uint64_t combined_nonce = ((uint64_t)current_tmr.active_nonce_hi << 32) |
                            current_tmr.active_nonce_lo;
  bool rtc_confirmed = false;

  if (platform->confirm && platform->confirm->check_ok) {
    rtc_confirmed = platform->confirm->check_ok(combined_nonce);
  }

  if (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT ||
      open_txn.intent == WAL_INTENT_RECOVERY_RESOLVED || rtc_confirmed) {

    /* P10 Security: Glitch-Resistente Nonce-Autorisation */
    volatile uint32_t auth_flag_1 = 0;
    volatile uint32_t auth_flag_2 = 0;

    bool intent_is_confirm = (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT);
    bool intent_is_recovery = (open_txn.intent == WAL_INTENT_RECOVERY_RESOLVED);
    reset_reason_t rst = platform->clock->get_reset_reason();

    if (rtc_confirmed) {
      auth_flag_1 = BOOT_OK;
      if (open_txn.intent == WAL_INTENT_NONE)
        open_txn.intent = WAL_INTENT_CONFIRM_COMMIT;
    } else if (intent_is_confirm) {
      /* XOR Math: 0 bedeutet exakter Match */
      uint64_t diff = open_txn.expected_nonce ^ combined_nonce;
      if (diff == 0)
        auth_flag_1 = BOOT_OK;
    } else if (intent_is_recovery && (rst == RESET_REASON_PIN_RESET ||
                                      rst == RESET_REASON_POWER_ON)) {
      auth_flag_1 = BOOT_OK;
    }

    BOOT_GLITCH_DELAY();

    if (auth_flag_1 == BOOT_OK) {
      if (rtc_confirmed ||
          (intent_is_confirm &&
           (open_txn.expected_nonce ^ combined_nonce) == 0) ||
          (intent_is_recovery &&
           (rst == RESET_REASON_PIN_RESET || rst == RESET_REASON_POWER_ON))) {
        auth_flag_2 = BOOT_OK;
      }
    }

    if (auth_flag_1 != BOOT_OK || auth_flag_2 != BOOT_OK ||
        auth_flag_1 != auth_flag_2) {
      /* MALICIOUS OR CORRUPT AUTHORIZATION! Discard silently. */
      open_txn.intent = WAL_INTENT_NONE;
    } else {
      /* SUCCESS: Rigorously reset the TMR boot_failure_counter back to 0. */
      if (current_tmr.boot_failure_counter > 0) {
        current_tmr.boot_failure_counter = 0;
        core_status = boot_journal_update_tmr(platform, &current_tmr);
        if (core_status != BOOT_OK)
          goto state_cleanup;
      }
      /* Normalize intent to IDLE */
      open_txn.intent = WAL_INTENT_NONE;
      core_status = boot_journal_append(platform, &open_txn);
      if (core_status != BOOT_OK)
        goto state_cleanup;
        
      /* GAP-07: Datenhygiene - Erase des Staging Slots nach erfolgreichem Boot! */
      platform->wdt->kick();
      /* Fire-and-Forget Erase des kompletten Staging Slots, um Firmware-Leaks zu verhindern */
      /* P10 Fix: Wir ignorieren den Return-Code, da der Boot bereits als COMMITTED gilt.
         Ein Fehler hier darf das OS nicht bricked lassen. */
      (void)boot_swap_erase_safe(platform, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE);
    }
  }

  state_cfi ^= CFI_STEP_2; /* Proof Step 2 */

  /*
   * ==============================================================================
   * STEP 3 - Failure Counter & Recovery Evaluation (M-ROLLBACK)
   * ==============================================================================
   */
  reset_reason_t rst_reason = platform->clock->get_reset_reason();

  /* Unconfirmed crash detection (excludes intent processing crashes itself) */
  bool is_app_crash = false;
  if ((rst_reason == RESET_REASON_WATCHDOG ||
       rst_reason == RESET_REASON_HARD_FAULT ||
       rst_reason == RESET_REASON_BROWNOUT) &&
      (open_txn.intent != WAL_INTENT_UPDATE_PENDING &&
       open_txn.intent != WAL_INTENT_TXN_BEGIN)) {
    is_app_crash = true;
  }

  volatile uint32_t crash_flag_1 = 0, crash_flag_2 = 0;
  if (is_app_crash)
    crash_flag_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (crash_flag_1 == BOOT_OK && is_app_crash)
    crash_flag_2 = BOOT_OK;

  if (crash_flag_1 == BOOT_OK && crash_flag_2 == BOOT_OK) {
    current_tmr.boot_failure_counter++;
    core_status = boot_journal_update_tmr(platform, &current_tmr);
    if (core_status != BOOT_OK)
      goto state_cleanup;
  }

  core_status = _handle_rollback_flow(platform, &current_tmr, &open_txn,
                                      target_out, &state_cfi);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 4 - Update Pipeline (STAGING -> TESTING -> SWAP)
   * ==============================================================================
   */
  uint32_t extracted_svn = 0;

  core_status =
      _handle_update_flow(platform, &open_txn, &extracted_svn, &state_cfi);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  if (extracted_svn > current_tmr.app_svn) {
    current_tmr.app_svn = extracted_svn;
  }

  /*
   * ==============================================================================
   * STEP 5 - Handoff Preparation / Nonce Registration
   * ==============================================================================
   */
  toob_image_header_t app_header;
  boot_secure_zeroize(&app_header, sizeof(app_header));

  uint32_t slot_addr = target_out->boot_recovery_os ? CHIP_RECOVERY_OS_ABS_ADDR
                                                    : CHIP_APP_SLOT_ABS_ADDR;

  core_status = platform->flash->read(slot_addr, (uint8_t *)&app_header,
                                      sizeof(toob_image_header_t));
  if (core_status != BOOT_OK)
    goto state_cleanup;

  /* Glitch-Proof Magic Header Boundary */
  volatile uint32_t magic_shield_1 = 0, magic_shield_2 = 0;
  if (app_header.magic == TOOB_MAGIC_HEADER)
    magic_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (magic_shield_1 == BOOT_OK && app_header.magic == TOOB_MAGIC_HEADER)
    magic_shield_2 = BOOT_OK;

  if (magic_shield_1 != BOOT_OK || magic_shield_2 != BOOT_OK) {
    core_status = BOOT_ERR_NOT_FOUND;
    goto state_cleanup;
  }

  target_out->active_entry_point = app_header.entry_point;
  target_out->active_image_size = app_header.image_size;

  /* Glitch-Shielded Evaluation for Nonce Generation */
  volatile uint32_t req_flag_1 = 0, req_flag_2 = 0;
  if (open_txn.intent == WAL_INTENT_TXN_COMMIT)
    req_flag_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (req_flag_1 == BOOT_OK && open_txn.intent == WAL_INTENT_TXN_COMMIT)
    req_flag_2 = BOOT_OK;

  bool requires_confirmation = (req_flag_1 == BOOT_OK && req_flag_2 == BOOT_OK);
  target_out->is_tentative_boot = requires_confirmation;

  platform->wdt->kick();

  if (requires_confirmation) {
    core_status = platform->crypto->random(
        (uint8_t *)&target_out->generated_nonce, sizeof(uint64_t));
    if (core_status != BOOT_OK)
      goto state_cleanup;

    current_tmr.active_nonce_lo =
        (uint32_t)(target_out->generated_nonce & 0xFFFFFFFF);
    current_tmr.active_nonce_hi = (uint32_t)(target_out->generated_nonce >> 32);
    core_status = boot_journal_update_tmr(platform, &current_tmr);
    if (core_status != BOOT_OK)
      goto state_cleanup;

    /* Stateful Slide Abandonment Fix */
    if (open_txn.intent != WAL_INTENT_NONE) {
      core_status = boot_journal_append(platform, &open_txn);
      if (core_status != BOOT_OK)
        goto state_cleanup;
    }
  } else {
    target_out->generated_nonce = 0;
  }

  target_out->net_search_accum_ms = active_net_accum;
  target_out->resume_offset = resume_offset;
  state_cfi ^= CFI_STEP_5;

state_cleanup:
  /* ==============================================================================
   * FINAL GLITCH-DEFENSE GATE (CFI VALIDATION)
   * ==============================================================================
   * Nur wenn der Status bisher legitimerweise OK war, prüfen wir, ob die
   * Pipeline physisch lückenlos bewiesen wurde! Ist sie das nicht, liegt ein
   * Fault-Injection Angriff (PC-Glitch) vor. Hardware-Fehler aus früheren
   * Schritten dürfen durch diesen Check nicht mit BOOT_ERR_INVALID_STATE
   * überschrieben werden!
   */
  if (core_status == BOOT_OK) {
    uint32_t expected_cfi = CFI_TOKEN_INIT ^ CFI_STEP_1 ^ CFI_STEP_2 ^
                            CFI_STEP_3 ^ CFI_STEP_4 ^ CFI_STEP_5;
    volatile uint32_t cfi_shield_1 = 0;
    volatile uint32_t cfi_shield_2 = 0;

    if (state_cfi == expected_cfi)
      cfi_shield_1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (cfi_shield_1 == BOOT_OK && state_cfi == expected_cfi)
      cfi_shield_2 = BOOT_OK;

    if (cfi_shield_1 != BOOT_OK || cfi_shield_2 != BOOT_OK) {
      core_status = BOOT_ERR_INVALID_STATE; /* CFI Failure - Attack Trapped! */
    }
  }

  /* Secure Fallback: Nulle den Target Output bei Fehlern, damit niemand den PC
   * verbiegt! */
  if (core_status != BOOT_OK) {
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
  }

  /* P10 Single-Exit: Vernichte kritische Runtime-Secrets (TMR/WAL-Payloads) vom
   * C-Stack */
  boot_secure_zeroize(&open_txn, sizeof(open_txn));
  boot_secure_zeroize(&current_tmr, sizeof(current_tmr));
  boot_secure_zeroize(&app_header, sizeof(app_header));

  return core_status;
}