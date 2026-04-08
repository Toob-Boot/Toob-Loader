/**
 * @file boot_state.c
 * @brief Core State-Machine Logic
 *
 * Implements the lifecycle orchestration for the update state machine
 * bridging M-JOURNAL, M-VERIFY, M-SWAP, and M-ROLLBACK.
 */

#include "boot_state.h"
#include "boot_types.h"
#include "boot_journal.h"
#include <string.h>

#include "boot_verify.h"
#include "boot_swap.h"
#include "boot_rollback.h"
#include "boot_config_mock.h"
#include "boot_suit.h"
#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include "boot_secure_zeroize.h"

extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

/* Static P10 Allocation: Verhindert Bare-Metal Stack Overflow für Stream Hashing */
static uint8_t stream_buf[CHIP_FLASH_MAX_SECTOR_SIZE];

/* ==============================================================================
 * STATIC HELPERS (Single Responsibility Principle)
 * ============================================================================== */

static boot_status_t _handle_rollback_flow(const boot_platform_t *platform, wal_tmr_payload_t *current_tmr, wal_entry_payload_t *open_txn, boot_target_config_t *target_out) {
    boot_status_t status = BOOT_OK;

    if (current_tmr->boot_failure_counter > 0) {
        /* 
         * CASE A: The crash happened immediately after a completed update (TXN_COMMIT) 
         * where Staging holds the old firmware via M-SWAP.
         * -> We must invoke M-SWAP in reverse to physically rollback!
         */
        if (open_txn->intent == WAL_INTENT_TXN_COMMIT || open_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
            /* Trigger M-SWAP in rollback mode to revert the failed new firmware */
            status = boot_rollback_trigger_revert(platform);
            if (status != BOOT_OK) {
                return status; /* FATAL: Cannot revert Staging image */
            }
            target_out->boot_recovery_os = false; /* We will boot the restored Staging OS instead */
            open_txn->intent = WAL_INTENT_NONE; /* Old firmware is stable baseline. Drop trial constraints. */
            
            /* Heal the system completely: Set counter to 0 and persist NONE append */
            current_tmr->boot_failure_counter = 0;
            status = boot_journal_update_tmr(platform, current_tmr);
            if (status != BOOT_OK) return status;
            
            status = boot_journal_append(platform, open_txn);
            if (status != BOOT_OK) return status;
        } 
        /* 
         * CASE B: Normal OS run with persistent crashes.
         * -> M-ROLLBACK must evaluate exponential backoff or booting Recovery-OS.
         */
        else {
            status = boot_rollback_evaluate_os(platform, current_tmr, &target_out->boot_recovery_os);
            if (status != BOOT_OK) {
                return status;
            }
        }
    }
    return BOOT_OK;
}

static boot_status_t _handle_update_flow(const boot_platform_t *platform, wal_entry_payload_t *open_txn, uint32_t *extracted_svn) {
    if (open_txn->intent != WAL_INTENT_UPDATE_PENDING) {
        return BOOT_OK;
    }

#ifdef TOOB_MOCK_TEST
    boot_verify_envelope_t mock_envelope = {
        .manifest_flash_addr = open_txn->offset, /* OS delivers intent offset */
        .manifest_size = 128, /* Dummy Size */
        .signature_ed25519 = (const uint8_t*)"DUMMYSIG",
        .key_index = 0,
        .pqc_hybrid_active = false
    };

    boot_status_t verify_status = boot_verify_manifest_envelope(platform, &mock_envelope, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
#else
    boot_status_t verify_status = BOOT_ERR_VERIFY; /* Grundannahme Verifikation fehlgeschlagen */
    
    /* 1. Einlesen des Manifests ins SRAM (Sektor-Größe reicht für SUIT Parser) */
    platform->wdt->kick();
    boot_status_t read_stat = platform->flash->read(open_txn->offset, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    platform->wdt->kick();

    struct toob_suit parsed_suit;
    memset(&parsed_suit, 0, sizeof(parsed_suit));
    
    if (read_stat == BOOT_OK) {
        size_t consumed_bytes = 0;
        
        /* 2. ZCBOR Manifest Parsing (P10 Safe) */
        if (cbor_decode_toob_suit(crypto_arena, BOOT_CRYPTO_ARENA_SIZE, &parsed_suit, &consumed_bytes)) {
            
            /* Anti-Aliasing Fix: Extract hardware trust anchor safely to stack to survive buffer overwrite from flash */
            uint8_t safe_sig_ed25519[64];
            if (parsed_suit.suit_envelope.signature_ed25519.len != 64) {
                verify_status = BOOT_ERR_INVALID_ARG;
            } else {
                memcpy(safe_sig_ed25519, parsed_suit.suit_envelope.signature_ed25519.value, 64);

                boot_verify_envelope_t real_envelope = {
                    .manifest_flash_addr = open_txn->offset,
                    .manifest_size = consumed_bytes,
                    .signature_ed25519 = safe_sig_ed25519,
                    .key_index = parsed_suit.suit_envelope.key_index,
                    .pqc_hybrid_active = parsed_suit.suit_envelope.pqc_hybrid_active,
                    .signature_pqc = parsed_suit.suit_envelope.signature_pqc.value,
                    .signature_pqc_len = parsed_suit.suit_envelope.signature_pqc.len,
                    .pubkey_pqc = parsed_suit.suit_envelope.pubkey_pqc.value,
                    .pubkey_pqc_len = parsed_suit.suit_envelope.pubkey_pqc.len
                };

                /* 3. Hardware-gehärtete Envelope Signatur Verifikation FIRST */
                verify_status = boot_verify_manifest_envelope(platform, &real_envelope, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

                if (verify_status == BOOT_OK) {
                    /* 4. SVN Anti-Rollback Check happens ONLY if math signature matched safely */
                    verify_status = boot_rollback_verify_svn(platform, parsed_suit.suit_conditions.svn, false); /* is_recovery_os = false */
                }
                boot_secure_zeroize(safe_sig_ed25519, sizeof(safe_sig_ed25519));
            }
        } else {
            verify_status = BOOT_ERR_INVALID_ARG; /* Parse Error (Corrupt SUIT Manifest) */
        }
    } else {
        verify_status = read_stat;
    }
#endif

    toob_image_header_t staging_header = {0};
    if (verify_status == BOOT_OK) {
        /* M-VERIFY has cryptographically confirmed the Staging area.
           Next, statically read the TOOB Magic Header from the Staging-Slot to establish Swap bounds. */
        boot_status_t head_status = platform->flash->read(CHIP_STAGING_SLOT_ABS_ADDR, (uint8_t*)&staging_header, sizeof(toob_image_header_t));
        
        if (head_status != BOOT_OK || staging_header.magic != TOOB_MAGIC_HEADER) {
            verify_status = BOOT_ERR_INVALID_STATE;
        } else if (staging_header.image_size > CHIP_APP_SLOT_SIZE) {
            verify_status = BOOT_ERR_FLASH_BOUNDS; /* Bound-Check protection against overflow */
        } else {
            /* 5. GHOST MERKLE FIX: Führe die Stream-Hash Validation aus, BEVOR geswappet wird!
               Die Firmware ist noch ungetestet. Wir jagen den Payload durch den Stream-Hasher.
               P10 Rule: Wir nutzen out-of-scope pointers von parsed_suit.suit_payload.images sicher,
               weil wir M-MERKLE anweisen, das Scratch-Buffer intern neu zu deklarieren (nicht-destruktiv für ZCBOR Pointer). */
               
            #ifndef TOOB_MOCK_TEST
            if (staging_header.image_size <= sizeof(toob_image_header_t)) {
                verify_status = BOOT_ERR_INVALID_ARG; /* Integer Underflow Prevention */
            } else {
                uint32_t chunk_size = 4096; /* GAP-08 Spec Default */
                uint32_t num_chunks = parsed_suit.suit_payload.images.len / 32;
                
                verify_status = boot_merkle_verify_stream(platform, 
                                            CHIP_STAGING_SLOT_ABS_ADDR, 
                                            staging_header.image_size, 
                                            chunk_size, 
                                            parsed_suit.suit_payload.images.value, 
                                            parsed_suit.suit_payload.images.len, 
                                            num_chunks, 
                                            stream_buf, 
                                            sizeof(stream_buf));
            }
            #endif
        }
    }

    if (verify_status == BOOT_OK) {
        /* 
         * The update integrity is mathematically proven.
         * Trigger the WDT-safe In-Place Overwrite execution via M-SWAP.
         * The HAL suspends the WDT natively during monolithic ROM erase operations.
         */
        boot_status_t swap_status = boot_swap_apply(platform, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_APP_SLOT_ABS_ADDR, staging_header.image_size, BOOT_DEST_SLOT_APP, open_txn);

        if (swap_status == BOOT_OK) {
            /*
             * The new image resides intact in the Active Slot.
             * Atomically persist TXN_COMMIT. If S1 crashes exactly here, 
             * Step 3 Rollback logic catches the unconfirmed firmware.
             */
            wal_entry_payload_t commit_txn = *open_txn;
            commit_txn.intent = WAL_INTENT_TXN_COMMIT;
            
            boot_status_t status = boot_journal_append(platform, &commit_txn);
            if (status != BOOT_OK) {
                return status; /* FATAL: Cannot persist active State */
            }
            
            open_txn->intent = WAL_INTENT_TXN_COMMIT; /* Normalize local state */
#ifndef TOOB_MOCK_TEST
            *extracted_svn = parsed_suit.suit_conditions.svn; /* GAP: Persist new SVN natively */
#endif
        } else {
            /* 
             * Swap physically failed (e.g., EOL Silicon, persistent Flash ECC errors).
             * We abort. The State-Machine will panic via return.
             */
            return swap_status;
        }
    } else {
        /* 
         * Verification Failed (Bit-Rot, MITM, Mismatched Target-SVN/Device-ID).
         * We unequivocally reject the update and revert the intent to NONE.
         * Appending this to WAL prevents an infinite verification exhaustion loop.
         */
        wal_entry_payload_t reject_txn = *open_txn;
        reject_txn.intent = WAL_INTENT_NONE;
        
        boot_status_t rej_stat = boot_journal_append(platform, &reject_txn);
        if (rej_stat != BOOT_OK) {
            return rej_stat; /* Fatal error, prevents endless failure loops */
        }
        open_txn->intent = WAL_INTENT_NONE;
        
        /* Proceed to boot the old fallback app silently as if no update happened */
    }
    return BOOT_OK;
}

/* ==============================================================================
 * MAIN BOOT STATE MACHINE 
 * ============================================================================== */

boot_status_t boot_state_run(const boot_platform_t *platform, boot_target_config_t *target_out) {
    /* P10 Pointer-Guard (Zero-Trust HAL Assumption) */
    if (!platform || !platform->clock || !platform->flash || !platform->crypto || !platform->wdt || !target_out) {
        return BOOT_ERR_INVALID_ARG;
    }
    
    /* Strict Functional Pointer Guard */
    if (!platform->clock->get_reset_reason || !platform->flash->read || 
        !platform->crypto->random || !platform->wdt->kick) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* Initialize Output Struct entirely to prevent uninitialized pointer bugs (e.g. boot_recovery_os) */
    memset(target_out, 0, sizeof(boot_target_config_t));

    wal_entry_payload_t open_txn = {0};
    wal_tmr_payload_t current_tmr = {0};
    
    /* 
     * ==============================================================================
     * STEP 1 - Journal Initialization, TMR State Retrieval & WAL Reconstruction
     * ==============================================================================
     */

    /* Initialize the WAL subsystem (scans sliding window and validates entries) */
    boot_status_t status = boot_journal_init(platform);
    if (status != BOOT_OK) {
        /* FATAL: Flash is inaccessible or Journal is fundamentally corrupted. */
        return status;
    }

    /* Retrieve current verified TMR Payload (Majority Voted) */
    status = boot_journal_get_tmr(platform, &current_tmr);
    if (status != BOOT_OK) {
        return status;
    }

    /* Reconstruct open transactions (Intents) */
    uint32_t active_net_accum = 0;
    status = boot_journal_reconstruct_txn(platform, &open_txn, &active_net_accum);
    if (status != BOOT_OK && status != BOOT_ERR_STATE) {
        /* 
         * BOOT_ERR_STATE is acceptable here. It indicates an empty, 
         * completely IDLE initialized journal with no pending transactions.
         * Any other error implies genuine WAL corruption.
         */
        return status;
    }

    /* Normalize the absent-transaction state to IDLE logic */
    if (status == BOOT_ERR_STATE) {
        open_txn.intent = WAL_INTENT_NONE;
    }

    platform->wdt->kick();

    /*
     * ==============================================================================
     * STEP 2 - Clean-Up / Confirmation Check (CONFIRMED & RECOVERY_RESOLVED)
     * ==============================================================================
     */
    /* FIX (Doublecheck): Added missing WAL_INTENT_RECOVERY_RESOLVED check from Specs */
    uint64_t combined_nonce = ((uint64_t)current_tmr.active_nonce_hi << 32) | current_tmr.active_nonce_lo;
    bool rtc_confirmed = false;
    
    if (platform->confirm && platform->confirm->check_ok) {
        rtc_confirmed = platform->confirm->check_ok(combined_nonce);
    }

    if (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT || 
        open_txn.intent == WAL_INTENT_RECOVERY_RESOLVED || 
        rtc_confirmed) {
        
        /* 
         * P10 Security: Nonce Authorization (Anti-Replay Validation)
         * Stellt sicher, dass das CONFIRM_COMMIT vom Feature-OS kryptografisch legitim 
         * ist. Die aktive Nonce kommt hardware-signed aus der TMR-Payload, NICHT aus 
         * dem OS-schreibbaren WAL (Verhindert Bypass-Attacken).
         */
        bool is_authorized = false;
        
        if (rtc_confirmed) {
            is_authorized = true;
            /* Virtuell den Intent-Fluss auf CONFIRM einstellen, um sauberes Cleanup zu triggern */
            if (open_txn.intent == WAL_INTENT_NONE) {
                open_txn.intent = WAL_INTENT_CONFIRM_COMMIT;
            }
        } else if (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT) {
            is_authorized = (open_txn.expected_nonce == combined_nonce);
        } else if (open_txn.intent == WAL_INTENT_RECOVERY_RESOLVED) {
            /* 
             * P10 Security: RECOVERY_RESOLVED darf nur greifen, wenn der Reboot
             * physisch vom Operator ausgeführt wurde (PIN/Power-On). Dies verhindert
             * Malware-Mopsing des Serial-Rescue Intents.
             */
            reset_reason_t rst = platform->clock->get_reset_reason();
            if (rst == RESET_REASON_PIN_RESET || rst == RESET_REASON_POWER_ON) {
                is_authorized = true;
            }
        }
        
        if (!is_authorized) {
            /* MALICIOUS OR CORRUPT AUTHORIZATION! We discard it silently to 
             * treat it like a generic Un-Confirmed Crash-Reboot. */
            open_txn.intent = WAL_INTENT_NONE;
        } else {
            /*
             * OS Boot or Recovery-Rescue was successful and delivered an atomic confirm.
             * We rigorously reset the TMR boot_failure_counter back to 0 to separate
             * past resolved crashes from future, unrelated timeouts.
             */
            if (current_tmr.boot_failure_counter > 0) {
                current_tmr.boot_failure_counter = 0;
                status = boot_journal_update_tmr(platform, &current_tmr);
                if (status != BOOT_OK) {
                    return status;
                }
            }
            /* Normalize intent to IDLE so the OS boots normally without recurring updates.
             * Force WAL Append to ensure the stale RECOVERY_RESOLVED doesn't loop on next reboot. */
            open_txn.intent = WAL_INTENT_NONE;
            status = boot_journal_append(platform, &open_txn);
            if (status != BOOT_OK) {
                return status;
            }
        }
    }

    /*
     * ==============================================================================
     * STEP 3 - Failure Counter & Recovery Evaluation (M-ROLLBACK)
     * ==============================================================================
     */
    reset_reason_t rst_reason = platform->clock->get_reset_reason();

    /* 
     * Identify an unconfirmed OS crash.
     * We assertively exclude UPDATE_PENDING and TXN_BEGIN intents here, because a crash 
     * *strictly during* an update process is handled by WAL-Resume, not the OS App-Level 
     * failure counter!
     */
    bool is_app_crash = (rst_reason == RESET_REASON_WATCHDOG || 
                         rst_reason == RESET_REASON_HARD_FAULT || 
                         rst_reason == RESET_REASON_BROWNOUT) && 
                         (open_txn.intent != WAL_INTENT_UPDATE_PENDING && 
                          open_txn.intent != WAL_INTENT_TXN_BEGIN);

    if (is_app_crash) {
        /* Increment failure counter and persist defensively before deciding fallback */
        current_tmr.boot_failure_counter++;
        status = boot_journal_update_tmr(platform, &current_tmr);
        if (status != BOOT_OK) {
            return status;
        }
    }

    status = _handle_rollback_flow(platform, &current_tmr, &open_txn, target_out);
    if (status != BOOT_OK) {
        return status;
    }

    platform->wdt->kick();

    /*
     * ==============================================================================
     * STEP 4 - Update Pipeline (STAGING -> TESTING -> SWAP)
     * ==============================================================================
     */
    
    uint32_t extracted_svn = 0;
    status = _handle_update_flow(platform, &open_txn, &extracted_svn);
    if (status != BOOT_OK) {
        return status;
    }

    /* NEU: Übernimm die neue SVN (Nur wenn sie größer ist, schützt vor Downgrade bei Reboots) */
    if (extracted_svn > current_tmr.app_svn) {
        current_tmr.app_svn = extracted_svn;
    }

    /*
     * ==============================================================================
     * STEP 5 - Handoff Preparation / Nonce Registration
     * ==============================================================================
     */
    
    /* 
     * Read the TOOB Magic Header from the securely determined active primary slot
     * to validate binary structure and retrieve bounds (Entry-Point, Image-Size) 
     * for Stage 0 MPU restrictions and the feature-OS jump.
     */
    toob_image_header_t app_header = {0};
    
    /* 
     * concept_fusion.md dictates an In-Place architecture for the main OS (App Slot A only).
     * The primary_slot_id in TMR refers ONLY to Stage 1. 
     */
    uint32_t slot_addr = CHIP_APP_SLOT_ABS_ADDR;
    
    /* Determine if rollback chose Recovery OS partition instead */
    if (target_out->boot_recovery_os) {
        slot_addr = CHIP_RECOVERY_OS_ABS_ADDR;
    }

    status = platform->flash->read(slot_addr, &app_header, sizeof(toob_image_header_t));
    if (status != BOOT_OK) {
        return status; /* FATAL: Hardware Flash Read Error */
    }

    /* End-to-end structural protection against booting erased sectors (0xFF) */
    if (app_header.magic != TOOB_MAGIC_HEADER) {
        return BOOT_ERR_NOT_FOUND; 
    }

    target_out->active_entry_point = app_header.entry_point;
    target_out->active_image_size  = app_header.image_size;

    /*
     * M-CONFIRM Anti-Replay Nonce Logic:
     * To prevent rapid wear-out of WAL Flash blocks, we ONLY generate a cryptographic 
     * nonce and expend an atomic WAL Append if the OS is currently unconfirmed 
     * (i.e. Trial Boot mapped via TXN_COMMIT or Crash Recovery Boot).
     */
    bool requires_confirmation = (open_txn.intent == WAL_INTENT_TXN_COMMIT);
    target_out->is_tentative_boot = requires_confirmation;

    platform->wdt->kick();

    if (requires_confirmation) {
        /* Generate cryptographically unpredictable 64-bit Nonce */
        status = platform->crypto->random((uint8_t*)&target_out->generated_nonce, sizeof(uint64_t));
        if (status != BOOT_OK) {
            return status; /* Graceful fallback. Do not lockup the device with P10_ASSERT! */
        }

        /* Secure the Expected Nonce deep inside the TMR payload.
         * The OS cannot forge this since it cannot calculate the Sector Header CRC32. */
        current_tmr.active_nonce_lo = (uint32_t)(target_out->generated_nonce & 0xFFFFFFFF);
        current_tmr.active_nonce_hi = (uint32_t)(target_out->generated_nonce >> 32);
        status = boot_journal_update_tmr(platform, &current_tmr);
        if (status != BOOT_OK) {
            return status;
        }

        /* 3.4 FIX: Stateful Slide Abandonment
         * boot_journal_update_tmr verschiebt das WAL Window.
         * Wir MÜSSEN den offenen open_txn erneut ins neue Window schreiben, 
         * damit der Rollback den Boot nach einem Brownout noch auswerten kann. */
        if (open_txn.intent != WAL_INTENT_NONE) {
            status = boot_journal_append(platform, &open_txn);
            if (status != BOOT_OK) return status;
        }
    } else {
        /* 
         * Stable System: Provide statically zeroed nonce to OS.
         * The LibToob C-API confirms the runtime state via (failure_count == 0) 
         * and prevents burning Flash aggressively during daily cold-boots!
         */
        target_out->generated_nonce = 0;
    }

    target_out->net_search_accum_ms = active_net_accum;

    /* Target configuration populated perfectly. Orchestration complete. */
    return BOOT_OK;
}
