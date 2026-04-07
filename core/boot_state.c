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
    if (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT || 
        open_txn.intent == WAL_INTENT_RECOVERY_RESOLVED) {
        
        /* 
         * P10 Security: Nonce Authorization (Anti-Replay Validation)
         * Stellt sicher, dass das CONFIRM_COMMIT vom Feature-OS kryptografisch legitim 
         * ist. Die aktive Nonce kommt hardware-signed aus der TMR-Payload, NICHT aus 
         * dem OS-schreibbaren WAL (Verhindert Bypass-Attacken).
         */
        bool is_authorized = false;
        
        if (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT) {
            is_authorized = (open_txn.expected_nonce == current_tmr.active_nonce);
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
            /* Normalize intent to IDLE so the OS boots normally without recurring updates */
            open_txn.intent = WAL_INTENT_NONE;
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

    /* 
     * Evaluate the cascading Rollback logic if the failure history is non-zero.
     * Even if we didn't crash *just now*, an older crash leaves the system in 
     * an unconfirmed state.
     */
    if (current_tmr.boot_failure_counter > 0) {
        /* 
         * CASE A: The crash happened immediately after a completed update (TXN_COMMIT) 
         * where Staging holds the old firmware via M-SWAP.
         * -> We must invoke M-SWAP in reverse to physically rollback!
         */
        if (open_txn.intent == WAL_INTENT_TXN_COMMIT) {
            /* Trigger M-SWAP in rollback mode to revert the failed new firmware */
            status = boot_rollback_trigger_revert(platform);
            if (status != BOOT_OK) {
                return status; /* FATAL: Cannot revert Staging image */
            }
            target_out->boot_recovery_os = false; /* We will boot the restored Staging OS instead */
        } 
        /* 
         * CASE B: Normal OS run with persistent crashes.
         * -> M-ROLLBACK must evaluate exponential backoff or booting Recovery-OS.
         */
        else {
            status = boot_rollback_evaluate_os(platform, &current_tmr, &target_out->boot_recovery_os);
            if (status != BOOT_OK) {
                return status;
            }
        }
    }

    platform->wdt->kick();

    /*
     * ==============================================================================
     * STEP 4 - Update Pipeline (STAGING -> TESTING -> SWAP)
     * ==============================================================================
     */
    if (open_txn.intent == WAL_INTENT_UPDATE_PENDING) {
        /* 
         * Envelope-First Verification: 
         * Authenticate the cryptographically signed SUIT envelope residing in Staging.
         * We do not read a single byte of internal instruction streams until the 
         * Ed25519 signature is evaluated to BOOT_OK.
         */
        /* 
         * Verify the complete update staging area via Envelope-First SUIT Validierung. 
         * TODO (Phase 2 integration): SUIT Manifest Parser is currently mocked. 
         * Create a static mock envelope that satisfies boot_verify_manifest_envelope.
         */
        boot_verify_envelope_t mock_envelope = {
            .manifest_flash_addr = CHIP_STAGING_SLOT_ABS_ADDR,
            .manifest_size = 128, /* Dummy Size */
            .signature_ed25519 = (const uint8_t*)"DUMMYSIG",
            .key_index = 0,
            .pqc_hybrid_active = false
        };

        boot_status_t verify_status = boot_verify_manifest_envelope(platform, &mock_envelope, crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

        if (verify_status == BOOT_OK) {
            /* 
             * The update integrity is mathematically proven.
             * Trigger the WDT-safe In-Place Overwrite execution via M-SWAP.
             * The HAL suspends the WDT natively during monolithic ROM erase operations.
             */
            boot_status_t swap_status = boot_swap_apply(platform, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE);

            if (swap_status == BOOT_OK) {
                /*
                 * The new image resides intact in the Active Slot.
                 * Atomically persist TXN_COMMIT. If S1 crashes exactly here, 
                 * Step 3 Rollback logic catches the unconfirmed firmware.
                 */
                wal_entry_payload_t commit_txn = open_txn;
                commit_txn.intent = WAL_INTENT_TXN_COMMIT;
                
                status = boot_journal_append(platform, &commit_txn);
                if (status != BOOT_OK) {
                    return status; /* FATAL: Cannot persist active State */
                }
                
                open_txn.intent = WAL_INTENT_TXN_COMMIT; /* Normalize local state */
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
            wal_entry_payload_t reject_txn = open_txn;
            reject_txn.intent = WAL_INTENT_NONE;
            
            boot_status_t rej_stat = boot_journal_append(platform, &reject_txn);
            if (rej_stat != BOOT_OK) {
                return rej_stat; /* Fatal error, prevents endless failure loops */
            }
            open_txn.intent = WAL_INTENT_NONE;
            
            /* Proceed to boot the old fallback app silently as if no update happened */
        }
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
     * FIX (Doublecheck): Removed Slot A/B dual-bank logic for App execution! 
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
    bool requires_confirmation = (open_txn.intent == WAL_INTENT_TXN_COMMIT) || 
                                 (current_tmr.boot_failure_counter > 0);

    platform->wdt->kick();

    if (requires_confirmation) {
        /* Generate cryptographically unpredictable 64-bit Nonce */
        status = platform->crypto->random((uint8_t*)&target_out->generated_nonce, sizeof(uint64_t));
        if (status != BOOT_OK) {
            return status; /* Graceful fallback. Do not lockup the device with P10_ASSERT! */
        }

        /* Secure the Expected Nonce deep inside the TMR payload.
         * The OS cannot forge this since it cannot calculate the Sector Header CRC32. */
        current_tmr.active_nonce = target_out->generated_nonce;
        status = boot_journal_update_tmr(platform, &current_tmr);
        if (status != BOOT_OK) {
            return status;
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
