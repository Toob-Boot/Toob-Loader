/**
 * @file boot_state.h
 * @brief Core State Machine for Lifecycle Orchestration
 *
 * Implements the IDLE, STAGING, TESTING, CONFIRMED state transitions.
 * Evaluates WAL reconstructed states and triggers Verify, Swap, and Rollback.
 */
#ifndef BOOT_STATE_H
#define BOOT_STATE_H

#include "boot_hal.h"
#include "boot_types.h"

/**
 * @brief The resolved target configuration for boot_main to execute.
 * Kapselt alle Parameter für den finalen OS Jump, sodass hal_deinit()
 * zuvor in boot_main() sauber gerufen werden kann.
 */
typedef struct {
    uint32_t active_entry_point;  /**< Physikalischer Flash-Offset des OS Vector Tables */
    uint32_t active_image_size;   /**< Für XIP Bounds Verifikation via Stage 0 / MPU */
    uint32_t net_search_accum_ms; /**< Extrahierter Netzwerk-Suchzeit Akkumulator */
    uint64_t generated_nonce;     /**< Dem OS bereitzustellende Anti-Replay Nonce */
    bool boot_recovery_os;        /**< Wahr, wenn das Recovery-OS (Fallback) gebootet wird */
} boot_target_config_t;

/**
 * @brief Main engine invocation. Evaluates WAL, executes Updates/Rollbacks 
 *        and returns the stable boot configuration to boot_main.c.
 *
 * @param platform The initialized hardware platform structs.
 * @param target_out Populated with the entry_point and nonce for the OS jump.
 * @return BOOT_OK on stable resolution, BOOT_ERR_* otherwise (which triggers panic/rescue).
 */
boot_status_t boot_state_run(const boot_platform_t *platform, boot_target_config_t *target_out);

/*
 * ==============================================================================
 * TODO (Phase 3) - Core Implementation Requirements (to be fulfilled in boot_state.c):
 * ==============================================================================
 * 1. RECONSTRUCTION:
 *    Read WAL via boot_journal_reconstruct_txn() & get TMR states (primary_slot_id, 
 *    boot_failure_counter).
 *
 * 2. OS-CONFIRMATION (CONFIRMED):
 *    If WAL contains WAL_INTENT_CONFIRM_COMMIT:
 *    - Update TMR: Reset boot_failure_counter = 0.
 *
 * 3. PIPELINE STAGE 1 (STAGING -> TESTING):
 *    If WAL contains WAL_INTENT_UPDATE_PENDING:
 *    - Trigger M-VERIFY (Envelope-First: Verify SUIT Signature over Staging slot,
 *      then verify Merkle-Chunks).
 *    - If valid, advance to M-SWAP. If invalid, reject update and return to IDLE.
 *
 * 4. PIPELINE STAGE 2 (SWAP & COMMIT):
 *    - Trigger M-SWAP to execute the WDT-safe In-Place overwrite.
 *    - Append WAL_INTENT_TXN_COMMIT.
 *
 * 5. RECOVERY/FAILURE HANDLING (ROLLBACK):
 *    - If boot_failure_counter > 0 and no CONFIRM_COMMIT received:
 *    - Escalate to M-ROLLBACK to evaluate Epochs / Fail-Counts.
 *    - Includes Support for edge_unattended_mode (Exponential Sleep Backoff).
 *
 * 6. FINAL HALT (HANDOFF):
 *    - Read toob_image_header_t (TOOB_MAGIC_HEADER) from chosen app_slot.
 *    - Generate 64-Bit expected_nonce via platform->crypto->random().
 *    - Append WAL_INTENT_NONCE_INTENT into the Journal.
 *    - Populate target_out struct for boot_main() to perform hal_deinit() and jump.
 * ==============================================================================
 */

#endif /* BOOT_STATE_H */
