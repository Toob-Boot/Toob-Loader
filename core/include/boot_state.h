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
    bool is_tentative_boot;       /**< Exported True if the boot is a trial (TXN_COMMIT) and unconfirmed */
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
 * STATE MACHINE LIFECYCLE (P10 Hardened)
 * ==============================================================================
 * Die boot_state_run() Orchestrierung führt folgende Phasen strikt sequentiell aus:
 *
 * 1. RECONSTRUCTION & ABORT-HEALING:
 *    - Fährt das WAL-Window hoch (boot_journal_init).
 *    - Liest die hochsichere TMR-Payload inkl. boot_failure_counter.
 *    - Heilt unvollständige Flash-Erase Brownouts.
 * 
 * 2. TRANSACTION CONFIRMATION:
 *    - Handelt CONFIRM_COMMIT (vom OS) und RECOVERY_RESOLVED (vom SOS-Fallback).
 *    - Validiert die kryptografische active_nonce aus dem TMR gegen Replay-Angriffe.
 *    - Wenn valid: Setzt TMR Fail-Counter deterministisch auf 0 zurück.
 * 
 * 3. FALLBACK CASCADES (M-ROLLBACK):
 *    - Verfolgt System-Crashes (WDT, HardFault).
 *    - Bei TXN_COMMIT Crashes → Triggered In-Place Reverse-Swap (Hard Rollback).
 *    - Bei wiederholten Crashes → Flieht in das Recovery-OS oder triggert Backoff-Sleep.
 * 
 * 4. UPDATE EXECUTION (M-VERIFY & M-SWAP):
 *    - Verifiziert Updates ENVELOPE-FIRST (Ed25519 Sign-then-Hash) gegen Voltage-Glitches.
 *    - Triggert boot_swap_apply() für In-Place Sector Overwrites mit WDT-Suspension.
 *    - Persistiert TXN_COMMIT atomar ins WAL.
 * 
 * 5. HANDOFF PREPARATION:
 *    - Ermittelt den Startvektor (Vector Table Adresse).
 *    - Generiert eine neue krypografisch starke 64-Bit Nonce für den OS .noinit Start.
 *    - Verankert die neue Nonce sicher im physikalisch isolierten TMR.
 * ==============================================================================
 */

#endif /* BOOT_STATE_H */
