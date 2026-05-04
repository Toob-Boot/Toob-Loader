/*
 * Toob-Boot Core File: boot_confirm.c
 * Relevant Spec-Dateien:
 * - docs/libtoob_api.md (Bestätigungs-Interaktion mit dem OS)
 * - docs/hals.md (Confirm HAL)
 */

#include "boot_types.h"
#include "boot_hal.h"
#include "boot_confirm.h"

boot_status_t boot_confirm_evaluate(const boot_platform_t* platform, uint64_t expected_nonce) {
    if (platform == NULL || platform->clock == NULL || platform->confirm == NULL || platform->wdt == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }

    if (platform->clock->get_reset_reason == NULL || 
        platform->confirm->check_ok == NULL || 
        platform->confirm->clear == NULL || 
        platform->wdt->kick == NULL) {
        return BOOT_ERR_NOT_SUPPORTED;
    }

    /* 1. Lese den hardware-spezifischen Reset-Reason aus */
    reset_reason_t reason = platform->clock->get_reset_reason();

    /* 2. Prüfe die Nonce (Ist das OS "Tentative" oder "Committed"?) mit WDT Kicks */
    platform->wdt->kick();
    bool is_ok = platform->confirm->check_ok(expected_nonce);
    platform->wdt->kick();

    /* 3. Whitelist Abwehr: Nur absolut unschädliche externe Resets dürfen als "Sicher" gelten.
     * ACHTUNG (BROWNOUT): Verliert der Akku Monate nach dem Update seine Spannung, löst dies
     * einen BROWNOUT-Reset aus. Dies indiziert KEINESFALLS ein crashendes OS! Passierte der
     * Brownout WÄHREND dem OS-Handoff, liefert check_ok() ohnehin false. Daher MUSS der
     * Brownout auf der Whitelist stehen, sonst rollt jedes entladene Gerät fälschlich zurück! */
    if (reason != RESET_REASON_POWER_ON && 
        reason != RESET_REASON_PIN_RESET && 
        reason != RESET_REASON_BROWNOUT) {
        is_ok = false;
    }

    /* 4. Glitch-Defense Double-Check Pattern (wie in boot_verify.c) */
    volatile uint32_t secure_flag_1 = 0;
    volatile uint32_t secure_flag_2 = 0;

    if (is_ok) {
        secure_flag_1 = BOOT_OK; 
    }

    /* Branch Delay Injection gegen Voltage Faults (Instruction Skips) */
    BOOT_GLITCH_DELAY();

    if (secure_flag_1 == BOOT_OK && is_ok) {
        secure_flag_2 = BOOT_OK;
    }

    /* Wenn das Update fehlschlägt (Glitch entdeckt oder regulär false) -> Lösche Flag + Rollback */
    if (secure_flag_1 != secure_flag_2 || secure_flag_2 != BOOT_OK) {
        platform->wdt->kick();
        boot_status_t clear_stat = platform->confirm->clear();
        platform->wdt->kick();
        
        if (clear_stat != BOOT_OK) {
            return clear_stat; /* Hardware Failure durchschleifen */
        }
        return BOOT_ERR_VERIFY;
    }

    return BOOT_OK;
}

boot_status_t boot_confirm_clear(const boot_platform_t* platform) {
    if (platform == NULL || platform->confirm == NULL || platform->wdt == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }

    if (platform->confirm->clear == NULL || platform->wdt->kick == NULL) {
        return BOOT_ERR_NOT_SUPPORTED;
    }

    platform->wdt->kick();
    boot_status_t stat = platform->confirm->clear();
    platform->wdt->kick();

    return stat;
}
