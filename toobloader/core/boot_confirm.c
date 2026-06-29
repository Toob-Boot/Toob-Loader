/*
 * Toob-Boot Core File: boot_confirm.c
 * Relevant Spec-Dateien:
 * - docs/libtoob_api.md (Bestätigungs-Interaktion mit dem OS)
 * - docs/hals.md (Confirm HAL)
 */

#include "boot_types.h"
#include "boot_hal.h"
#include "boot_confirm.h"
#include "boot_fih.h"

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

    /* P7b: Die Nonce-Prüfung (check_ok) ist das primäre Gate.
     * Eine valide Nonce beweist, dass das OS bis zum Confirm-Punkt lief.
     * Reset-Reason ist nur korroborierende Information:
     * - Nonce gültig → Confirm gilt, unabhängig vom Reset-Reason.
     *   Ein BROWNOUT/WDT *nach* erfolgreichem Confirm darf nicht rückgängig machen.
     * - Nonce ungültig + WDT/FAULT → definitiv kein Confirm (OS hat nie confirmed). */

    /* 4. Glitch-Defense Double-Check Pattern (wie in boot_verify.c) */
    BOOT_SECURE_REQUIRE(is_ok, {
        platform->wdt->kick();
        boot_status_t clear_stat = platform->confirm->clear();
        platform->wdt->kick();
        
        if (clear_stat != BOOT_OK) {
            return clear_stat; /* Hardware Failure durchschleifen */
        }
        return BOOT_ERR_VERIFY;
    });

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
