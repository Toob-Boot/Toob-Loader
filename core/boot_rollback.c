/*
 * Toob-Boot Core File: boot_rollback.c
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md
 * - docs/testing_requirements.md
 */
#include <string.h>
#include "boot_rollback.h"
#include "boot_panic.h"
#include "boot_config_mock.h"
#include "boot_swap.h"

_Static_assert(BOOT_CONFIG_MAX_RETRIES > 0, "Invalid Configuration: Target Retries must be positive");
_Static_assert((BOOT_CONFIG_BACKOFF_BASE_S * 24ULL) <= UINT32_MAX, "Exponential Backoff Configuration will overflow");

/*
 * ============================================================================
 * BLOCK 1: Hybrid SVN Verification
 * ============================================================================
 */
boot_status_t boot_rollback_verify_svn(const boot_platform_t *platform, uint32_t manifest_svn, bool is_recovery_os) {
    if (!platform || !platform->crypto) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* 1. Lese persistierte SVN Werte (app_svn oder recovery_svn) aus WAL TMR Payload */
    wal_tmr_payload_t tmr = {0};
    boot_status_t status = boot_journal_get_tmr(platform, &tmr);
    
    /* Wenn kein Journal existiert (Initial Flash/Blank Device), nehmen wir SVN 0 als Baseline an.
     * BOOT_ERR_NOT_FOUND (z.B. nach Factory Reset) maskieren wir ebenfalls absichtlich.
     */
    if (status != BOOT_OK && status != BOOT_ERR_STATE && status != BOOT_ERR_NOT_FOUND) {
        return status;
    }

    uint32_t persisted_wal_svn = is_recovery_os ? tmr.svn_recovery_counter : tmr.app_svn; /* Hinweis: app_svn existiert (wurde in Phase 3.3 in boot_journal.h aufgenommen) */

    /* 2. Hole eFuse Epoch als absolutes Hardware-Sicherheitsnetz gegen CVE-Downgrades.
     * Architektur-Notiz: Auf Chips ohne Monotonic Counter in eFuse wird diese 
     * Funktion übersprungen. Der Downgrade-Schutz verlässt sich dann rein auf den 
     * kryptografisch signierten TMR Payload im Write-Ahead Log. */
    uint32_t efuse_epoch = 0;
    if (platform->crypto->read_monotonic_counter) {
        if (platform->wdt) platform->wdt->kick(); /* Kick vor langsamem OTP Hardware-Read */
        
        boot_status_t efuse_status = platform->crypto->read_monotonic_counter(&efuse_epoch);
        if (efuse_status != BOOT_OK && efuse_status != BOOT_ERR_NOT_SUPPORTED) {
            return efuse_status; /* Hardware fault beim Lesen der Sicherheits-Fuses */
        }
    }

    /* 3. Verweigere Downgrades rigoros gegen BEIDE Kriterien. 
          manifest_svn < persisted bedeutet BOOT_ERR_DOWNGRADE. 
       4. Erlaube identische Versionen: Re-Flashes der gleichen Version müssen für Reparaturen durchkommen.
       5. Isoliere die Evaluierung: is_recovery_os schaltet transparent zwischen app_svn und svn_recovery_counter um. */
    if (manifest_svn < persisted_wal_svn) {
        return BOOT_ERR_DOWNGRADE;
    }
    
    if (manifest_svn < efuse_epoch) {
        return BOOT_ERR_DOWNGRADE;
    }

    return BOOT_OK;
}

/*
 * ============================================================================
 * BLOCK 2: Crash Cascade & Edge Mitigation
 * ============================================================================
 */
boot_status_t boot_rollback_evaluate_os(const boot_platform_t *platform, const wal_tmr_payload_t *tmr, bool *boot_recovery_os_out) {
    if (!platform || !tmr || !boot_recovery_os_out) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* Hinweis (Doublecheck): Der Mechanische Anti-Softbrick-Override (Recovery-Pin) 
     * wird bereits in boot_main.c (Block 2.5) hardwarenah debounced und abgefangen.
     * Eine doppelte Evaluation hier wäre redundant und fehleranfällig (Race Condition).
     */

    uint32_t counter = tmr->boot_failure_counter;

    /* CASE 1 (Normal Reboot): OS Slot A booten */
    if (counter <= BOOT_CONFIG_MAX_RETRIES) {
        *boot_recovery_os_out = false;
        return BOOT_OK;
    }

    /* CASE 2 (Recovery Fallback): Boot Recovery-OS */
    if (counter <= (BOOT_CONFIG_MAX_RETRIES + BOOT_CONFIG_MAX_RECOVERY_RETRIES)) {
        *boot_recovery_os_out = true;
        return BOOT_OK;
    }

    /* CASE 3 (Zero-Day Brick / Double Failure) */
#if BOOT_CONFIG_EDGE_UNATTENDED_MODE
    /* Unattended Mode (TRUE): Triggere deep-sleep Backoff (1h, 4h, 12h, 24h Kaskade) via HAL. */
    if (!platform->soc || !platform->soc->enter_low_power) {
        /* Fallback, falls Hardware den Low-Power Sleep nicht unterstützt */
        boot_panic(platform, BOOT_RECOVERY_REQUESTED);
        return BOOT_RECOVERY_REQUESTED;
    }

    /* Berechne Exponential Backoff basierend auf dem Überlauf des Failure Counters */
    uint32_t excess_fails = counter - (BOOT_CONFIG_MAX_RETRIES + BOOT_CONFIG_MAX_RECOVERY_RETRIES) - 1;
    uint32_t wakeup_s = BOOT_CONFIG_BACKOFF_BASE_S; /* Default: 1h */
    
    if (excess_fails == 1) {
        wakeup_s *= 4;           /* 4h */
    } else if (excess_fails == 2) {
        wakeup_s *= 12;          /* 12h */
    } else if (excess_fails >= 3) {
        wakeup_s *= 24;          /* 24h MAX-CAP */
    }

    /* TMR-State/Intent muss abgesichert werden BEVOR wir den SoC physikalisch schlafen legen! */
    wal_entry_payload_t sleep_intent;
    memset(&sleep_intent, 0, sizeof(sleep_intent));
    sleep_intent.magic = WAL_ENTRY_MAGIC;
    sleep_intent.intent = WAL_INTENT_SLEEP_BACKOFF;
    sleep_intent.offset = wakeup_s;
    
    boot_status_t log_status = boot_journal_append(platform, &sleep_intent);
    if (log_status != BOOT_OK) {
        /* Falls WAL voll/defekt, verhindern wir den Akku-Tod durch endloses Schlafen-und-Wiederkehren 
         * indem wir gezielt in Code-Halt / Panic stoppen. */
        boot_panic(platform, BOOT_ERR_WAL_FULL);
        return BOOT_RECOVERY_REQUESTED;
    }
    
    /* Friert die CPU ein und wacht in "wakeup_s" Sekunden durch einen Reset wieder auf. */
    platform->soc->enter_low_power(wakeup_s);
    
    /* Should never be reached. Falls hardware enter_low_power fehlschlägt, WDT Resett provoziert */
    while(1) { }
#else
    /* Attended Mode (FALSE): Bootloader blockiert. Springe in die Schicht 4a Serial Rescue */
    boot_panic(platform, BOOT_RECOVERY_REQUESTED);
    return BOOT_RECOVERY_REQUESTED;
#endif

    return BOOT_OK; /* Unreachable, silences missing return compiler warnings */
}

/*
 * ============================================================================
 * BLOCK 3: Reverse Swap Orchestration
 * ============================================================================
 */
boot_status_t boot_rollback_trigger_revert(const boot_platform_t *platform) {
    if (!platform || !platform->flash) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* 1. Lese das Backup aus dem Staging-Slot (Source) */
    toob_image_header_t backup_header;
    boot_status_t status = platform->flash->read(CHIP_STAGING_SLOT_ABS_ADDR, (uint8_t*)&backup_header, sizeof(backup_header));
    if (status != BOOT_OK) {
        return status;
    }

    /* Validiere, dass der Staging Slot tatsächlich ein intaktes Backup hält */
    if (backup_header.magic != TOOB_MAGIC_HEADER || backup_header.image_size == 0 || backup_header.image_size == 0xFFFFFFFF) {
        return BOOT_ERR_NOT_FOUND;
    }

    /* Bounds-Check: Verhindere böswilligen Flash-Overflow durch gehackte Längenangaben im Header (CVE-Prevention) */
    if (backup_header.image_size > CHIP_APP_SLOT_SIZE) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    
    if ((UINT32_MAX - CHIP_STAGING_SLOT_ABS_ADDR < backup_header.image_size) ||
        (UINT32_MAX - CHIP_APP_SLOT_ABS_ADDR < backup_header.image_size)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }

    /* 2. GAP: 1-Way Idempotent Backup Revert! 
     * Der App Slot ist gecrasht und somit Müll. Wir kopieren stur von Staging -> App.
     * Eine Tearing-Danger existiert nicht, da Staging read-only bleibt! Ein Reboot 
     * fängt durch das WAL_INTENT_TXN_ROLLBACK_PENDING einfach von vorne an.
     */
    wal_entry_payload_t pending_intent;
    memset(&pending_intent, 0, sizeof(pending_intent));
    pending_intent.magic = WAL_ENTRY_MAGIC;
    pending_intent.intent = WAL_INTENT_TXN_ROLLBACK_PENDING;
    status = boot_journal_append(platform, &pending_intent);
    if (status != BOOT_OK) return status;

    uint32_t current_offset = 0;
    static uint8_t copy_buf[CHIP_FLASH_MAX_SECTOR_SIZE];
    
    while (current_offset < backup_header.image_size) {
        platform->wdt->kick();
        
        uint32_t src = CHIP_STAGING_SLOT_ABS_ADDR + current_offset;
        uint32_t dst = CHIP_APP_SLOT_ABS_ADDR + current_offset;
        
        size_t dst_sec_size = 0;
        status = platform->flash->get_sector_size(dst, &dst_sec_size);
        if (status != BOOT_OK || dst_sec_size == 0 || dst_sec_size > CHIP_FLASH_MAX_SECTOR_SIZE) {
            return BOOT_ERR_FLASH_HW;
        }

        /* Lese Source sicher */
        status = platform->flash->read(src, copy_buf, dst_sec_size);
        if (status != BOOT_OK) return status;
        
        /* Überschreibe Dest */
        status = boot_swap_erase_safe(platform, dst, dst_sec_size);
        if (status != BOOT_OK) return status;
        
        status = platform->flash->write(dst, copy_buf, dst_sec_size);
        if (status != BOOT_OK) return status;
        
        current_offset += dst_sec_size;
    }

    /* TODO (GAP-28): Multi-Core Atomic Groups & Secondary Boot Delegation (concept_fusion.md Z.28)
     * Aktuell rollt nur der Main-Core zurück! Für Architekturen mit Radio-Cores (z.B. nRF5340)  
     * müssen beim Fehlschlag ALLE assoziierten Images in einer transaktionalen Kette abgerollt werden.
     * Zukünftige Implementierung: TXN_ROLLBACK_BEGIN loggen -> Radio-Cores swappen -> App swappen -> TXN_ROLLBACK loggen.
     */

    /* 5. Isolierter Rollback-Intent, damit beim Reboot der Boot_Failure_Counter richtig agiert */
    wal_entry_payload_t revert_intent;
    memset(&revert_intent, 0, sizeof(revert_intent));
    revert_intent.magic = WAL_ENTRY_MAGIC;
    revert_intent.intent = WAL_INTENT_TXN_ROLLBACK;
    
    status = boot_journal_append(platform, &revert_intent);
    if (status != BOOT_OK) {
        return status;
    }
    
    return BOOT_OK;
}
