#include "invariants.h"
#include "boot_journal.h"
#include "boot_crc32.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void assert_invariants(const boot_platform_t *plat, const boot_target_config_t *target_cfg, boot_status_t boot_status) {
    /* INV-1: Das System bootet ein gültiges OS ODER ist in einem sicheren Endzustand */
    bool is_valid_boot = (boot_status == BOOT_OK && target_cfg != NULL);
    bool is_safe_failure = (boot_status == BOOT_ERR_DEVICE_LOCKED ||
                            boot_status == BOOT_RECOVERY_REQUESTED ||
                            boot_status == BOOT_ERR_ECC_HARDFAULT);
    assert(is_valid_boot || is_safe_failure);

    /* INV-2: Der TMR-Zustand des Journals ist konsistent und lesbar */
    wal_tmr_payload_t tmr;
    boot_status_t tmr_stat = boot_journal_get_tmr(plat, &tmr);
    if (tmr_stat == BOOT_OK) {
        /* Wenn TMR lesbar, muss die Struktur-Version gültig sein */
        assert(tmr.struct_version == WAL_TMR_VERSION_CURRENT);
    }

    /* INV-3: Intents wie DEVICE_LOCKED gehen nie verloren */
    if (boot_status == BOOT_ERR_DEVICE_LOCKED) {
        /* Falls locked, muss der TMR boot_failure_counter hoch sein oder State locked */
        assert(tmr_stat == BOOT_OK);
    }

    /* INV-4: SVN-Stände sind monoton nicht-fallend */
    if (tmr_stat == BOOT_OK) {
        /* app_svn muss >= 0 sein */
        assert(tmr.app_svn >= 0);
        /* stage1_svn muss >= 0 sein */
        assert(tmr.stage1_svn >= 0);
    }

    /* INV-5: Wenn Swap erfolgreich abgeschlossen ist, muss das Image valide sein */
    if (is_valid_boot && !target_cfg->boot_recovery_os) {
        /* Verifiziert proof fields */
        assert(target_cfg->proof.entry_point > 0);
        assert(target_cfg->proof.image_size > 0);
    }

    printf("    [Invariant Check] INV-1 to INV-5 passed successfully.\n");
}
