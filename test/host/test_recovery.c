/**
 * @file test_recovery.c
 * @brief Integration Test: Roach-Motel Recovery exhaustion verification.
 */

#include "flash_model.h"
#include "hal_tape.h"
#include "invariants.h"
#include "boot_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define SIM_FLASH_FILE "builds/sim_recovery_flash.bin"

static uint8_t g_arena[32 * 1024];
static const uint32_t dummy_key[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444};

int main(void) {
    printf("==================================================\n");
    printf("   Recovery OS Integration & Roach-Motel Test\n");
    printf("==================================================\n\n");

    /* 1. Setup Flash Model */
    flash_model_t model;
    memset(&model, 0, sizeof(model));
    model.file_path = SIM_FLASH_FILE;
    model.total_size = 16 * 1024 * 1024;
    model.sector_size = 4096;
    model.erased_value = 0xFF;
    model.write_align = 4;

    const flash_hal_t *flash_hal = flash_model_get_hal(&model);
    
    extern const boot_platform_t *boot_platform_init(void);
    const boot_platform_t *base_plat = boot_platform_init();
    
    boot_platform_t test_plat;
    memcpy(&test_plat, base_plat, sizeof(boot_platform_t));
    test_plat.flash = flash_hal;

    boot_target_config_t target_cfg;
    memset(&target_cfg, 0, sizeof(target_cfg));

    /* Populate initial healthy TMR in flash */
    boot_status_t status = boot_state_run(&test_plat, &target_cfg, dummy_key, g_arena, sizeof(g_arena));
    printf("Initial boot status: 0x%x, boot_recovery: %d\n", status, target_cfg.boot_recovery_os);

    /* Get current TMR */
    wal_tmr_payload_t tmr;
    assert(boot_journal_get_tmr(&test_plat, &tmr) == BOOT_OK);
    printf("Initial boot_failure_counter: %d, recovery_failure_counter: %d\n", 
           tmr.boot_failure_counter, tmr.recovery_failure_counter);

    /* Let's write a mock test to exhaust both counters and verify the outcome */
    printf("\nExhausting counters directly in TMR...\n");
    assert(boot_journal_get_tmr(&test_plat, &tmr) == BOOT_OK);
    tmr.boot_failure_counter = 4; // Exceeds BOOT_CONFIG_MAX_RETRIES (3)
    tmr.recovery_failure_counter = 4; // Exceeds BOOT_CONFIG_MAX_RECOVERY_RETRIES (3)
    assert(boot_journal_update_tmr(&test_plat, &tmr) == BOOT_OK);

    /* Trigger reboot run. It should result in BOOT_RECOVERY_REQUESTED (Serial Rescue) and NOT sleep */
    memset(&target_cfg, 0, sizeof(target_cfg));
    boot_status_t final_status = boot_state_run(&test_plat, &target_cfg, dummy_key, g_arena, sizeof(g_arena));
    
    printf("Final boot status: 0x%x (expected: 0x%x)\n", final_status, BOOT_RECOVERY_REQUESTED);
    assert(final_status == BOOT_RECOVERY_REQUESTED);

    /* Verify WAL has no Sleep Intent (which would mean we went to sleep) */
    wal_entry_payload_t open_txn;
    boot_secure_zeroize(&open_txn, sizeof(open_txn));
    uint32_t dummy_accum = 0;
    uint32_t dummy_resume = 0;
    assert(boot_journal_reconstruct_txn(&test_plat, &open_txn, &dummy_accum, &dummy_resume) == BOOT_OK);
    printf("Active intent in WAL: 0x%x (expected: 0x0/WAL_INTENT_NONE)\n", open_txn.intent);
    assert(open_txn.intent != WAL_INTENT_SLEEP_BACKOFF);

    remove(SIM_FLASH_FILE);
    printf("\n==================================================\n");
    printf("   ROACH-MOTEL RECOVERY INVARIANT VERIFIED!\n");
    printf("==================================================\n");
    return 0;
}
