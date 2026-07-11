#include "flash_model.h"
#include "hal_tape.h"
#include "invariants.h"
#include "boot_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TAPE_FILE_PATH "builds/tape.bin"
#define SIM_FLASH_FILE "builds/sim_flash.bin"

/* Globale Puffer für Fuzzing / Tests */
static uint8_t g_arena[32 * 1024];

static const uint32_t dummy_key[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444};

extern const boot_platform_t *mock_platform_get_base(flash_model_t *flash_model);

int main(void) {
    printf("==================================================\n");
    printf("   Toob-Boot K5-T3 Interruption Enumerator Runner\n");
    printf("==================================================\n\n");

    /* 1. Setup Flash Model */
    flash_model_t model;
    memset(&model, 0, sizeof(model));
    model.file_path = SIM_FLASH_FILE;
    model.total_size = 16 * 1024 * 1024;
    model.sector_size = 4096;
    model.erased_value = 0xFF;
    model.write_align = 4;
    model.fail_at_op = 0;
    model.torn_prefix = 0;

    /* Base platform mocken */
    const flash_hal_t *flash_hal = flash_model_get_hal(&model);
    
    /* Wir holen uns die Basis-Mocks von der Sandbox */
    extern const boot_platform_t *boot_platform_init(void);
    const boot_platform_t *base_plat = boot_platform_init();
    
    /* Plattform mit unserem Flash-Modell überschreiben */
    boot_platform_t test_plat;
    memcpy(&test_plat, base_plat, sizeof(boot_platform_t));
    test_plat.flash = flash_hal;

    printf("[1] Running initial recording boot...\n");
    const boot_platform_t *rec_plat = hal_tape_init(TAPE_FILE_PATH, TAPE_MODE_RECORD, &test_plat);
    
    boot_target_config_t target_cfg;
    memset(&target_cfg, 0, sizeof(target_cfg));
    
    boot_status_t status = boot_state_run(rec_plat, &target_cfg, dummy_key, g_arena, sizeof(g_arena));
    printf("    -> Initial boot completed with status: 0x%x\n", status);
    
    /* Ermittle Anzahl destruktiver Ops */
    uint32_t total_ops = model.op_counter;
    printf("    -> Recorded total of %d write/erase flash operations.\n\n", total_ops);
    hal_tape_deinit();

    if (total_ops == 0) {
        printf("No write ops recorded. Nothing to crash-test.\n");
        return 0;
    }

    printf("[2] Starting Crash Enumeration over %d operations...\n", total_ops);

    /* Kopiere Baseline Flash für Wiederherstellung */
    FILE *baseline_file = fopen("builds/sim_flash_baseline.bin", "wb");
    FILE *src_file = fopen(SIM_FLASH_FILE, "rb");
    if (baseline_file && src_file) {
        uint8_t buffer[4096];
        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
            fwrite(buffer, 1, bytes, baseline_file);
        }
        fclose(baseline_file);
        fclose(src_file);
    }

    /* 3. Crash Enumeration Loop */
    for (uint32_t i = 1; i <= total_ops; i++) {
        /* Wiederherstellen des Baseline-Flashs vor dem Crash-Lauf */
        baseline_file = fopen("builds/sim_flash_baseline.bin", "rb");
        src_file = fopen(SIM_FLASH_FILE, "wb");
        if (baseline_file && src_file) {
            uint8_t buffer[4096];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), baseline_file)) > 0) {
                fwrite(buffer, 1, bytes, src_file);
            }
            fclose(baseline_file);
            fclose(src_file);
        }

        /* Konfiguriere Crash */
        model.fail_at_op = i;
        model.torn_prefix = 0; /* Simuliere standardmäßig Abbruch vor Write */
        
        printf("    -> Simulating crash at op %d/%d...\n", i, total_ops);
        
        /* 1. Lauf (stürzt ab) */
        const boot_platform_t *replay_plat = hal_tape_init(TAPE_FILE_PATH, TAPE_MODE_REPLAY, &test_plat);
        boot_state_run(replay_plat, &target_cfg, dummy_key, g_arena, sizeof(g_arena));
        hal_tape_deinit();

        /* 2. Lauf (Reboot nach Absturz - fehlerfrei) */
        model.fail_at_op = 0;
        const boot_platform_t *reboot_plat = hal_tape_init(TAPE_FILE_PATH, TAPE_MODE_REPLAY, &test_plat);
        
        boot_target_config_t reboot_cfg;
        memset(&reboot_cfg, 0, sizeof(reboot_cfg));
        boot_status_t reboot_status = boot_state_run(reboot_plat, &reboot_cfg, dummy_key, g_arena, sizeof(g_arena));
        hal_tape_deinit();

        /* Verifiziere Invarianten */
        assert_invariants(&test_plat, &reboot_cfg, reboot_status);
    }

    /* Cleanups */
    remove("builds/sim_flash_baseline.bin");
    remove(SIM_FLASH_FILE);
    remove(TAPE_FILE_PATH);

    printf("\n==================================================\n");
    printf("   CRASH ENUMERATION COMPLETED SUCCESSFULLY!\n");
    printf("==================================================\n");
    return 0;
}
