/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: RTC RAM Implementation
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS & GAPS:
 * 
 * 1. docs/libtoob_api.md & docs/concept_fusion.md
 *    - TENTATIVE Flag & 2-Way Handshake: Simuliert das RTC-RAM (oder Backup-Register).
 *    - Das Flag darf bei Watchdog-Resets (Crash des OS) NICHT gelöscht werden, 
 *      sondern muss bis zum erneuten Bootloader-Start überleben.
 *    - Deshalb nutzen wir eine Datei `rtc_sim.bin` - C-Variablen würden bei abort() sterben.
 */

#include "mock_rtc_ram.h"
#include "chip_fault_inject.h"
#include <stdio.h>
#include <stdlib.h>

static FILE *rtc_file = NULL;

static boot_status_t mock_rtc_init(void) {
    /* L1-Isolation: Konfiguration wird zentral von chip_fault_inject bezogen */
    rtc_file = fopen(g_fault_config.rtc_sim_file, "rb+");
    if (!rtc_file) {
        rtc_file = fopen(g_fault_config.rtc_sim_file, "wb+");
        if (!rtc_file) return BOOT_ERR_STATE;
        
        uint64_t initial_garbage = 0;
        fwrite(&initial_garbage, sizeof(uint64_t), 1, rtc_file);
        fflush(rtc_file);
    }
    return BOOT_OK;
}

static void mock_rtc_deinit(void) {
    if (rtc_file) {
        fclose(rtc_file);
        rtc_file = NULL;
    }
}

static bool mock_rtc_check_ok(uint64_t expected_nonce) {
    if (!rtc_file) return false;
    
    if (fseek(rtc_file, 0, SEEK_SET) != 0) return false;
    
    uint64_t stored_nonce = 0;
    if (fread(&stored_nonce, sizeof(uint64_t), 1, rtc_file) != 1) {
        return false;
    }
    
    return stored_nonce == expected_nonce;
}

static boot_status_t mock_rtc_clear(void) {
    if (!rtc_file) return BOOT_ERR_STATE;
    
    /* P10 Zero-Memory Pattern: 
     * Wir löschen die Datei NICHT via remove() (kein dynamisches Filesystem Sync-Racing),
     * sondern überschreiben deterministisch exakt die Nonce auf 0x00. */
    uint64_t zeroes = 0;
    
    if (fseek(rtc_file, 0, SEEK_SET) != 0) return BOOT_ERR_STATE; 
    
    if (fwrite(&zeroes, sizeof(uint64_t), 1, rtc_file) != 1) return BOOT_ERR_STATE;
    
    fflush(rtc_file);
    return BOOT_OK;
}

/* --- Test-Runner Injection Utilities --- */

void mock_rtc_ram_reset_to_factory(void) {
    if (rtc_file) {
        fclose(rtc_file);
        rtc_file = NULL;
    }
    if (g_fault_config.rtc_sim_file) {
        remove(g_fault_config.rtc_sim_file);
    } else {
        remove("rtc_sim.bin");
    }
}

void mock_rtc_ram_set_nonce(uint64_t nonce) {
    if (!rtc_file) {
        mock_rtc_init(); /* Zwanghaftes Bootstrapping für Test-Injects vor boot_platform_init() */
    }
    if (rtc_file) {
        fseek(rtc_file, 0, SEEK_SET);
        fwrite(&nonce, sizeof(uint64_t), 1, rtc_file);
        fflush(rtc_file);
    }
}

void mock_rtc_ram_force_corruption(void) {
    if (!rtc_file) mock_rtc_init();
    if (rtc_file) {
        fseek(rtc_file, 0, SEEK_SET);
        uint64_t garbage = 0xDEADBEEFCAFEBABE;
        fwrite(&garbage, sizeof(uint64_t), 1, rtc_file);
        fflush(rtc_file);
    }
}

/* --- Trait Export --- */

const confirm_hal_t sandbox_confirm_hal = {
    .abi_version = 0x01000000,
    .init = mock_rtc_init,
    .deinit = mock_rtc_deinit,
    .check_ok = mock_rtc_check_ok,
    .clear = mock_rtc_clear
};
