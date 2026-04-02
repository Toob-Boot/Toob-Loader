/*
 * Toob-Boot Core File: boot_panic.c
 * Relevant Spec-Dateien:
 * - docs/stage_1_5_spec.md (Serial Rescue, SOS, Exponential Penalty)
 * - docs/testing_requirements.md
 */

#include "boot_panic.h"
#include "boot_delay.h"

static void enter_sos_loop(const boot_platform_t *platform) {
    // Endlosschleife ohne Serial Rescue (Fallback)
    while (1) {
        if (platform->wdt) {
            platform->wdt->kick();
        }
        boot_delay_with_wdt(platform, 500); 
    }
}

void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    (void)reason; // Momentan nicht ausgegeben, da wir kein snprintf haben

    if (!platform) {
        while (1) {} // Hard Fault Fallback
    }

    if (!platform->console) {
        enter_sos_loop(platform);
    }

    // GAP-12 / GAP-C06: Serial Rescue Naked COBS Flow
    uint32_t failed_auth_attempts = 0;

    platform->console->putchar('P');
    platform->console->putchar('N');
    platform->console->putchar('C');
    platform->console->flush();

    while (1) {
        if (platform->wdt) {
            platform->wdt->kick();
        }
        
        // Blockierendes Lesen auf COBS Start/End Byte (TODO: Implementiere COBS Decoder Core)
        int c = platform->console->getchar(100);
        
        if (c >= 0) {
            // Mock: Auth ist fehlgeschlagen (TODO: Ed25519 Verify anbinden)
            failed_auth_attempts++;
            
            // P10 Compliance: Bounds Check auf failed_auth_attempts (Max 10 Shifts = ~102 Sekunden)
            uint32_t shifts = failed_auth_attempts;
            if (shifts > 10) {
                shifts = 10;
            }
            
            uint32_t penalty_ms = (1U << shifts) * 100U;
            
            if (platform->soc && platform->soc->enter_low_power) {
                platform->soc->enter_low_power(penalty_ms);
            } else {
                boot_delay_with_wdt(platform, penalty_ms);
            }
        }
    }
}
