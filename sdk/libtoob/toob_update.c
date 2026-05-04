/**
 * ==============================================================================
 * Toob-Boot libtoob: Update Registration Implementation (toob_update.c)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (toob_set_next_update signature and WAL interaction requirements)
 * - docs/concept_fusion.md (WAL transaction architecture, TXN_UPDATE_READY state)
 * - docs/structure_plan.md (GAP-C03 WAL union alignment constraints for bare C)
 * - docs/testing_requirements.md (Atomic operations over untrusted OS hooks)
 */

#include "libtoob.h"
#include "toob_internal.h"
#include "libtoob_config_sandbox.h" 
#include <string.h>

toob_status_t toob_set_next_update(uint32_t manifest_flash_addr) {
    /* Schritt 1: Basic Sanity-Checks für die Flash-Adresse (0 ist ein valider Memory Space!) */
    if (manifest_flash_addr == 0xFFFFFFFF || (manifest_flash_addr % CHIP_FLASH_WRITE_ALIGN) != 0) {
        return TOOB_ERR_INVALID_ARG;
    }
    
    /* Schritt 2: Frame WAL Payload assembeln */
    toob_wal_entry_payload_t intent;
    memset(&intent, 0, sizeof(toob_wal_entry_payload_t));
    
    intent.magic = TOOB_WAL_ENTRY_MAGIC;
    intent.intent = TOOB_WAL_INTENT_UPDATE_PENDING;
    
    /* Der Bootloader wertet fuer UPDATE_PENDING das offset aus */
    intent.offset = manifest_flash_addr;
    
    /* Schritt 3: Naive Delegation an den Shared Appender */
    return toob_wal_naive_append(&intent);
}
