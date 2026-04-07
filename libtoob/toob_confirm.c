/**
 * ==============================================================================
 * Toob-Boot libtoob: Update Confirmation Implementation (toob_confirm.c)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (toob_confirm_boot API behavior and COMMITTED flag specification)
 * - docs/concept_fusion.md (TENTATIVE -> COMMITTED state transition logic)
 * - docs/hals.md (Confirm abstracting - RTC RAM vs. WAL Append)
 * - docs/structure_plan.md (Zero-dependency policy: No access to boot_journal.h)
 */

#include "libtoob.h"
#include "toob_internal.h"
#include "libtoob_config_sandbox.h" 
#include <string.h>

#if TOOB_MOCK_CONFIRM_BACKEND == TOOB_MOCK_CONFIRM_BACKEND_RTC
/* Instanziiert den x86 Dummy-Pointer zur Laufzeit, um Segfaults auf dem OS-Host zu verhindern */
uint64_t mock_rtc_ram = 0;
#endif

toob_status_t toob_confirm_boot(void) {
    /* Schritt 1: Hole verifizierte Nonce über Handoff-API (Anti-Replay) 
     * 
     * [SECURITY CONTRACT]: Libtoob fungiert hier physikalisch nur als dumme 
     * Transport-Schicht! Die tatsaechliche kryptographische Anti-Replay Sicherheit 
     * wird unbarmherzig vom Bootloader selbst auf S1 durchgesetzt (siehe boot_state.c). 
     * Wenn das OS hier eine falsche Nonce einreicht, verwirft sie der Bootloader stillschweigend.
     *
     * Arch-Note: On MMU-less boundaries, active RCE payloads can always hijack 
     * the Nonce. However, accidental OS-induced heap overflows corrupting the 
     * .noinit RAM are instantly deflected by the internal CRC-32 verification here.
     */
    toob_handoff_t handoff;
    toob_status_t status = toob_get_handoff(&handoff);
    if (status != TOOB_OK) {
        return status;
    }

#ifdef ADDR_CONFIRM_RTC_RAM
    /* Pfad A: Direkter Write bei Hardware mit Backup-Resigtern/RTC 
     * 
     * Arch-Note (Zero-Dependency): Wir schreiben absichtlich direkt an die Adresse.
     * Im Bootloader abstrahiert dies ggf. die `confirm_hal_t`. Da Libtoob ohne Vendor-C-Bloat
     * ausliefern muss, MUSS das Tooling (Manifest-Compiler) zwingend sicherstellen, dass die 
     * in `libtoob_config.h` als `ADDR_CONFIRM_RTC_RAM` generierte Register-Adresse absolut 1:1
     * exakt auf denselben Adressraum greift wie der Vendor-HAL drüben im S1-Binary!
     */
    /* Zwingendes Volatile-Casting, um C-Optimizer (z.B. GCC -O3) beim Hardware-Write zu blockieren! */
    volatile uint64_t* rtc_ptr = (volatile uint64_t*) ADDR_CONFIRM_RTC_RAM;
    *rtc_ptr = handoff.boot_nonce;
    return TOOB_OK;
#else
    /* Pfad B: Naive WAL Append */
    toob_wal_entry_payload_t intent;
    memset(&intent, 0, sizeof(toob_wal_entry_payload_t));
    
    intent.magic = TOOB_WAL_ENTRY_MAGIC;
    intent.intent = TOOB_WAL_INTENT_CONFIRM_COMMIT;
    intent.expected_nonce = handoff.boot_nonce;
    
    /* Naive Delegation (schuetzt vor Duplikation und Erase-Komplexitaet) */
    return toob_wal_naive_append(&intent);
#endif
}

toob_status_t toob_recovery_resolved(void) {
    toob_wal_entry_payload_t intent;
    memset(&intent, 0, sizeof(toob_wal_entry_payload_t));
    
    intent.magic = TOOB_WAL_ENTRY_MAGIC;
    intent.intent = TOOB_WAL_INTENT_RECOVERY_RESOLVED;
    
    return toob_wal_naive_append(&intent);
}

toob_status_t toob_accumulate_net_search(uint32_t active_search_ms) {
    toob_wal_entry_payload_t intent;
    memset(&intent, 0, sizeof(toob_wal_entry_payload_t));
    
    intent.magic = TOOB_WAL_ENTRY_MAGIC;
    intent.intent = TOOB_WAL_INTENT_NET_SEARCH_ACCUM;
    
    /* P10 Spec: Das OS sammelt kontinuierlich und schickt das Delta oder den Totalwert. 
     * Wir casten via offset für den dynamischen Accumulator State. */
    intent.offset = active_search_ms;
    
    return toob_wal_naive_append(&intent);
}
