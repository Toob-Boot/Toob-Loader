/**
 * ==============================================================================
 * Toob-Boot libtoob: Handoff-RAM (.noinit) Validierung (toob_handoff.c)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (toob_handoff_t structure definition and Magic values)
 * - docs/concept_fusion.md (P10 CRC-32 validation requirements across ABI boundaries)
 * - docs/testing_requirements.md (RAM bound checks to prevent .noinit arbitrary read vulnerabilities)
 */

#include "libtoob.h"
#include "toob_internal.h"
#include <string.h>

/* ==============================================================================
 * .noinit RAM Definition (GAP-39)
 * (Wird durch den Linker in die uninitialisierte Sektion gemappt)
 * 
 * Arch-Note (Zero-Dependency): This library defines the OS-side boundary.
 * The Bootloader (S1) uses its own isolated definition. Since the OS and S1 
 * are compiled into strictly separate binaries, there are no linker collisions.
 * ============================================================================== */
/* Arch-Note: Für Cross-Compilation Linker-Collisions (Unit Tests) */
#ifndef TOOB_MOCK_TEST
TOOB_NOINIT toob_handoff_t toob_handoff_state;
#endif

toob_status_t toob_validate_handoff(void) {
    if (toob_handoff_state.magic != TOOB_STATE_COMMITTED) {
        return TOOB_ERR_VERIFY;
    }
    
    /* P10 Robustness: Berechne CRC per offsetof statt sizeof zwecks Tail-Padding Immunität */
    size_t payload_len = offsetof(toob_handoff_t, crc32_trailer);
    uint32_t calculated_crc = toob_lib_crc32((const uint8_t*)&toob_handoff_state, payload_len);
    
    if (calculated_crc != toob_handoff_state.crc32_trailer) {
        return TOOB_ERR_VERIFY;
    }
    
    return TOOB_OK;
}

toob_status_t toob_get_handoff(toob_handoff_t* out_handoff) {
    if (!out_handoff) {
        return TOOB_ERR_INVALID_ARG;
    }
    
    /* Strikte Garbage-Abwehr: Wenn CRC nicht stimmt, WDT Absturz verhindern! */
    toob_status_t status = toob_validate_handoff();
    if (status != TOOB_OK) {
        return status;
    }
    
    /* Sicheres Kopieren by-value ins OS-Feature-RAM */
    memcpy(out_handoff, &toob_handoff_state, sizeof(toob_handoff_t));
    
    return TOOB_OK;
}
