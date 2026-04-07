/**
 * ==============================================================================
 * Toob-Boot libtoob: Diagnostics Extraktions Implementation (toob_diag.c)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (toob_get_boot_diag function definition)
 * - docs/toob_telemetry.md (Boot diagnostic data model, CBOR readiness)
 * - docs/concept_fusion.md (Fleet insight extraction without static buffer dependencies)
 */

#include "libtoob.h"
#include "toob_internal.h"
#include <string.h>

/* ==============================================================================
 * .noinit RAM Definition (GAP-39 / Diagnostics)
 * ============================================================================== */
#ifndef TOOB_MOCK_TEST
TOOB_NOINIT toob_boot_diag_t toob_diag_state;
#endif

toob_status_t toob_get_boot_diag(toob_boot_diag_t* diag) {
    if (!diag) {
        return TOOB_ERR_INVALID_ARG;
    }
    
    /* 1. Prüfe struct_version und isolierte CRC der Diagnostics */
    if (toob_diag_state.struct_version != TOOB_DIAG_STRUCT_VERSION) {
        return TOOB_ERR_VERIFY;
    }
    
    /* P10 Robustness: CRC-32 Validation relies dynamically on offsetof, mitigating ABI tail-padding drifts */
    size_t payload_len = offsetof(toob_boot_diag_t, crc32_trailer);
    uint32_t calculated_crc = toob_lib_crc32((const uint8_t*)&toob_diag_state, payload_len);
    
    if (calculated_crc != toob_diag_state.crc32_trailer) {
        return TOOB_ERR_VERIFY;
    }
    
    /* 3. Safe-Passing P10: By-Value-Kopie in OS-Feature-Space zum Schutz */
    memcpy(diag, &toob_diag_state, sizeof(toob_boot_diag_t));
    
    return TOOB_OK;
}
