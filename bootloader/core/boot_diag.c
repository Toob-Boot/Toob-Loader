/*
 * Toob-Boot Core File: boot_diag.c
 * Relevant Spec-Dateien:
 * - docs/toob_telemetry.md (CBOR Kodierung, Wear Data, Diag-Struct)
 */

#include "boot_types.h"
#include "boot_diag.h"
#include "boot_secure_zeroize.h"
#include "boot_crc32.h"
#include <stddef.h>

void boot_diag_init(void) {
    boot_secure_zeroize(&toob_diag_state, sizeof(toob_boot_diag_t));
    toob_diag_state.struct_version = TOOB_DIAG_STRUCT_VERSION;
}

void boot_diag_add_verify_time(uint32_t time_ms) {
    toob_diag_state.verify_time_ms += time_ms;
}

void boot_diag_set_boot_time(uint32_t time_ms) {
    toob_diag_state.boot_duration_ms = time_ms;
}

void boot_diag_set_error(boot_status_t error, uint32_t vendor_fault) {
    toob_diag_state.last_error_code = (uint32_t)error;
    toob_diag_state.vendor_error = vendor_fault;
}

void boot_diag_set_security_meta(uint32_t svn, uint32_t key_idx, const uint8_t *sbom_hash) {
    toob_diag_state.current_svn = svn;
    toob_diag_state.active_key_index = key_idx;
    if (sbom_hash) {
        for (size_t i = 0; i < 32; i++) {
            toob_diag_state.sbom_digest[i] = sbom_hash[i];
        }
    } else {
        boot_secure_zeroize(toob_diag_state.sbom_digest, 32);
    }
}

void boot_diag_set_recovery_events(uint32_t count) {
    toob_diag_state.edge_recovery_events = count;
}

void boot_diag_set_wear_data(const toob_ext_health_t *wear_stats) {
    if (wear_stats) {
        toob_diag_state.ext_health_present = 1;
        toob_diag_state.ext_health.wal_erase_count = wear_stats->wal_erase_count;
        toob_diag_state.ext_health.app_slot_erase_count = wear_stats->app_slot_erase_count;
        toob_diag_state.ext_health.staging_slot_erase_count = wear_stats->staging_slot_erase_count;
        toob_diag_state.ext_health.swap_buffer_erase_count = wear_stats->swap_buffer_erase_count;
    }
}

void boot_diag_seal(void) {
    /* P10 Defense: Ensure internal alignment padding cannot leak stack/RAM fragments */
    toob_diag_state._padding[0] = 0;
    toob_diag_state._padding[1] = 0;
    toob_diag_state._padding[2] = 0;
    
    /* Calculate CRC-32 exactly up to the trailer boundary */
    size_t payload_len = offsetof(toob_boot_diag_t, crc32_trailer);
    toob_diag_state.crc32_trailer = compute_boot_crc32((const uint8_t *)&toob_diag_state, payload_len);
}
