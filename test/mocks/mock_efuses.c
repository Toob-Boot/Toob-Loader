/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: eFuses & OTP Implementation
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS & GAPS:
 * 1. docs/provisioning_guide.md -> Ed25519 Root Key OTP burning
 * 2. docs/concept_fusion.md -> (ENTFERNT: SECURE_BOOT_EN wird laut hals.md 
 *    nicht explizit über ein Trait-Flag vom Bootloader abgefragt).
 * 3. docs/stage_1_5_spec.md -> DSLC Factor (Hardware 2FA)
 */

#include "mock_efuses.h"
#include "chip_fault_inject.h"
#include <string.h>

static uint32_t simulated_monotonic_counter = 0;

/* Dummy Ed25519 Root Key */
static const uint8_t MOCK_ED_PUBKEY[32] = {
    0xED, 0x25, 0x51, 0x19, 0xAA, 0xBB, 0xCC, 0xDD,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
};

/* Fallback Ed25519 Root Key für Rotation Tests (key_index > 0) */
static const uint8_t MOCK_ED_PUBKEY_FALLBACK[32] = {
    0xFA, 0x11, 0xBA, 0xCC, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B
};

/* Dummy DSLC (16 Bytes) */
static const uint8_t MOCK_DSLC_BYTES[16] = "M-SANDBOX-DSLC01";

boot_status_t mock_efuse_read_pubkey(uint8_t *key, size_t key_len, uint8_t key_index) {
    if (key == NULL || key_len < 32) {
        return BOOT_ERR_INVALID_ARG;
    }

    fault_inject_init();
    if (g_fault_config.efuse_hardware_fault) {
        return BOOT_ERR_CRYPTO;
    }
    
    if (key_index == 0) {
        memcpy(key, MOCK_ED_PUBKEY, 32);
    } else {
        /* P10 Feature Simulation: Key Rotation Fallbacks (Slot > 0) */
        memcpy(key, MOCK_ED_PUBKEY_FALLBACK, 32);
    }
    
    return BOOT_OK;
}

boot_status_t mock_efuse_read_dslc(uint8_t *buffer, size_t *len) {
    if (buffer == NULL || len == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }

    fault_inject_init();
    if (g_fault_config.efuse_hardware_fault) {
        return BOOT_ERR_CRYPTO;
    }

    /* P10 Defense: Boundary Check */
    if (*len < 16) {
        return BOOT_ERR_INVALID_ARG;
    }

    memcpy(buffer, MOCK_DSLC_BYTES, 16);
    *len = 16;
    
    return BOOT_OK;
}

boot_status_t mock_efuse_read_monotonic_counter(uint32_t *ctr) {
    if (ctr == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }

    fault_inject_init();
    if (g_fault_config.efuse_hardware_fault) {
        return BOOT_ERR_CRYPTO;
    }

    *ctr = simulated_monotonic_counter;
    return BOOT_OK;
}

boot_status_t mock_efuse_advance_monotonic_counter(void) {
    fault_inject_init();
    if (g_fault_config.efuse_hardware_fault) {
        return BOOT_ERR_CRYPTO;
    }

    /* P10 Defense: Erschöpfung der physischen OTP-Bits */
    if (simulated_monotonic_counter >= g_fault_config.efuse_monotonic_limit) {
        return BOOT_ERR_COUNTER_EXHAUSTED;
    }

    simulated_monotonic_counter++;
    return BOOT_OK;
}

void mock_efuse_reset_state(void) {
    simulated_monotonic_counter = 0;
}
