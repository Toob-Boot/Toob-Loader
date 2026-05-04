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

/* Dummy Ed25519 Root Key (RFC 8032 Test Vector 1) */
static const uint8_t MOCK_ED_PUBKEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

/* Fallback Ed25519 Root Key für Rotation Tests (key_index > 0, RFC 8032 Test Vector 2) */
static const uint8_t MOCK_ED_PUBKEY_FALLBACK[32] = {
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
    0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
    0xe0, 0xeb, 0x66, 0x84, 0x78, 0xd2, 0x2a, 0x86
};

/* Dummy DSLC (32 Bytes, P10 Alignment für boot_state.c) */
static const uint8_t MOCK_DSLC_BYTES[32] = "M-SANDBOX-DSLC-0000000000000001";

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
    if (*len < 32) {
        return BOOT_ERR_INVALID_ARG;
    }

    memcpy(buffer, MOCK_DSLC_BYTES, 32);
    *len = 32;
    
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
