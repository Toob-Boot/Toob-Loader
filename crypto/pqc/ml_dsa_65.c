/**
 * @file crypto_pqc.c
 * @brief PQC-Hybrid Stub (ML-DSA-65)
 * 
 * Verhindert CMake Linker-Fails und erlaubt Footprint-Analysen der crypto_arena,
 * bis das echte PQC Backend integriert ist.
 */

#include "boot_hal.h"

boot_status_t boot_pqc_verify_ml_dsa_65(const uint8_t *msg, size_t msg_len,
                                        const uint8_t *sig, size_t sig_len,
                                        const uint8_t *pubkey, size_t pubkey_len) {
    (void)msg;
    (void)msg_len;
    (void)sig;
    (void)sig_len;
    (void)pubkey;
    (void)pubkey_len;
    
    return BOOT_ERR_NOT_SUPPORTED; /* PQC Not Yet Implemented */
}
