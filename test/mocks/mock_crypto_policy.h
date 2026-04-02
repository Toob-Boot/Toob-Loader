/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Crypto Policy Bypass Header
 * ==============================================================================
 */

#ifndef MOCK_CRYPTO_POLICY_H
#define MOCK_CRYPTO_POLICY_H

#include "boot_hal.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Der originale Math-Call, bereitgestellt durch die Linker --wrap Magie.
 */
extern boot_status_t __real_verify_ed25519(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,
    const uint8_t *pubkey
);

/**
 * @brief Der Interceptor für die Ed25519-Signaturprüfung.
 */
boot_status_t __wrap_verify_ed25519(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,
    const uint8_t *pubkey
);

/**
 * @brief Der originale Math-Call für Post-Quantum Crypto (ML-DSA)
 */
extern boot_status_t __real_verify_pqc(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,      size_t sig_len,
    const uint8_t *pubkey,   size_t pubkey_len
);

/**
 * @brief Der Interceptor für die ML-DSA Post-Quantum Signaturprüfung.
 */
boot_status_t __wrap_verify_pqc(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,      size_t sig_len,
    const uint8_t *pubkey,   size_t pubkey_len
);

/**
 * @brief Original Vendor-Fehler Telemetrie-Abruf.
 */
extern uint32_t __real_get_last_vendor_error(void);

/**
 * @brief Mock Vendor-Fehler Telemetrie-Abruf (liefert z.B. 0xDEADBEEF bei simulierten Faults).
 */
uint32_t __wrap_get_last_vendor_error(void);

#endif /* MOCK_CRYPTO_POLICY_H */
