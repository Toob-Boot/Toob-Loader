/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Crypto Policy Implementation (--wrap)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS & GAPS:
 * 1. docs/hals.md -> crypto_hal_t
 * 2. docs/merkle_spec.md -> Stream-Hashing Bypass
 *    ENTSCHEIDUNG: Ein genereller SHA-256 Bypass wird NICHT implementiert. Das Hashing ist
 *    auf x86 schnell genug und wir benötigen die echten Hashes, um `boot_verify.c` beim
 *    Lesen korrupter Payloads nicht komplett blind zu machen. Merkle-Bypass = Real Math.
 * 3. docs/testing_requirements.md -> Zero Code Slop (Link-Time Mocking)
 * 4. docs/hals.md -> verify_pqc / PQC Bypass implemented.
 * 5. docs/hals.md -> get_last_vendor_error telemetry mock implemented.
 */

#include "mock_crypto_policy.h"
#include "chip_fault_inject.h"

boot_status_t __wrap_verify_ed25519(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,
    const uint8_t *pubkey) 
{
    /* Lade Config aus dem M-SANDBOX State */
    fault_inject_init();

    if (g_fault_config.crypto_hardware_fault) {
        /* Gesteuerte HW-Simulation: C-Core soll über `BOOT_ERR_CRYPTO` stolpern. */
        return BOOT_ERR_CRYPTO;
    }

    if (g_fault_config.crypto_force_invalid) {
        return BOOT_ERR_VERIFY;
    }

    if (g_fault_config.crypto_bypass_ed25519) {
        /* Zero-Code-Slop HW-Bypass. Ideal für Fuzzing Tests der JSON-Parser 
           ohne Signaturaufwand! */
        return BOOT_OK;
    }

    /* Fallback zur echten C-Implementierung (Monocypher etc. über Host gelinkt) */
    return __real_verify_ed25519(message, msg_len, sig, pubkey);
}

boot_status_t __wrap_verify_pqc(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,      size_t sig_len,
    const uint8_t *pubkey,   size_t pubkey_len)
{
    /* Lade Config aus dem M-SANDBOX State */
    fault_inject_init();

    if (g_fault_config.crypto_hardware_fault) {
        return BOOT_ERR_CRYPTO;
    }

    if (g_fault_config.crypto_force_invalid) {
        return BOOT_ERR_VERIFY;
    }

    if (g_fault_config.crypto_bypass_ed25519) {
        /* ML-DSA Bypass parallel zum klassischen Bypass aktiv. */
        return BOOT_OK;
    }

    /* Originale Post-Quantum Mathe-Engine rechnen lassen */
    return __real_verify_pqc(message, msg_len, sig, sig_len, pubkey, pubkey_len);
}

uint32_t __wrap_get_last_vendor_error(void) {
    fault_inject_init();

    if (g_fault_config.crypto_hardware_fault) {
        /* P10 Diagnostic Code: Simulierter Hardware Fault auf dem Host Runner 
         * gibt 0xDEADBEEF als Dummy-Register Zustand zurück. */
        return 0xDEADBEEF;
    }

    return __real_get_last_vendor_error();
}
