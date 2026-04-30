/*
 * Toob-Boot Stage 0: stage0_verify.c
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md (Ed25519)
 */
#include "../../crypto/monocypher/monocypher-ed25519.h"
#include <stddef.h>
#include <stdint.h>

/* Signatur-Prüfung in Stage0. Direkt angebunden an Monocypher, ohne HAL. */
int stage0_verify_signature(const uint8_t *sig, const uint8_t *pubkey, const uint8_t *msg, size_t len) {
    int status = crypto_ed25519_check(sig, pubkey, msg, len);
    
    /* P10 Glitch-Defense Double-Check Pattern */
    volatile uint32_t s1 = 0, s2 = 0;
    if (status == 0) {
        s1 = 0x55AA55AA;
    }
    
    /* Bare-Metal Instruction Delay */
    for (volatile uint32_t delay = 0; delay < 100; delay++) {
        __asm__ volatile("nop");
    }
    
    if (s1 == 0x55AA55AA && status == 0) {
        s2 = 0x55AA55AA;
    }
    
    if (s1 == 0x55AA55AA && s2 == 0x55AA55AA && s1 == s2) {
        return 0; /* OK */
    }
    
    return -1; /* FAIL */
}
