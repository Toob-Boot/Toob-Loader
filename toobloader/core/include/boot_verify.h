/**
 * @file boot_verify.h
 * @brief SUIT-Manifest Signatur Envelope Wrapper. 
 *
 * Toob-Boot Stage 1 wertet ein Manifest erst aus, wenn das gesamte Paket mathematisch 
 * als legitim bewiesen ist (Sign-then-Hash nach RFC/COSE_Sign1). 
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md (Anti-Truncation, Branch-Delay, OTFDEC Offline-Zwang)
 * - docs/stage_1_5_spec.md (Auth-Token Signatur)
 */

#ifndef TOOB_BOOT_VERIFY_H
#define TOOB_BOOT_VERIFY_H

#include "boot_hal.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Boot Verify Kontext für asymmetrische Envelope Validierungen
 * Setzt den Kontext für den vollständigen Signatur-Schild.
 */
typedef struct {
    uint32_t manifest_flash_addr;     /* Absoluter physikalischer SPI Pointer */
    size_t   manifest_size;           /* Gesamtgröße des voll geformten SUIT-Manifests */
    const uint8_t* signature_ed25519; /* Pointer auf die Ed25519 Signatur */
    uint8_t  key_index;               /* eFuse OTP Key-Index (0..) für Key-Revocation Check */
    
    bool     pqc_hybrid_active;       /* Ist PQC-Migration (ML-DSA) durch das Manifest verlangt? */
    const uint8_t* signature_pqc;     /* Signatur-Block für PQC */
    size_t   signature_pqc_len;       /* Länge des PQC Blocks */
    const uint8_t* pubkey_pqc;        /* Der PQC-Public-Key (Anchored in Payload) */
    size_t   pubkey_pqc_len;          /* Länge des PQC Keys */
} boot_verify_envelope_t;

/**
 * @brief Envelope-First Validierungs-Gate (Glitch-gehärtet)
 *
 * Reißt die OTFDEC-Wall nieder, zieht das Manifest in SRAM (Vermeidung von hw-crypto Timings)
 * und evaluiert die Signatur mittels Double-Check against Voltage Faults.
 * 
 * 1. Argument- & Bounds-Verifikation (manifest_size > work_buf_len blocken!)
 * 2. OTFDEC abschalten (Anti-Side-Channel) via flash_hal.
 * 3. Flash-Read in den Puffer mit Watchdog Kicks vor/danach.
 * 4. Lade den physischen Public-Key via crypto_hal->read_pubkey(key_index).
 * 5. Führe O(1) verify_ed25519 auf den RAM Puffer aus.
 * 6. Double-Check Flag mit __asm__ volatile("nop") Delay Injection!
 * 7. Optional PQC-Hybrid Validierung, wenn gefordert.
 * 
 * @param platform      Boot HAL Platform Pointer
 * @param envelope      Check-Kontext mit Meta-Daten und Payload-Signatur
 * @param work_buffer   No-Malloc Puffer für das Manifest-SRAM-Laden (typisch crypto_arena)
 * @param work_buf_len  Größe des verfügbaren Puffers
 * @return BOOT_OK (0x55AA55AA) wenn mathematisch/physisch einwandfrei, sonst Fehlercode.
 */
boot_status_t boot_verify_manifest_envelope(const boot_platform_t* platform, 
                                            const boot_verify_envelope_t* envelope,
                                            uint8_t* work_buffer,
                                            size_t work_buf_len);

#endif /* TOOB_BOOT_VERIFY_H */
