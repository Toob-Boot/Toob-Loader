/**
 * @file boot_verify.h
 * @brief TBM1-Manifest Signatur Envelope Wrapper. 
 *
 * Toob-Boot Stage 1 wertet ein Manifest erst aus, wenn das gesamte Paket mathematisch 
 * als legitim bewiesen ist (Sign-then-Hash). 
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md (Anti-Truncation, Branch-Delay, OTFDEC Offline-Zwang)
 * - docs/stage_1_5_spec.md (Auth-Token Signatur)
 */

#ifndef TOOB_BOOT_VERIFY_H
#define TOOB_BOOT_VERIFY_H

#include "boot_hal.h"
#include "boot_types.h"
#include "generated_boot_config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Boot Verify Kontext für asymmetrische Envelope Validierungen
 * Setzt den Kontext für den vollständigen Signatur-Schild.
 */
typedef struct {
  uint32_t manifest_flash_addr;     /* Absoluter physikalischer SPI Pointer */
  size_t manifest_size;             /* Exakte Größe des signierten Bereichs (total_len - 64).
                                       * MUSS aus dem TBM1-Header kommen, NIEMALS aus dem Pufferrand inferiert. */
  const uint8_t *signature_ed25519; /* Pointer auf die Ed25519 Signatur */
  uint8_t key_index;                /* eFuse OTP Key-Index (0..) für Key-Revocation Check */

#if TOOB_PQC_ENABLED
  bool pqc_hybrid_active;       /* Ist PQC-Migration (ML-DSA) durch das Manifest verlangt? */
  const uint8_t *signature_pqc; /* Signatur-Block für PQC */
  size_t signature_pqc_len;     /* Länge des PQC Blocks */
  const uint8_t *pubkey_pqc;    /* Der PQC-Public-Key (Anchored in Payload) */
  size_t pubkey_pqc_len;        /* Länge des PQC Keys */
#endif
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
boot_status_t boot_verify_manifest_envelope(const boot_platform_t *platform,
                                            const boot_verify_envelope_t *envelope,
                                            uint8_t *work_buffer, size_t work_buf_len);

/**
 * @brief Authenticates a flashed App, Recovery OS, or Backup slot image via TSIG trailer.
 *
 * Streams SHA-256 over [slot_addr .. slot_addr + image_size - 72) using `arena`,
 * enforces constant-time non-revoked OTP key check on `trailer.key_index`, and
 * verifies the Ed25519 signature stored in `toob_img_sig_trailer_t`.
 * Zeroizes all keys, digests, and arena contents prior to return.
 *
 * Unsigned image bypass via TOOB_ALLOW_UNSIGNED_APP_BOOT is compile-time forbidden
 * whenever TOOB_PROFILE_PRODUCTION is defined.
 *
 * @param platform  Boot HAL platform pointer
 * @param slot_addr Absolute flash start address of the slot image
 * @param slot_size Total slot size in bytes
 * @param hdr       Previously parsed image header at slot_addr
 * @param arena     Caller scratch buffer (>= 256 bytes)
 * @param arena_len Size of `arena` in bytes
 * @return BOOT_OK if valid (or bounds-valid under explicit non-prod bypass), else error.
 */
boot_status_t boot_verify_slot_image(const boot_platform_t *platform, uint32_t slot_addr,
                                     uint32_t slot_size, const toob_image_header_t *hdr,
                                     uint8_t *arena, size_t arena_len);

#endif /* TOOB_BOOT_VERIFY_H */
