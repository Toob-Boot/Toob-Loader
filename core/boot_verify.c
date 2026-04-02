/**
 * @file boot_verify.c
 * @brief Implementierung des Envelope-First Checks
 * 
 * Architektur-Direktiven (concept_fusion.md):
 * - Anti-Truncation (Envelope-Wrap)
 * - Anti-Side-Channel (OTFDEC Disable)
 * - Glitching Defense (Double-Check & NOP Injection)
 */

#include "boot_verify.h"
#include "boot_secure_zeroize.h"

/* Mathematisches Glitch-Resistenz-Gating. Darf sich statisch nicht auf implizierte Enums verlassen! */
_Static_assert(BOOT_OK == 0x55AA55AA, "BOOT_OK muss zwingend ein High-Hamming-Weight Pattern sein, ansonsten hebelt ein Single-Bit-Glitch das Double-Check Pattern aus!");

boot_status_t boot_verify_manifest_envelope(const boot_platform_t* platform, 
                                            const boot_verify_envelope_t* envelope,
                                            uint8_t* work_buffer,
                                            size_t work_buf_len) {

    /* 1. Argument- & Bounds-Verifikation */
    if (!platform || !platform->flash || !platform->wdt || !platform->crypto) {
        return BOOT_ERR_INVALID_ARG;
    }
    
    if (!envelope || !envelope->signature_ed25519 || !work_buffer) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* P10 Defensive Programming (GAP-03): Pruefe HAL Pointer bevor sie gerufen werden */
    if (!platform->crypto->read_pubkey || !platform->crypto->verify_ed25519) {
        return BOOT_ERR_NOT_SUPPORTED;
    }

    /* NASA P10 Bound Validation: Manifest darf den allokierten SRAM Buffer nicht übersteigen!
     * Ein Pufferüberlauf wäre hier tödlich (Privilege Escalation). */
    if (envelope->manifest_size == 0 || envelope->manifest_size > work_buf_len) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* 2. OTFDEC abschalten (Anti-Side-Channel Regel aus concept_fusion.md) */
    /* Die Signatur muss zwingend über den ROHEN Ciphertext abgegriffen werden. 
     * Ist OTFDEC auf MCU-Ebene noch an, entstünden katastrophale Crypto-Timings durch die HW-Verzögerungen.
     * ACHTUNG: Das Re-Enabling von OTFDEC erfolgt hier BEWUSST NICHT im Fehler-Exit. 
     * Das Delegations-Design schreibt vor, dass die `flash.deinit()` dies unmittelbar vor dem OS-Handoff asynchron triggert. 
     * 
     * HINWEIS `work_buffer`: Das Manifest im Buffer wird nach Return bewusst nicht gezeroized, 
     * da es als signierte Public-Domain Daten keinerlei kryptografische Geheimnisse enthält (RAM-Effizienz).
     */
    if (platform->flash->set_otfdec_mode != NULL) {
        boot_status_t otf_stat = platform->flash->set_otfdec_mode(false);
        if (otf_stat != BOOT_OK) {
            return otf_stat; 
        }
    }

    /* 3. Flash-Read in den Puffer mit Watchdog Kicks */
    /* Watchdog Kicks umschließen den potenziell blockierenden SPI Read */
    platform->wdt->kick();
    boot_status_t read_stat = platform->flash->read(envelope->manifest_flash_addr, work_buffer, envelope->manifest_size);
    platform->wdt->kick();
    
    if (read_stat != BOOT_OK) {
        return read_stat;
    }

    /* GAP-09 Key Epoch Revocation Check
     * concept_fusion.md Line 38: "Ist ein höherer HW-Epochen-Key gebrannt, weist der Bootloader 
     * alle Manifeste mit niedrigerer Epoch unwiderruflich ab". 
     * Da eFuses hardwareseitig sequenziell gebrannt werden, validieren wir elegant in O(1):
     * Wenn `read_pubkey(key_index + 1)` erfolgreich ist, ist der vom Manifest angefragte
     * key_index definitiv veraltet (revoked) und das Update muss hart abgewiesen werden!
     * 
     * Die `read_monotonic_counter` API der HAL wird hingegen strikt als Anti-Replay
     * für das logische Recovery-OS verwendet. Die Hardware-Epoche ergibt sich physisch.
     * HAL-CONTRACT: Die HAL MUSS forciert `BOOT_ERR...` zurückgeben, wenn ein eFuse Slot ungebrannt ist.
     */
    if (envelope->key_index < 255) {
        uint8_t dummy_pubkey[32];
        if (platform->crypto->read_pubkey(dummy_pubkey, envelope->key_index + 1) == BOOT_OK) {
            boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));
            return BOOT_ERR_VERIFY; /* Aktiver Downgrade-Versuch mit gestohlenem Alt-Key! */
        }
        boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));
    }

    /* 4. Lade den physischen Public-Key via crypto_hal */
    uint8_t root_pubkey[32];
    boot_status_t key_stat = platform->crypto->read_pubkey(root_pubkey, envelope->key_index);
    if (key_stat != BOOT_OK) {
        /* Anti-Leakage: Buffer sicher nilifizieren bei Mismatch/Hardware-Fehler */
        boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
        return key_stat;
    }

    /* 5. verify_ed25519 O(1) Check & 6. Double-Check Flag / Delay Injection */
    /* HINWEIS Timing-Protection: Die Sicherstellung der Constant-Time Ausführung der Krypto-Math
     * obliegt physisch dem Vendor in der HAL/Hardware. Diese Datei härtet nur die Branches (Glitching). */
    volatile uint32_t secure_flag_1 = 0;
    volatile uint32_t secure_flag_2 = 0;

    boot_status_t verify_stat = platform->crypto->verify_ed25519(
        work_buffer, envelope->manifest_size,
        envelope->signature_ed25519, root_pubkey
    );

    /* SECURE ZEROIZATION (GAP-Mitigation): Den Root-Key SOFORT nach Nutzung vernichten, 
     * um DPA/Memory-Leakage Angriffe im ruhenden SRAM abzuwehren! 
     * Verwendet zwingend boot_secure_zeroize() anstatt memset(), wie in hals.md vorgegeben. */
    boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));

    if (verify_stat == BOOT_OK) {
        secure_flag_1 = BOOT_OK; /* 0x55AA55AA */
    }

    /* Branch Delay Injection gegen Voltage Faults (Instruction Skips) */
    __asm__ volatile ("nop; nop; nop;");

    if (secure_flag_1 == BOOT_OK && verify_stat == BOOT_OK) {
        secure_flag_2 = BOOT_OK;
    }

    /* Dualer Signatur-Check zur Glitch-Rettung */
    if (secure_flag_1 != secure_flag_2) {
        return BOOT_ERR_VERIFY;
    }
    if (secure_flag_2 != BOOT_OK) {
        return BOOT_ERR_VERIFY;
    }

    /* 7. Optional PQC-Hybrid Validierung 
     * ARCHITEKTUR-PFEILER: Da ML-DSA Keys (~2.5 KB) niemals in eFuses passen, nutzen wir das
     * "Anchored Payload" Modell. Der PQC-PubKey (`envelope->pubkey_pqc`) stammt direkt aus dem
     * `work_buffer`, der oben bereits ERFOLGREICH über die Hardware-Root (Ed25519) verifiziert wurde!
     * Somit entsteht ein transitives, wasserdichtes Hardware-Vertrauensmodell für PQC.
     */
    if (envelope->pqc_hybrid_active) {
        if (!envelope->signature_pqc || envelope->signature_pqc_len == 0 ||
            !envelope->pubkey_pqc || envelope->pubkey_pqc_len == 0 ||
            !platform->crypto->verify_pqc) {
            return BOOT_ERR_INVALID_ARG;
        }

        /* Zwingende hardwaretechnische Erzwignung des Anchored-Payload Modells:
         * Wir MÜSSEN in C validieren, dass der PQC-Key-Pointer des Parsers sich physisch 
         * wirklich innerhalb des durch Ed25519 signierten SRAM-Buffers befindet!
         * Ein Pointer-Ausbruch in unsigniertes RAM würde die PQC-Vertrauenskette lautlos aushebeln. */
         if (envelope->pubkey_pqc < work_buffer ||
             (envelope->pubkey_pqc + envelope->pubkey_pqc_len) > (work_buffer + envelope->manifest_size)) {
             return BOOT_ERR_INVALID_ARG;
         }

        volatile uint32_t pqc_secure_flag_1 = 0;
        volatile uint32_t pqc_secure_flag_2 = 0;

        boot_status_t pqc_stat = platform->crypto->verify_pqc(
            work_buffer, envelope->manifest_size,
            envelope->signature_pqc, envelope->signature_pqc_len,
            envelope->pubkey_pqc, envelope->pubkey_pqc_len
        );

        if (pqc_stat == BOOT_OK) {
            pqc_secure_flag_1 = BOOT_OK; /* 0x55AA55AA */
        }

        /* Branch Delay Injection gegen Voltage Faults (Instruction Skips) */
        __asm__ volatile ("nop; nop; nop;");

        if (pqc_secure_flag_1 == BOOT_OK && pqc_stat == BOOT_OK) {
            pqc_secure_flag_2 = BOOT_OK;
        }

        /* Dualer PQC-Signatur-Check */
        if (pqc_secure_flag_1 != pqc_secure_flag_2 || pqc_secure_flag_2 != BOOT_OK) {
            return BOOT_ERR_VERIFY;
        }
    }

    return BOOT_OK; 
}
