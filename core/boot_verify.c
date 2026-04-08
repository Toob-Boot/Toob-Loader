/**
 * @file boot_verify.c
 * @brief Implementierung des Envelope-First Checks (Mathematical Perfection
 * Revision)
 *
 * Architektur-Direktiven (concept_fusion.md):
 * - Anti-Truncation (Envelope-Wrap Proofs)
 * - Anti-Side-Channel (Constant-Time eFuse Read & OTFDEC Offline-Zwang)
 * - Glitching Defense (Control Flow Integrity & Double-Check Pattern)
 * - Pointer Provenance Defense (uintptr_t Casting gegen Compiler-Optimierungen)
 */

#include "boot_verify.h"
#include "boot_secure_zeroize.h"
#include "boot_types.h"
#include <stddef.h>
#include <stdint.h>

/* Mathematisches Glitch-Resistenz-Gating. Darf sich statisch nicht auf
 * implizierte Enums verlassen! */
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK muss zwingend ein High-Hamming-Weight Pattern sein, um "
               "das Double-Check Pattern zu garantieren!");

/**
 * @brief O(1) Mathematisch perfekter Buffer-Boundary Check (UB-frei).
 * Verhindert "Anchored Payload" CVEs. Arbeitet via uintptr_t Addition,
 * um Integer/Pointer Wraparounds auf 32/64-bit Architekturen absolut
 * auszuschließen.
 */
static inline bool is_buffer_within(const uint8_t *inner, size_t inner_len,
                                    const uint8_t *outer, size_t outer_len) {
  if (inner_len == 0 || outer_len == 0)
    return false;

  uintptr_t i_start = (uintptr_t)inner;
  uintptr_t o_start = (uintptr_t)outer;

  /* Wraparound Proof: Kann die Länge den Addressraum sprengen? */
  if (UINTPTR_MAX - i_start < inner_len)
    return false;
  if (UINTPTR_MAX - o_start < outer_len)
    return false;

  uintptr_t i_end = i_start + inner_len;
  uintptr_t o_end = o_start + outer_len;

  /* Liegt der innere Buffer mathematisch komplett im äußeren? */
  return (i_start >= o_start) && (i_end <= o_end);
}

boot_status_t
boot_verify_manifest_envelope(const boot_platform_t *platform,
                              const boot_verify_envelope_t *envelope,
                              uint8_t *work_buffer, size_t work_buf_len) {

  /* ====================================================================
   * 1. P10 ALLOCATION & PESSIMISTIC INITIALIZATION
   * ==================================================================== */
  boot_status_t final_status =
      BOOT_ERR_VERIFY; /* Grundzustand: Kompromittiert / Default-Deny */

  /* CFI-Akkumulator: Beweist den physischen Durchlauf der Verifikationsblöcke
   */
  volatile uint32_t execution_path = 0x00000000;

  /* P10 Stack Allocation: 8-Byte Alignment zwingend für HW-Crypto-Cores
   * (AArch64 / TrustZone) */
  uint8_t root_pubkey[32] __attribute__((aligned(8)));
  uint8_t dummy_pubkey[32] __attribute__((aligned(8)));

  /* Sofortige Nullifizierung zur Vermeidung von Leakage undefinierter
   * Stack-Werte */
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));

  /* ====================================================================
   * 2. P10 ARGUMENT & BOUNDS VALIDATION (Zero-Trust)
   * ==================================================================== */
  if (!platform || !platform->flash || !platform->wdt || !platform->crypto) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (!envelope || !envelope->signature_ed25519 || !work_buffer) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (!platform->crypto->read_pubkey || !platform->crypto->verify_ed25519) {
    final_status = BOOT_ERR_NOT_SUPPORTED;
    goto cleanup;
  }

  /* NASA P10 Bound Validation: Manifest darf den allokierten SRAM Buffer nicht
   * übersteigen! */
  if (envelope->manifest_size == 0 || envelope->manifest_size > work_buf_len) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* Address-Space Wraparound Defense für den RAM-Puffer selbst */
  uintptr_t base_ptr = (uintptr_t)work_buffer;
  if (UINTPTR_MAX - base_ptr < envelope->manifest_size) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  execution_path ^= 0x11111111; /* Schritt 1 erfolgreich bewiesen */

  /* ====================================================================
   * 3. CONSTANT-TIME eFUSE DOWNGRADE CHECK (Side-Channel Closure)
   * ====================================================================
   * Wir lesen IMMER eine Hardware-eFuse, um Power/Timing-Analysen zu
   * verhindern. C-Ternary Operator kompiliert typischerweise in 'CSEL'
   * (Conditional Select), was keinen Jump erzeugt.
   */
  uint8_t next_idx =
      (envelope->key_index < 255) ? (envelope->key_index + 1) : 255;

  platform->wdt->kick();
  boot_status_t next_key_stat = platform->crypto->read_pubkey(
      dummy_pubkey, sizeof(dummy_pubkey), next_idx);
  platform->wdt->kick();

  /* Wenn der angefragte Index < 255 ist und der nächste Slot gültig ist,
     handelt es sich um einen revozierten Key -> Downgrade-Versuch! */
  volatile uint32_t downgrade_shield_1 = 0;
  volatile uint32_t downgrade_shield_2 = 0;

  bool is_max_key = (envelope->key_index == 255);
  bool next_key_absent = (next_key_stat != BOOT_OK);

  if (is_max_key || next_key_absent) {
    downgrade_shield_1 = BOOT_OK;
  }

  __asm__ volatile("nop; nop; nop;"); /* Glitch Delay Injection */

  if (downgrade_shield_1 == BOOT_OK && (is_max_key || next_key_absent)) {
    downgrade_shield_2 = BOOT_OK;
  }

  if (downgrade_shield_1 != BOOT_OK || downgrade_shield_2 != BOOT_OK) {
    final_status =
        BOOT_ERR_DOWNGRADE; /* Downgrade Attack physikalisch identifiziert! */
    goto cleanup;
  }

  execution_path ^= 0x22222222; /* Schritt 3 erfolgreich bewiesen */

  /* ====================================================================
   * 4. HARDWARE ROOT-OF-TRUST EXTRACTION
   * ==================================================================== */
  platform->wdt->kick();
  boot_status_t key_stat = platform->crypto->read_pubkey(
      root_pubkey, sizeof(root_pubkey), envelope->key_index);
  platform->wdt->kick();

  if (key_stat != BOOT_OK) {
    final_status = key_stat;
    goto cleanup;
  }

  /* ====================================================================
   * 5. ENVELOPE-FIRST ED25519 VERIFICATION (Glitch Hardened)
   * ==================================================================== */
  volatile uint32_t ed_secure_flag_1 = 0;
  volatile uint32_t ed_secure_flag_2 = 0;

  platform->wdt->kick();
  boot_status_t verify_stat = platform->crypto->verify_ed25519(
      work_buffer, envelope->manifest_size, envelope->signature_ed25519,
      root_pubkey);
  platform->wdt->kick();

  /* DPA MINIMIZATION: Wir schreddern den Root Key SOFORT nach dem
   * Signatur-Check! Er darf keine Makrosekunde länger als zwingend nötig im RAM
   * verweilen. */
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));

  if (verify_stat == BOOT_OK) {
    ed_secure_flag_1 = BOOT_OK;
  }

  __asm__ volatile("nop; nop; nop;"); /* Branch-Skip Mitigation */

  if (ed_secure_flag_1 == BOOT_OK && verify_stat == BOOT_OK) {
    ed_secure_flag_2 = BOOT_OK;
  }

  if (ed_secure_flag_1 != BOOT_OK || ed_secure_flag_2 != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  execution_path ^= 0x44444444; /* Schritt 5 erfolgreich bewiesen */

  /* ====================================================================
   * 6. POST-QUANTUM HYBRID ENFORCEMENT & ANCHORED PAYLOAD VERIFY
   * ==================================================================== */
  bool pqc_enforced = false;
  if (platform->crypto->is_pqc_enforced) {
    pqc_enforced = platform->crypto->is_pqc_enforced();
  }

  bool pqc_required = pqc_enforced || envelope->pqc_hybrid_active;

  if (pqc_required) {
    if (!platform->crypto->verify_pqc) {
      final_status = BOOT_ERR_NOT_SUPPORTED;
      goto cleanup;
    }

    if (!envelope->signature_pqc || envelope->signature_pqc_len == 0 ||
        !envelope->pubkey_pqc || envelope->pubkey_pqc_len == 0) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    /* MATHEMATISCHER POINTER-BEWEIS (CVE Defense):
     * Wir beweisen mathematisch UB-frei, dass der vom Parser übergebene
     * PQC-Key-Pointer und Signatur-Pointer physisch innerhalb des durch Ed25519
     * signierten SRAM-Buffers liegen! */
    if (!is_buffer_within(envelope->pubkey_pqc, envelope->pubkey_pqc_len,
                          work_buffer, envelope->manifest_size)) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    if (!is_buffer_within(envelope->signature_pqc, envelope->signature_pqc_len,
                          work_buffer, envelope->manifest_size)) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    volatile uint32_t pqc_secure_flag_1 = 0;
    volatile uint32_t pqc_secure_flag_2 = 0;

    platform->wdt->kick();
    boot_status_t pqc_stat = platform->crypto->verify_pqc(
        work_buffer, envelope->manifest_size, envelope->signature_pqc,
        envelope->signature_pqc_len, envelope->pubkey_pqc,
        envelope->pubkey_pqc_len);
    platform->wdt->kick();

    if (pqc_stat == BOOT_OK) {
      pqc_secure_flag_1 = BOOT_OK;
    }

    __asm__ volatile("nop; nop; nop;");

    if (pqc_secure_flag_1 == BOOT_OK && pqc_stat == BOOT_OK) {
      pqc_secure_flag_2 = BOOT_OK;
    }

    if (pqc_secure_flag_1 != pqc_secure_flag_2 ||
        pqc_secure_flag_2 != BOOT_OK) {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    execution_path ^= 0x88888888; /* PQC-Verifikation erfolgreich bewiesen */
  }

  /* ====================================================================
   * 7. CONTROL FLOW INTEGRITY (CFI) RESOLUTION
   * ==================================================================== */
  /* Berechne das erwartete kryptografische Hamming-Weight, das die CPU
   * am Ende des Durchlaufs im CFI-Akkumulator aufweisen muss. */
  uint32_t expected_path = 0x11111111 ^ 0x22222222 ^ 0x44444444 ^
                           (pqc_required ? 0x88888888 : 0x00000000);

  volatile uint32_t path_check_1 = 0;
  volatile uint32_t path_check_2 = 0;

  if (execution_path == expected_path) {
    path_check_1 = BOOT_OK;
  }

  __asm__ volatile("nop; nop; nop;");

  if (path_check_1 == BOOT_OK && execution_path == expected_path) {
    path_check_2 = BOOT_OK;
  }

  /* Nur wenn der Control Flow lückenlos physisch bewiesen ist,
   * entsperren wir den finalen BOOT_OK Status! */
  if (path_check_1 == BOOT_OK && path_check_2 == BOOT_OK) {
    final_status = BOOT_OK;
  } else {
    final_status = BOOT_ERR_VERIFY;
  }

cleanup:
  /* ====================================================================
   * 8. P10 SINGLE EXIT: SECURE ZEROIZE FALLBACK
   * ====================================================================
   * Unabhängig vom Ausgang werden alle Krypto-Materialien atomar vom Stack
   * radiert. Der `root_pubkey` verlässt diesen Scope NIEMALS intakt,
   * auch nicht, wenn wir per Pointer-Overflow in dieses Goto fielen.
   */
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));

  return final_status;
}