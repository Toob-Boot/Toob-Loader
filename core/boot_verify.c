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
 * - TOCTOU Defense (Isolierte O(1) Memory Clones)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Zero-Key Hardware Lock: Verhindert mathematisch "All-Zero Key Forgeries"
 * bei Ed25519 und PQC, falls ein EMFI-Glitch den SPI-Read oder eFuse-Read
 * unterbricht.
 * 2. Strict Internal CFI: Feingranulares Control Flow Integrity Tracking
 * beweist, dass Extrahierung, Downgrade-Check und Signatur lückenlos
 * durchlaufen wurden.
 * 3. Glitch-Gated Hardware Reads: Double-Check Pattern für kritische
 * HAL-Aufrufe.
 * 4. Branchless Math: Konstante Zeit-Berechnungen ohne Branches.
 */

#include "boot_verify.h"
#include "boot_secure_zeroize.h"
#include "boot_types.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Mathematisches Glitch-Resistenz-Gating. Darf sich statisch nicht auf
 * implizierte Enums verlassen! */
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK muss zwingend ein High-Hamming-Weight Pattern sein, um "
               "das Double-Check Pattern zu garantieren!");

/* P10 Zero-Trust CFI Constants */
#define CFI_VERIFY_INIT 0x00000000
#define CFI_VERIFY_STEP_1 0x11111111
#define CFI_VERIFY_STEP_2 0x22222222
#define CFI_VERIFY_STEP_3 0x33333333
#define CFI_VERIFY_STEP_4 0x44444444
#define CFI_VERIFY_STEP_5 0x88888888
#define CFI_VERIFY_STEP_5_SKIP 0x55555555

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

/**
 * @brief O(1) Mathematical Zero-Buffer Verification (Glitch Protected)
 * Verhindert Triviale-Signatur-Fälschungen durch fabrikneue (leere) eFuses
 * oder Hardware-Glitches, die einen All-Zero (oder All-0xFF) Public Key
 * produzieren.
 */
static inline boot_status_t verify_not_all_zeros_glitch_safe(const uint8_t *buf,
                                                             size_t len) {
  uint8_t or_acc = 0x00;
  uint8_t and_acc = 0xFF;

  for (size_t i = 0; i < len; i++) {
    or_acc |= buf[i];
    and_acc &= buf[i];
  }

  volatile uint32_t zero_shield_1 = 0;
  volatile uint32_t zero_shield_2 = 0;

  if (or_acc != 0x00 && and_acc != 0xFF)
    zero_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (zero_shield_1 == BOOT_OK && or_acc != 0x00 && and_acc != 0xFF)
    zero_shield_2 = BOOT_OK;

  if (zero_shield_1 == BOOT_OK && zero_shield_2 == BOOT_OK &&
      zero_shield_1 == zero_shield_2) {
    return BOOT_OK;
  }

  return BOOT_ERR_VERIFY; /* All-Zero / All-xFF Key detected -> Abort! */
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
  volatile uint32_t execution_path = CFI_VERIFY_INIT;

  /* P10 Stack Allocation: 8-Byte Alignment zwingend für HW-Crypto-Cores */
  uint8_t root_pubkey[32] __attribute__((aligned(8)));
  uint8_t dummy_pubkey[32] __attribute__((aligned(8)));

  /* Sofortige Nullifizierung zur Vermeidung von Leakage undefinierter
   * Stack-Werte */
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));

  /* ====================================================================
   * 1.5 TOCTOU & DOUBLE-FETCH SHIELDING (Time-Of-Check to Time-Of-Use)
   * ====================================================================
   * Zieht die Envelope-Struktur in den lokalen, sicheren C-Stack. Das
   * verhindert asynchrone Manipulationen (z.B. durch bösartiges DMA),
   * die zwischen Verifikation und Nutzung Pointer-Längen verändern.
   */
  boot_verify_envelope_t local_env;
  boot_secure_zeroize(&local_env, sizeof(local_env));

  if (envelope != NULL) {
    memcpy(&local_env, envelope, sizeof(boot_verify_envelope_t));
  } else {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* ====================================================================
   * 2. P10 ARGUMENT & BOUNDS VALIDATION (Zero-Trust)
   * ==================================================================== */
  if (!platform || !platform->flash || !platform->wdt || !platform->crypto) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (!local_env.signature_ed25519 || !work_buffer) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (!platform->crypto->read_pubkey || !platform->crypto->verify_ed25519) {
    final_status = BOOT_ERR_NOT_SUPPORTED;
    goto cleanup;
  }

  /* NASA P10 Bound Validation: Manifest darf den allokierten SRAM Buffer nicht
   * übersteigen! */
  if (local_env.manifest_size == 0 || local_env.manifest_size > work_buf_len) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* Address-Space Wraparound Defense für den RAM-Puffer selbst */
  uintptr_t base_ptr = (uintptr_t)work_buffer;
  if (UINTPTR_MAX - base_ptr < local_env.manifest_size) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  execution_path ^= CFI_VERIFY_STEP_1; /* Schritt 1 erfolgreich bewiesen */

  /* ====================================================================
   * 3. CONSTANT-TIME eFUSE DOWNGRADE CHECK (Side-Channel Closure)
   * ====================================================================
   * Wir lesen IMMER eine Hardware-eFuse, um Power/Timing-Analysen zu
   * verhindern. Branchless Math für den Index, um SPA Leaks beim
   * Bedingungs-Sprung zu meiden.
   */
  uint8_t next_idx = (uint8_t)(local_env.key_index + (local_env.key_index < 255));

  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  boot_status_t next_key_stat = platform->crypto->read_pubkey(
      dummy_pubkey, sizeof(dummy_pubkey), next_idx);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  /* Hardware-Defekte / Timeout: Dürfen kein Downgrade freischalten!
   * Nur wenn der Slot definitiv leer (NOT_FOUND) ist, ist der aktuelle Key der
   * Neueste. */
  if (next_key_stat != BOOT_OK && next_key_stat != BOOT_ERR_NOT_FOUND) {
    final_status = next_key_stat;
    goto cleanup;
  }

  /* Wenn der angefragte Index < 255 ist und der nächste Slot gültig ist,
     handelt es sich um einen revozierten Key -> Downgrade-Versuch! */
  volatile uint32_t downgrade_shield_1 = 0;
  volatile uint32_t downgrade_shield_2 = 0;

  bool is_max_key = (local_env.key_index == 255);
  bool next_key_absent = (next_key_stat == BOOT_ERR_NOT_FOUND);

  if (is_max_key || next_key_absent) {
    downgrade_shield_1 = BOOT_OK;
  }

  BOOT_GLITCH_DELAY(); /* Glitch Delay Injection */

  if (downgrade_shield_1 == BOOT_OK && (is_max_key || next_key_absent)) {
    downgrade_shield_2 = BOOT_OK;
  }

  if (downgrade_shield_1 != BOOT_OK || downgrade_shield_2 != BOOT_OK ||
      downgrade_shield_1 != downgrade_shield_2) {
    final_status =
        BOOT_ERR_DOWNGRADE; /* Downgrade Attack physikalisch identifiziert! */
    goto cleanup;
  }

  execution_path ^= CFI_VERIFY_STEP_2; /* Schritt 2 erfolgreich bewiesen */

  /* ====================================================================
   * 4. HARDWARE ROOT-OF-TRUST EXTRACTION (Glitch-Hardened)
   * ====================================================================
   * FIX: Verhindert den fatalen All-Zero Key Exploit! Ohne diesen Double-Check
   * könnte ein Glitch den Error-Branch überspringen und verify_ed25519 mit
   * dem genullten root_pubkey Puffer füttern.
   */
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  boot_status_t key_stat = platform->crypto->read_pubkey(
      root_pubkey, sizeof(root_pubkey), local_env.key_index);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  volatile uint32_t key_shield_1 = 0;
  volatile uint32_t key_shield_2 = 0;

  if (key_stat == BOOT_OK) {
    key_shield_1 = BOOT_OK;
  }

  BOOT_GLITCH_DELAY(); /* EMFI Instruction Skip Protection */

  if (key_shield_1 == BOOT_OK && key_stat == BOOT_OK) {
    key_shield_2 = BOOT_OK;
  }

  if (key_shield_1 != BOOT_OK || key_shield_2 != BOOT_OK ||
      key_shield_1 != key_shield_2) {
    final_status = (key_stat != BOOT_OK) ? key_stat : BOOT_ERR_VERIFY;
    goto cleanup;
  }

  /* BEWEIS DER KRYPTOGRAFISCHEN IDENTITÄT:
   * Verhindert Ed25519 "All-Zero Key" / "All-xFF" Trivial-Forging Exploits */
  if (verify_not_all_zeros_glitch_safe(root_pubkey, sizeof(root_pubkey)) !=
      BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  execution_path ^= CFI_VERIFY_STEP_3; /* Schritt 3 erfolgreich bewiesen */

  /* ====================================================================
   * 5. ENVELOPE-FIRST ED25519 VERIFICATION (Glitch Hardened)
   * ==================================================================== */
  volatile uint32_t ed_secure_flag_1 = 0;
  volatile uint32_t ed_secure_flag_2 = 0;

  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  boot_status_t verify_stat = platform->crypto->verify_ed25519(
      work_buffer, local_env.manifest_size, local_env.signature_ed25519,
      root_pubkey);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  /* DPA MINIMIZATION: Wir schreddern den Root Key SOFORT nach dem
   * Signatur-Check! Er darf keine Makrosekunde länger als zwingend nötig im RAM
   * verweilen. */
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));

  if (verify_stat == BOOT_OK) {
    ed_secure_flag_1 = BOOT_OK;
  }

  BOOT_GLITCH_DELAY(); /* Branch-Skip Mitigation */

  if (ed_secure_flag_1 == BOOT_OK && verify_stat == BOOT_OK) {
    ed_secure_flag_2 = BOOT_OK;
  }

  if (ed_secure_flag_1 != BOOT_OK || ed_secure_flag_2 != BOOT_OK ||
      ed_secure_flag_1 != ed_secure_flag_2) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  execution_path ^= CFI_VERIFY_STEP_4; /* Schritt 4 erfolgreich bewiesen */

  /* ====================================================================
   * 6. POST-QUANTUM HYBRID ENFORCEMENT (Bypass Shielded)
   * ==================================================================== */
  volatile uint32_t pqc_req_shield_1 = 0;
  volatile uint32_t pqc_req_shield_2 = 0;

  bool pqc_enforced = false;
  if (platform->crypto->is_pqc_enforced) {
    pqc_enforced = platform->crypto->is_pqc_enforced();
  }

  if (pqc_enforced || local_env.pqc_hybrid_active) {
    pqc_req_shield_1 = BOOT_OK;
  }

  BOOT_GLITCH_DELAY();

  if (pqc_req_shield_1 == BOOT_OK &&
      (pqc_enforced || local_env.pqc_hybrid_active)) {
    pqc_req_shield_2 = BOOT_OK;
  }

  bool pqc_required_proven =
      (pqc_req_shield_1 == BOOT_OK && pqc_req_shield_2 == BOOT_OK &&
       pqc_req_shield_1 == pqc_req_shield_2);

  /* Anti-Glitch: Wenn die HW PQC erzwingt, aber die Schilde korrumpiert wurden
   * -> Halt! */
  if (pqc_enforced && !pqc_required_proven) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  if (pqc_required_proven) {
    if (!platform->crypto->verify_pqc) {
      final_status = BOOT_ERR_NOT_SUPPORTED;
      goto cleanup;
    }

    if (!local_env.signature_pqc || local_env.signature_pqc_len == 0 ||
        !local_env.pubkey_pqc || local_env.pubkey_pqc_len == 0) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    /* MATHEMATISCHER POINTER-BEWEIS (CVE Defense):
     * Wir beweisen mathematisch UB-frei, dass der vom Parser übergebene
     * PQC-Key-Pointer und Signatur-Pointer physisch innerhalb des durch Ed25519
     * signierten SRAM-Buffers liegen! */
    bool pqc_pub_ok =
        is_buffer_within(local_env.pubkey_pqc, local_env.pubkey_pqc_len,
                         work_buffer, local_env.manifest_size);
    bool pqc_sig_ok =
        is_buffer_within(local_env.signature_pqc, local_env.signature_pqc_len,
                         work_buffer, local_env.manifest_size);

    volatile uint32_t pqc_b_shield_1 = 0, pqc_b_shield_2 = 0;
    if (pqc_pub_ok && pqc_sig_ok)
      pqc_b_shield_1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (pqc_b_shield_1 == BOOT_OK && pqc_pub_ok && pqc_sig_ok)
      pqc_b_shield_2 = BOOT_OK;

    if (pqc_b_shield_1 != BOOT_OK || pqc_b_shield_2 != BOOT_OK ||
        pqc_b_shield_1 != pqc_b_shield_2) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    /* ZERO-KEY FORGERY DEFENSE für PQC Algorithmen */
    if (verify_not_all_zeros_glitch_safe(local_env.pubkey_pqc,
                                         local_env.pubkey_pqc_len) != BOOT_OK) {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    volatile uint32_t pqc_secure_flag_1 = 0;
    volatile uint32_t pqc_secure_flag_2 = 0;

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    boot_status_t pqc_stat = platform->crypto->verify_pqc(
        work_buffer, local_env.manifest_size, local_env.signature_pqc,
        local_env.signature_pqc_len, local_env.pubkey_pqc,
        local_env.pubkey_pqc_len);
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    if (pqc_stat == BOOT_OK) {
      pqc_secure_flag_1 = BOOT_OK;
    }

    BOOT_GLITCH_DELAY();

    if (pqc_secure_flag_1 == BOOT_OK && pqc_stat == BOOT_OK) {
      pqc_secure_flag_2 = BOOT_OK;
    }

    if (pqc_secure_flag_1 != BOOT_OK || pqc_secure_flag_2 != BOOT_OK ||
        pqc_secure_flag_1 != pqc_secure_flag_2) {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    execution_path ^=
        CFI_VERIFY_STEP_5; /* Schritt 5 (PQC) erfolgreich bewiesen */
  } else {
    /* NEGATIVE CFI ROUTING: Beweist physikalisch, dass PQC legitimerweise
     * übersprungen wurde! */
    volatile uint32_t skip_shield_1 = 0;
    volatile uint32_t skip_shield_2 = 0;

    if (!pqc_enforced && !local_env.pqc_hybrid_active)
      skip_shield_1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (skip_shield_1 == BOOT_OK && !pqc_enforced &&
        !local_env.pqc_hybrid_active)
      skip_shield_2 = BOOT_OK;

    if (skip_shield_1 != BOOT_OK || skip_shield_2 != BOOT_OK ||
        skip_shield_1 != skip_shield_2) {
      final_status = BOOT_ERR_VERIFY; /* Trapped Glitch trying to skip PQC! */
      goto cleanup;
    }
    execution_path ^=
        CFI_VERIFY_STEP_5_SKIP; /* Negativer Pfad (Kein PQC) bewiesen */
  }

  /* ====================================================================
   * 7. CONTROL FLOW INTEGRITY (CFI) RESOLUTION
   * ==================================================================== */
  /* Berechne das erwartete kryptografische Hamming-Weight, das die CPU
   * am Ende des Durchlaufs im CFI-Akkumulator aufweisen muss. */
  uint32_t expected_path =
      CFI_VERIFY_INIT ^ CFI_VERIFY_STEP_1 ^ CFI_VERIFY_STEP_2 ^
      CFI_VERIFY_STEP_3 ^ CFI_VERIFY_STEP_4 ^
      (pqc_required_proven ? CFI_VERIFY_STEP_5 : CFI_VERIFY_STEP_5_SKIP);

  volatile uint32_t path_check_1 = 0;
  volatile uint32_t path_check_2 = 0;

  if (execution_path == expected_path) {
    path_check_1 = BOOT_OK;
  }

  BOOT_GLITCH_DELAY();

  if (path_check_1 == BOOT_OK && execution_path == expected_path) {
    path_check_2 = BOOT_OK;
  }

  /* Nur wenn der Control Flow lückenlos physisch bewiesen ist UND wir
   * nicht durch ein Goto-Cleanup mit Fehlern hier landeten, entsperren
   * wir den finalen BOOT_OK Status! */
  if (path_check_1 == BOOT_OK && path_check_2 == BOOT_OK &&
      path_check_1 == path_check_2) {
    final_status = BOOT_OK;
  } else {
    final_status = BOOT_ERR_VERIFY;
  }

cleanup:
  /* ====================================================================
   * 8. P10 SINGLE EXIT: SECURE ZEROIZE FALLBACK
   * ====================================================================
   * Unabhängig vom Ausgang werden alle Krypto-Materialien und Metadaten
   * atomar vom Stack radiert. Nichts verlässt diesen Scope intakt.
   */
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));
  boot_secure_zeroize(&local_env, sizeof(local_env));

  return final_status;
}