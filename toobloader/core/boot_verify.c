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
#include "boot_fih.h"
#include "boot_ct_utils.h"
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

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define VERIFY_CFI_SLOT_INIT      0
#define VERIFY_CFI_SLOT_1         1
#define VERIFY_CFI_SLOT_2         2
#define VERIFY_CFI_SLOT_3         3
#define VERIFY_CFI_SLOT_4         4
#define VERIFY_CFI_SLOT_5         5
#define VERIFY_CFI_SLOT_5_SKIP    6
#define VERIFY_CFI_NUM_TOKENS     7




boot_status_t
boot_verify_manifest_envelope(const boot_platform_t *platform,
                              const boot_verify_envelope_t *envelope,
                              uint8_t *work_buffer, size_t work_buf_len) {

  /* ====================================================================
   * 1. P10 ALLOCATION & PESSIMISTIC INITIALIZATION
   * ==================================================================== */
  boot_status_t final_status =
      BOOT_ERR_VERIFY; /* Grundzustand: Kompromittiert / Default-Deny */

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t verify_cfi_seed = 0;
  boot_random_safe(platform, (uint8_t *)&verify_cfi_seed, sizeof(verify_cfi_seed));
  boot_cfi_ctx_t verify_cfi_ctx;
  boot_cfi_init(verify_cfi_ctx, verify_cfi_seed);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_1);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_2);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_3);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_4);

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

  if (!platform->crypto->read_pubkey || !platform->crypto->verify_signature) {
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

  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_1); /* Schritt 1 erfolgreich bewiesen */

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
  bool is_max_key = (local_env.key_index == 255);
  bool next_key_absent = (next_key_stat == BOOT_ERR_NOT_FOUND);

  BOOT_SECURE_REQUIRE(is_max_key || next_key_absent, {
    final_status = BOOT_ERR_DOWNGRADE;
    goto cleanup;
  });

  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_2); /* Schritt 2 erfolgreich bewiesen */

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

  if (boot_secure_confirm(key_stat) != BOOT_OK) {
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

  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_3); /* Schritt 3 erfolgreich bewiesen */

  /* ====================================================================
   * 5. ENVELOPE-FIRST ED25519 VERIFICATION (Glitch Hardened)
   * ==================================================================== */
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();
  boot_status_t verify_stat = platform->crypto->verify_signature(
      work_buffer, local_env.manifest_size, local_env.signature_ed25519,
      root_pubkey);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

#if TOOB_DOUBLE_VERIFY
  /* DOUBLE-EXECUTION: Zweiter, vollständiger Krypto-Aufruf detektiert auch
   * algorithmus-interne Faults (z.B. Glitch im Monocypher Feldmultiplizierer).
   * Trade-off: root_pubkey bleibt ~30ms länger im RAM (dokumentiert in
   * docs/security_model.md, Abschnitt "DPA vs. Glitch-Resistenz"). */
  BOOT_GLITCH_DELAY();
  boot_status_t verify_stat_2 = platform->crypto->verify_signature(
      work_buffer, local_env.manifest_size, local_env.signature_ed25519,
      root_pubkey);
  if (platform->wdt && platform->wdt->kick)
    platform->wdt->kick();

  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));

  BOOT_SECURE_REQUIRE(verify_stat == BOOT_OK && verify_stat_2 == BOOT_OK, {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  });
#else
  /* DPA MINIMIZATION: Root Key wird SOFORT nach dem Signatur-Check geschreddert.
   * Er darf keine Makrosekunde länger als zwingend nötig im RAM verweilen. */
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
#endif

  if (boot_secure_confirm(verify_stat) != BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_4); /* Schritt 4 erfolgreich bewiesen */

  /* ====================================================================
   * 6. POST-QUANTUM HYBRID ENFORCEMENT (Bypass Shielded)
   * ==================================================================== */
#if TOOB_PQC_ENABLED
  bool pqc_enforced = false;
  if (platform->crypto->is_pqc_enforced) {
    pqc_enforced = platform->crypto->is_pqc_enforced();
  }

  bool pqc_required_proven = false;
  if (pqc_enforced || local_env.pqc_hybrid_active) {
    BOOT_SECURE_REQUIRE(pqc_enforced || local_env.pqc_hybrid_active, {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    });
    pqc_required_proven = true;
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

    BOOT_SECURE_REQUIRE(pqc_pub_ok && pqc_sig_ok, {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    });

    /* ZERO-KEY FORGERY DEFENSE für PQC Algorithmen */
    if (verify_not_all_zeros_glitch_safe(local_env.pubkey_pqc,
                                         local_env.pubkey_pqc_len) != BOOT_OK) {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    boot_status_t pqc_stat = platform->crypto->verify_pqc(
        work_buffer, local_env.manifest_size, local_env.signature_pqc,
        local_env.signature_pqc_len, local_env.pubkey_pqc,
        local_env.pubkey_pqc_len);
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    if (boot_secure_confirm(pqc_stat) != BOOT_OK) {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_5);
    boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_5); /* Schritt 5 (PQC) erfolgreich bewiesen */
  } else {
    /* NEGATIVE CFI ROUTING: Beweist physikalisch, dass PQC legitimerweise
     * übersprungen wurde! */
    BOOT_SECURE_REQUIRE(!pqc_enforced && !local_env.pqc_hybrid_active, {
      final_status = BOOT_ERR_VERIFY; /* Trapped Glitch trying to skip PQC! */
      goto cleanup;
    });
    boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP);
    boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP); /* Negativer Pfad (Kein PQC) bewiesen */
  }
#else
  /* P7d: PQC nicht konfiguriert — statischer SKIP-Pfad.
   * CFI: Negativer Pfad beweisen, damit der Akkumulator konsistent bleibt. */
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP);
  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP);
#endif

  /* ====================================================================
   * 7. CONTROL FLOW INTEGRITY (CFI) RESOLUTION
   * ==================================================================== */
  boot_cfi_require(verify_cfi_ctx, {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  });
  final_status = BOOT_OK;

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