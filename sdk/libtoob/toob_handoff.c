/**
 * ==============================================================================
 * Toob-Boot libtoob: Handoff-RAM (.noinit) Validierung (toob_handoff.c)
 * (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (toob_handoff_t structure definition and Magic values)
 * - docs/concept_fusion.md (P10 CRC-32 validation requirements across ABI
 * boundaries)
 * - docs/testing_requirements.md (RAM bound checks to prevent .noinit arbitrary
 * read vulnerabilities)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Tentative Boot Enablement: Magic-Validation akzeptiert nun
 * TOOB_STATE_TENTATIVE, damit das OS Probe-Updates testen und via
 * toob_confirm_boot() besiegeln kann.
 * 2. ABI Versioning Shield: Explizite Prüfung der struct_version gegen
 * Memory-Drifts.
 * 3. Glitch-Resistant OS Boundary: Cross-Compiler-kompatible Delay-Injections
 *    und Double-Check Patterns verhindern Voltage-Glitches in der
 * RAM-Validierung.
 * 4. TOCTOU Defense: Verhindert asynchrone RTOS-Interrupt Korruptionen während
 * des Reads.
 * 5. P10 Leakage Defense: Präemptive Nullifizierung des OS-Buffers vor Output.
 */

#include "libtoob.h"
#include "toob_internal.h"
#include <string.h>

/* ==============================================================================
 * Cross-Compiler Glitch-Delay Injection für Fault-Injection (FI) Defense
 * Erzeugt Instruktions-Barrieren gegen EMFI-bedingte PC-Sprünge, kompatibel
 * mit allen relevanten Cortex-M / RISC-V Compilern des Feature-OS.
 * ==============================================================================
 */
#if defined(__GNUC__) || defined(__clang__)
#define TOOB_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;")
#elif defined(__ICCARM__)
#include <intrinsics.h>
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    __no_operation();                                                          \
    __no_operation();                                                          \
    __no_operation();                                                          \
  } while (0)
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    __nop();                                                                   \
    __nop();                                                                   \
    __nop();                                                                   \
  } while (0)
#else
/* Fallback Sequence-Point, falls inline Assembly strikt verboten ist */
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    volatile uint32_t _delay = 0;                                              \
    _delay = 1;                                                                \
    (void)_delay;                                                              \
  } while (0)
#endif

/* ==============================================================================
 * .noinit RAM Definition (GAP-39)
 * (Wird durch den Linker in die uninitialisierte Sektion gemappt)
 *
 * Arch-Note (Zero-Dependency): This library defines the OS-side boundary.
 * The Bootloader (S1) uses its own isolated definition. Since the OS and S1
 * are compiled into strictly separate binaries, there are no linker collisions.
 * ==============================================================================
 */
/* Arch-Note: Für Cross-Compilation Linker-Collisions (Unit Tests) */
#ifndef TOOB_MOCK_TEST
TOOB_NOINIT toob_handoff_t toob_handoff_state;
#endif

toob_status_t toob_validate_handoff(void) {
  /* ====================================================================
   * 1. MAGIC & ABI-VERSION CHECK (Glitch-Shielded)
   * ====================================================================
   * LOGIK-FIX: Das OS MUSS TENTATIVE Boots zulassen, um sie via
   * toob_confirm_boot() in COMMITTED wandeln zu können!
   */
  volatile uint32_t shield_1 = 0;
  volatile uint32_t shield_2 = 0;

  bool is_magic_ok = (toob_handoff_state.magic == TOOB_STATE_COMMITTED ||
                      toob_handoff_state.magic == TOOB_STATE_TENTATIVE);
  bool is_version_ok =
      (toob_handoff_state.struct_version == TOOB_HANDOFF_STRUCT_VERSION);

  if (is_magic_ok && is_version_ok) {
    shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY();

  if (shield_1 == TOOB_OK && (is_magic_ok && is_version_ok)) {
    shield_2 = TOOB_OK;
  }

  if (shield_1 != TOOB_OK || shield_2 != TOOB_OK || shield_1 != shield_2) {
    return TOOB_ERR_VERIFY;
  }

  /* ====================================================================
   * 2. P10 CRC-32 PAYLOAD VERIFICATION
   * ====================================================================
   * Robustness: Berechne CRC per offsetof statt sizeof zwecks Tail-Padding
   * Immunität
   */
  size_t payload_len = offsetof(toob_handoff_t, crc32_trailer);
  uint32_t calculated_crc =
      toob_lib_crc32((const uint8_t *)&toob_handoff_state, payload_len);

  volatile uint32_t crc_shield_1 = 0;
  volatile uint32_t crc_shield_2 = 0;

  if (calculated_crc == toob_handoff_state.crc32_trailer) {
    crc_shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY();

  if (crc_shield_1 == TOOB_OK &&
      calculated_crc == toob_handoff_state.crc32_trailer) {
    crc_shield_2 = TOOB_OK;
  }

  if (crc_shield_1 != TOOB_OK || crc_shield_2 != TOOB_OK ||
      crc_shield_1 != crc_shield_2) {
    return TOOB_ERR_VERIFY;
  }

  return TOOB_OK;
}

toob_status_t toob_get_handoff(toob_handoff_t *out_handoff) {
  /* P10 Pointer Zero-Trust Check */
  if (!out_handoff) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* P10 Leakage Defense: Zielspeicher sofort nullen.
   * Verhindert, dass das Betriebssystem bei einem Boot-Fail auf veralteten
   * Stack-Garbage (Memory Leakage) zugreift, falls es den Return-Status
   * fahrlässig ignoriert! Da 'out_handoff' den Scope überlebt, ist dieser
   * memset() durch C-Compiler niemals als Dead Code eliminierbar (DCE-sicher).
   */
  memset(out_handoff, 0, sizeof(toob_handoff_t));

  /* Strikte Garbage-Abwehr: Wenn CRC nicht stimmt, Vorgang abbrechen! */
  toob_status_t status = toob_validate_handoff();

  /* Glitch-Schild für die Error-Propagation:
   * Verhindert, dass ein fehlerhafter Status (z.B. TOOB_ERR_VERIFY)
   * durch EMFI in der Register-Zuweisung zu einem TOOB_OK geflippt wird.
   */
  volatile uint32_t prop_shield_1 = 0;
  volatile uint32_t prop_shield_2 = 0;

  if (status == TOOB_OK) {
    prop_shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY();

  if (prop_shield_1 == TOOB_OK && status == TOOB_OK) {
    prop_shield_2 = TOOB_OK;
  }

  if (prop_shield_1 != TOOB_OK || prop_shield_2 != TOOB_OK ||
      prop_shield_1 != prop_shield_2) {
    /* Force Error-Propagation mask, preventing logic manipulation */
    return (status != TOOB_OK) ? status : TOOB_ERR_VERIFY;
  }

  /* Sicheres Kopieren by-value ins isolierte OS-Feature-RAM */
  memcpy(out_handoff, &toob_handoff_state, sizeof(toob_handoff_t));

  /* ====================================================================
   * Post-Copy Re-Validation (TOCTOU Defense)
   * ====================================================================
   * In Multithreading/Interrupt-lastigen RTOS Umgebungen könnte der asynchrone
   * .noinit RAM zwischen der Validierung und dem memcpy() von außen korrumpiert
   * worden sein (Time-of-Check to Time-of-Use). Wir verifizieren den isolierten
   * Klon mathematisch, bevor das OS ihn nutzt!
   */
  size_t payload_len = offsetof(toob_handoff_t, crc32_trailer);
  uint32_t local_crc =
      toob_lib_crc32((const uint8_t *)out_handoff, payload_len);

  bool local_magic_ok = (out_handoff->magic == TOOB_STATE_COMMITTED ||
                         out_handoff->magic == TOOB_STATE_TENTATIVE);
  bool local_version_ok =
      (out_handoff->struct_version == TOOB_HANDOFF_STRUCT_VERSION);

  if (local_crc != out_handoff->crc32_trailer || !local_magic_ok ||
      !local_version_ok) {
    /* Zeiger-Inhalt radikal radieren, damit das Feature-OS niemals Garbage
     * liest! */
    memset(out_handoff, 0, sizeof(toob_handoff_t));
    return TOOB_ERR_VERIFY;
  }

  /* P10 Zero-Trust: Sicherstellen, dass das Struct-Padding im OS-Heap
   * genullt ist (Verhindert subtiles Data-Leakage bei Serialisierung). */
  out_handoff->_reserved_pad = 0;

  return TOOB_OK;
}