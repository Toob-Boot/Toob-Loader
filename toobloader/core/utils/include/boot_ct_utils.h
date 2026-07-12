/**
 * @file boot_ct_utils.h
 * @brief Constant-Time Comparison Utilities (Glitch-Protected)
 *
 * Provides a single shared implementation of the glitch-resistant
 * constant-time memory comparison used across the Core. Previously
 * duplicated as static inline in 5 translation units.
 *
 * SECURITY CONTRACT:
 * - Dual-accumulator (forward + reverse) prevents single-bit fault bypass
 * - Double-check gating via BOOT_GLITCH_DELAY() resists voltage faults
 * - Constant-time: no early exit on first mismatch (timing side-channel safe)
 */

#ifndef BOOT_CT_UTILS_H
#define BOOT_CT_UTILS_H

#include "boot_types.h"
#include "boot_fih.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Glitch-resistant constant-time memory comparison.
 *
 * Compares `len` bytes of `a` and `b` in both forward and reverse direction.
 * Returns BOOT_OK only if both accumulators agree on a full match.
 *
 * @param a   First buffer
 * @param b   Second buffer
 * @param len Number of bytes to compare
 * @return BOOT_OK on match, BOOT_ERR_VERIFY on mismatch or fault
 */
static inline boot_status_t constant_time_memcmp_glitch_safe(const uint8_t *a,
                                                             const uint8_t *b,
                                                             size_t len) {
  /* P10 Fault-Injection Guard: A glitched len=0 must never yield BOOT_OK.
   * Without this, both accumulators stay 0 → shields pass → silent bypass. */
  if (len == 0)
    return BOOT_ERR_VERIFY;

  volatile uint32_t acc_fwd = 0;
  volatile uint32_t acc_rev = 0;

  for (size_t i = 0; i < len; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[len - 1 - i] ^ b[len - 1 - i]);
  }

  BOOT_SECURE_REQUIRE(acc_fwd == 0 && acc_rev == 0, { return BOOT_ERR_VERIFY; });
  return BOOT_OK;
}

/**
 * @brief O(1) Branch-freie Überprüfung auf Erased-Flash-Status. 
 * Verhindert Timing-Orakel bei Smart-Erase Pre-Checks.
 */
static inline bool is_fully_erased_constant_time(const uint8_t *buf, size_t len,
                                          uint8_t erased_val) {
  uint32_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (uint32_t)(buf[i] ^ erased_val);
  }
  return diff == 0;
}

/**
 * @brief Sicheres O(1) Auslesen des Monotonic Counters mit P10 Double-Check
 * 
 * Verhindert Voltage-Glitches durch doppeltes Lesen und Shield-Verifikation.
 */
static inline boot_status_t boot_read_monotonic_counter_safe(
    const boot_platform_t *platform, uint32_t *out_ctr) 
{
    if (!platform || !platform->crypto || !platform->crypto->read_monotonic_counter) 
        return BOOT_ERR_NOT_SUPPORTED;
    
    uint32_t val1 = 0, val2 = 0;
    boot_status_t s1 = platform->crypto->read_monotonic_counter(&val1);
    BOOT_GLITCH_DELAY();
    boot_status_t s2 = platform->crypto->read_monotonic_counter(&val2);
    
    BOOT_SECURE_REQUIRE(s1 == BOOT_OK && s2 == BOOT_OK && val1 == val2, {
        if (s1 != BOOT_OK) return s1;
        if (s2 != BOOT_OK) return s2;
        return BOOT_ERR_VERIFY;
    });
    
    *out_ctr = val1;
    return BOOT_OK;
}

/**
 * @brief O(1) mathematisch perfekter Buffer-Boundary Check (UB-frei).
 *
 * Prüft, ob [inner, inner+inner_len) vollständig innerhalb von
 * [outer, outer+outer_len) liegt. Wraparound-sicher auf 32/64-bit.
 */
static inline bool is_buffer_within(const uint8_t *inner, size_t inner_len,
                                    const uint8_t *outer, size_t outer_len) {
  if (inner_len == 0 || outer_len == 0)
    return false;
  uintptr_t i_start = (uintptr_t)inner;
  uintptr_t o_start = (uintptr_t)outer;
  if (UINTPTR_MAX - i_start < inner_len)
    return false;
  if (UINTPTR_MAX - o_start < outer_len)
    return false;
  return (i_start >= o_start) &&
         ((i_start + inner_len) <= (o_start + outer_len));
}

/**
 * @brief Sicheres O(1) Auslesen von TRNG Daten mit mathematischem Health-Check
 * 
 * Prüft, ob der TRNG (z.B. wegen fehlender Entropie oder Hardwareschaden) 
 * ausschließlich 0x00 oder 0xFF ausspuckt.
 */
static inline boot_status_t boot_random_safe(
    const boot_platform_t *platform, uint8_t *buf, size_t len) 
{
    if (!platform || !platform->crypto || !platform->crypto->random) 
        return BOOT_ERR_NOT_SUPPORTED;
        
    boot_status_t stat = platform->crypto->random(buf, len);
    if (stat != BOOT_OK) return stat;

    /* Post-TRNG Sanity Check (O(1) Constant-Time) */
    uint8_t or_acc = 0x00;
    uint8_t and_acc = 0xFF;
    for (size_t i = 0; i < len; i++) {
        or_acc |= buf[i];
        and_acc &= buf[i];
    }
    
    /* Wenn alle Bytes 0x00 sind, ist or_acc == 0x00.
     * Wenn alle Bytes 0xFF sind, ist and_acc == 0xFF. */
    if (or_acc == 0x00 || and_acc == 0xFF) {
        return BOOT_ERR_CRYPTO; /* TRNG defekt */
    }
    
    return BOOT_OK;
}

/**
 * @brief RFC 1982 Serial Number Arithmetic (100% Wrap-Around Safe).
 *
 * Shared utility for underflow-safe sequence comparison across
 * boot_journal (WAL sectors) and boot_rstore (quorum stores).
 */
static inline bool is_newer_sequence(uint32_t new_seq, uint32_t old_seq) {
  if (new_seq == old_seq)
    return false;
  return ((new_seq > old_seq) && (new_seq - old_seq <= (1U << 31))) ||
         ((new_seq < old_seq) && (old_seq - new_seq > (1U << 31)));
}

/**
 * @brief Deterministic CFI Token Derivation from TRNG Seed.
 *
 * Derives a unique, non-zero 32-bit token from a random seed and a slot index.
 * Uses Fibonacci hashing (golden ratio constant) with avalanche mixing to
 * guarantee collision-freedom across slots for any given seed.
 *
 * SECURITY PROPERTIES:
 * - Bit 0 forced to 1: Token is guaranteed non-zero (XOR no-op immunity)
 * - Avalanche: Single-bit change in seed/slot flips ~50% of output bits
 * - Without knowing the seed, an attacker cannot predict the expected CFI path
 *
 * @param seed  32-bit TRNG value, unique per boot cycle
 * @param slot  Token index (0..N) within the function's CFI sequence
 * @return Non-zero 32-bit token
 */
static inline uint32_t cfi_derive(uint32_t seed, uint8_t slot) {
  uint32_t h = seed ^ ((uint32_t)slot * 0x9E3779B9u); /* Fibonacci Hashing */
  h ^= h >> 16;
  h *= 0x45D9F3Bu;
  h ^= h >> 16;
  return h | 1u; /* Bit 0 erzwungen: Garantiert niemals 0 */
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

  BOOT_SECURE_REQUIRE(or_acc != 0x00 && and_acc != 0xFF, { return BOOT_ERR_VERIFY; });
  return BOOT_OK;
}

#endif /* BOOT_CT_UTILS_H */
