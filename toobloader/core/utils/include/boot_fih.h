#ifndef BOOT_FIH_H
#define BOOT_FIH_H

#include "boot_types.h"
#include <stdbool.h>

#ifdef TOOB_MOCK_TEST
extern volatile int g_fault_trigger_count;
extern volatile int g_fault_target_index;
extern bool should_inject_fault(void);
#else
static inline bool should_inject_fault(void) {
  return false;
}
#endif

/* 
 * Fall 1: re-evaluierbare, NEBENWIRKUNGSFREIE Bedingung (reine Arithmetik/Vergleich).
 * Der Ausdruck wird ABSICHTLICH zweimal evaluiert (liest die zugrunde liegenden
 * Werte erneut -> fängt Glitches auf dem Wert, nicht nur auf der Zuweisung).
 * VERTRAG: expr MUSS seiteneffektfrei und billig re-evaluierbar sein.
 */
#define BOOT_SECURE_REQUIRE(expr, on_fault)                                                        \
  do {                                                                                             \
    volatile uint32_t fih_s1 = 0U;                                                                 \
    volatile uint32_t fih_s2 = 0U;                                                                 \
    bool fih_inj = should_inject_fault();                                                          \
    if ((expr) && !fih_inj) {                                                                      \
      fih_s1 = BOOT_OK;                                                                            \
    }                                                                                              \
    BOOT_GLITCH_DELAY();                                                                           \
    if (fih_s1 == BOOT_OK && (expr) && !fih_inj) {                                                 \
      fih_s2 = BOOT_OK;                                                                            \
    }                                                                                              \
    if (fih_s1 != BOOT_OK || fih_s2 != BOOT_OK || fih_s1 != fih_s2) {                              \
      on_fault;                                                                                    \
    }                                                                                              \
  } while (0)

/*
 * Fall 2: EINMALIGES Ergebnis, das nicht billig wiederholbar ist
 * (z. B. ein HAL-Crypto-Verify, ein eFuse-Read). Hier wird der
 * gespeicherte Status doppelt gegen das Verdict geprüft. Schwächer als
 * Fall 1, aber unvermeidbar — und JETZT explizit als solcher benannt.
 */
boot_status_t boot_secure_confirm_impl(boot_status_t one_shot_status, bool inject);

#ifdef TOOB_MOCK_TEST
#define boot_secure_confirm(status) boot_secure_confirm_impl((status), should_inject_fault())
#else
#define boot_secure_confirm(status) boot_secure_confirm_impl((status), false)
#endif

/* CFI Context Tracker */
typedef struct {
  uint32_t seed;
  uint32_t current_val;
  uint32_t expected_val;
} boot_cfi_ctx_t;

static inline uint32_t cfi_derive(uint32_t seed, uint8_t slot) {
  uint32_t h = seed ^ ((uint32_t)slot * 0x9E3779B9U);
  h ^= h >> 16U;
  h *= 0x45D9F3BU;
  h ^= h >> 16U;
  return h | 1U;
}

static inline uint32_t boot_cfi_mix_val(uint32_t acc, uint32_t token) {
  uint32_t rot = (acc << 7U) | (acc >> 25U);
  return rot ^ token;
}

#define boot_cfi_init(ctx, seed_val)                                                               \
  do {                                                                                             \
    (ctx).seed = (seed_val);                                                                       \
    (ctx).current_val = cfi_derive((ctx).seed, 0U);                                                \
    (ctx).expected_val = cfi_derive((ctx).seed, 0U);                                               \
  } while (0)

#define boot_cfi_step(ctx, slot)                                                                   \
  do {                                                                                             \
    (ctx).current_val =                                                                            \
        boot_cfi_mix_val((ctx).current_val, cfi_derive((ctx).seed, (uint8_t)(slot)));              \
  } while (0)

#define boot_cfi_add_expected(ctx, slot)                                                           \
  do {                                                                                             \
    (ctx).expected_val =                                                                           \
        boot_cfi_mix_val((ctx).expected_val, cfi_derive((ctx).seed, (uint8_t)(slot)));             \
  } while (0)

#define boot_cfi_require(ctx, on_fault)                                                            \
  do {                                                                                             \
    volatile uint32_t cfi_s1 = 0U;                                                                 \
    volatile uint32_t cfi_s2 = 0U;                                                                 \
    bool cfi_inj = should_inject_fault();                                                          \
    if ((ctx).current_val == (ctx).expected_val && !cfi_inj) {                                     \
      cfi_s1 = BOOT_OK;                                                                            \
    }                                                                                              \
    BOOT_GLITCH_DELAY();                                                                           \
    if (cfi_s1 == BOOT_OK && (ctx).current_val == (ctx).expected_val && !cfi_inj) {                \
      cfi_s2 = BOOT_OK;                                                                            \
    }                                                                                              \
    if (cfi_s1 != BOOT_OK || cfi_s2 != BOOT_OK || cfi_s1 != cfi_s2) {                              \
      on_fault;                                                                                    \
    }                                                                                              \
  } while (0)

#endif /* BOOT_FIH_H */
