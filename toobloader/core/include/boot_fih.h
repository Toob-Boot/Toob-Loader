#ifndef BOOT_FIH_H
#define BOOT_FIH_H

#include "boot_types.h"

#ifdef TOOB_MOCK_TEST
#include <stdbool.h>
extern volatile int g_fault_trigger_count;
extern volatile int g_fault_target_index;
extern bool should_inject_fault(void);
#else
static inline bool should_inject_fault(void) { return false; }
#endif

/* 
 * Fall 1: re-evaluierbare, NEBENWIRKUNGSFREIE Bedingung (reine Arithmetik/Vergleich).
 * Der Ausdruck wird ABSICHTLICH zweimal evaluiert (liest die zugrunde liegenden
 * Werte erneut -> fängt Glitches auf dem Wert, nicht nur auf der Zuweisung).
 * VERTRAG: expr MUSS seiteneffektfrei und billig re-evaluierbar sein.
 */
#define BOOT_SECURE_REQUIRE(expr, on_fault)                       \
    do {                                                          \
        volatile uint32_t _s1 = 0, _s2 = 0;                       \
        bool _inject = should_inject_fault();                     \
        if ((expr) && !_inject) _s1 = BOOT_OK;                    \
        BOOT_GLITCH_DELAY();                                      \
        if (_s1 == BOOT_OK && (expr) && !_inject) _s2 = BOOT_OK;  \
        if (_s1 != BOOT_OK || _s2 != BOOT_OK || _s1 != _s2)       \
            { on_fault; }                                         \
    } while (0)

/*
 * Fall 2: EINMALIGES Ergebnis, das nicht billig wiederholbar ist
 * (z. B. ein HAL-Crypto-Verify, ein eFuse-Read). Hier wird der
 * gespeicherte Status doppelt gegen das Verdict geprüft. Schwächer als
 * Fall 1, aber unvermeidbar — und JETZT explizit als solcher benannt.
 */
static inline boot_status_t boot_secure_confirm_impl(boot_status_t one_shot_status, bool inject) {
    volatile uint32_t s1 = 0, s2 = 0;
    if (one_shot_status == BOOT_OK && !inject) s1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (s1 == BOOT_OK && one_shot_status == BOOT_OK && !inject) s2 = BOOT_OK;
    if (s1 == BOOT_OK && s2 == BOOT_OK && s1 == s2) return BOOT_OK;
    return BOOT_ERR_VERIFY;
}

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

// We use the cfi_derive function (defined in boot_ct_utils.h)
// Let's include boot_ct_utils.h at the end of boot_fih.h to avoid circular dependency.
#include "boot_ct_utils.h"

#define boot_cfi_init(ctx, seed_val) do { \
    (ctx).seed = (seed_val); \
    (ctx).current_val = cfi_derive((ctx).seed, 0); \
    (ctx).expected_val = cfi_derive((ctx).seed, 0); \
} while(0)

#define boot_cfi_step(ctx, slot) do { \
    (ctx).current_val ^= cfi_derive((ctx).seed, (slot)); \
} while(0)

#define boot_cfi_add_expected(ctx, slot) do { \
    (ctx).expected_val ^= cfi_derive((ctx).seed, (slot)); \
} while(0)

#define boot_cfi_require(ctx, on_fault) do { \
    volatile uint32_t _cfi_s1 = 0, _cfi_s2 = 0; \
    bool _inject = should_inject_fault(); \
    if ((ctx).current_val == (ctx).expected_val && !_inject) _cfi_s1 = BOOT_OK; \
    BOOT_GLITCH_DELAY(); \
    if (_cfi_s1 == BOOT_OK && (ctx).current_val == (ctx).expected_val && !_inject) _cfi_s2 = BOOT_OK; \
    if (_cfi_s1 != BOOT_OK || _cfi_s2 != BOOT_OK || _cfi_s1 != _cfi_s2) { \
        on_fault; \
    } \
} while(0)

#endif /* BOOT_FIH_H */
