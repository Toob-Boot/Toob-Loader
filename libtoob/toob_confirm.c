/**
 * ==============================================================================
 * Toob-Boot libtoob: Update Confirmation Implementation (toob_confirm.c)
 * (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (toob_confirm_boot API behavior and COMMITTED flag
 * specification)
 * - docs/concept_fusion.md (TENTATIVE -> COMMITTED state transition logic)
 * - docs/hals.md (Confirm abstracting - RTC RAM vs. WAL Append)
 * - docs/structure_plan.md (Zero-dependency policy: No access to
 * boot_journal.h)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Blind-Write Elimination: Hardware RTC Register Writes werden nun durch
 *    ein striktes Phase-Bound Read-Back Verify gesichert.
 * 2. Glitch-Resistant Verification: Der Register-Check ist via Double-Check
 *    und Cross-Compiler Delay-Barrieren vor Voltage Faults geschützt.
 * 3. Stack Leakage Defense: Kryptografische Nonces und WAL Intents werden
 *    zwingend via toob_secure_zeroize vom OS-C-Stack radiert (P10 Single-Exit).
 * 4. P10 Memory Alignment: Zwingt alle Payload-Structs auf 8-Byte Boundaries,
 *    um SPI-DMA UsageFaults (Unaligned Access) in der Feature-OS HAL zu meiden.
 */

#include "libtoob.h"
#include "libtoob_config_sandbox.h"
#include "toob_internal.h"
#include <stddef.h>
#include <string.h>

/* ==============================================================================
 * Cross-Compiler Glitch-Delay Injection für Fault-Injection (FI) Defense
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
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    volatile uint32_t _delay = 0;                                              \
    _delay = 1;                                                                \
    (void)_delay;                                                              \
  } while (0)
#endif

#if TOOB_MOCK_CONFIRM_BACKEND == TOOB_MOCK_CONFIRM_BACKEND_RTC
/* Instanziiert den x86 Dummy-Pointer zur Laufzeit, um Segfaults auf dem OS-Host
 * zu verhindern */
uint64_t mock_rtc_ram = 0;
#endif

/* ==============================================================================
 * INTERNAL HELPERS
 * ==============================================================================
 */

/**
 * @brief OS-Safe Memory Zeroization (Prevents Compiler DCE).
 * Verhindert das "Liegenbleiben" kryptografischer Nonces im OS-RAM.
 */
static inline void toob_secure_zeroize(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len--) {
    *p++ = 0;
  }
}

/* ==============================================================================
 * PUBLIC API IMPLEMENTATION
 * ==============================================================================
 */

toob_status_t toob_confirm_boot(void) {
  /* P10 8-Byte Alignment für DMA/Cortex-M Safety */
  toob_handoff_t handoff __attribute__((aligned(8)));
  toob_secure_zeroize(&handoff,
                      sizeof(handoff)); /* P10 Uninitialized Mem Trap */

  /* Schritt 1: Hole verifizierte Nonce über Handoff-API (Anti-Replay) */
  toob_status_t status = toob_get_handoff(&handoff);

  /* P10 Glitch Protection: Fehler-Propagation absichern */
  volatile uint32_t get_shield_1 = 0, get_shield_2 = 0;
  if (status == TOOB_OK)
    get_shield_1 = TOOB_OK;
  TOOB_GLITCH_DELAY();
  if (get_shield_1 == TOOB_OK && status == TOOB_OK)
    get_shield_2 = TOOB_OK;

  if (get_shield_1 != TOOB_OK || get_shield_2 != TOOB_OK ||
      get_shield_1 != get_shield_2) {
    toob_secure_zeroize(&handoff, sizeof(handoff));
    return (status != TOOB_OK) ? status : TOOB_ERR_VERIFY;
  }

#ifdef ADDR_CONFIRM_RTC_RAM
  /* ====================================================================
   * Pfad A: Direkter Write bei Hardware mit Backup-Registern/RTC
   * ====================================================================
   * Zwingendes Volatile-Casting, um C-Optimizer (z.B. GCC -O3) beim
   * Hardware-Write zu blockieren!
   */
  volatile uint64_t *rtc_ptr = (volatile uint64_t *)ADDR_CONFIRM_RTC_RAM;

  /* Hardware Write */
  *rtc_ptr = handoff.boot_nonce;

  /* Memory Barrier: Erzwingt das Flushen der CPU-Write-Buffer auf den
   * Systembus, BEVOR wir den Read-Back initiieren! */
#if defined(__GNUC__) || defined(__clang__)
  __sync_synchronize();
#endif

  /* PHASE-BOUND READ-BACK VERIFY (Tearing / Hardware-Fault Defense)
   * Verhindert OS-Lockouts durch stille SPI/Bus Write-Fehler in die RTC
   * Peripherie! */
  uint64_t verified_nonce = *rtc_ptr;

  volatile uint32_t rtc_shield_1 = 0;
  volatile uint32_t rtc_shield_2 = 0;

  if (verified_nonce == handoff.boot_nonce) {
    rtc_shield_1 = TOOB_OK;
  }

  TOOB_GLITCH_DELAY(); /* Branch-Skip Mitigation */

  if (rtc_shield_1 == TOOB_OK && verified_nonce == handoff.boot_nonce) {
    rtc_shield_2 = TOOB_OK;
  }

  /* Data-Privacy: Nonce sofort vernichten, bevor wir returnen! */
  toob_secure_zeroize(&handoff, sizeof(handoff));

  if (rtc_shield_1 != TOOB_OK || rtc_shield_2 != TOOB_OK ||
      rtc_shield_1 != rtc_shield_2) {
    return TOOB_ERR_FLASH_HW; /* Hardware Backup Domain Failed (Bus Error /
                                 Glitch) */
  }

  return TOOB_OK;
#else
  toob_status_t final_stat = TOOB_ERR_VERIFY;
  /* ====================================================================
   * Pfad B: Naive WAL Append
   * ====================================================================
   */
  toob_wal_entry_payload_t intent __attribute__((aligned(8)));
  toob_secure_zeroize(&intent, sizeof(intent));

  intent.magic = TOOB_WAL_ENTRY_MAGIC;
  intent.intent = TOOB_WAL_INTENT_CONFIRM_COMMIT;
  intent.expected_nonce = handoff.boot_nonce;

  /* Naive Delegation (schützt vor Duplikation und Erase-Komplexitaet) */
  toob_status_t app_stat = toob_wal_naive_append(&intent);

  volatile uint32_t wal_shield_1 = 0, wal_shield_2 = 0;
  if (app_stat == TOOB_OK)
    wal_shield_1 = TOOB_OK;
  TOOB_GLITCH_DELAY();
  if (wal_shield_1 == TOOB_OK && app_stat == TOOB_OK)
    wal_shield_2 = TOOB_OK;

  if (wal_shield_1 == TOOB_OK && wal_shield_2 == TOOB_OK &&
      wal_shield_1 == wal_shield_2) {
    final_stat = TOOB_OK;
  } else {
    final_stat = (app_stat != TOOB_OK) ? app_stat : TOOB_ERR_FLASH_HW;
  }

  /* P10 Leakage Defense */
  toob_secure_zeroize(&handoff, sizeof(handoff));
  toob_secure_zeroize(&intent, sizeof(intent));

  return final_stat;
#endif
}

toob_status_t toob_recovery_resolved(void) {
  toob_status_t final_stat = TOOB_ERR_VERIFY;

  toob_wal_entry_payload_t intent __attribute__((aligned(8)));
  toob_secure_zeroize(&intent, sizeof(intent));

  intent.magic = TOOB_WAL_ENTRY_MAGIC;
  intent.intent = TOOB_WAL_INTENT_RECOVERY_RESOLVED;

  toob_status_t append_stat = toob_wal_naive_append(&intent);

  volatile uint32_t wal_shield_1 = 0, wal_shield_2 = 0;
  if (append_stat == TOOB_OK)
    wal_shield_1 = TOOB_OK;
  TOOB_GLITCH_DELAY();
  if (wal_shield_1 == TOOB_OK && append_stat == TOOB_OK)
    wal_shield_2 = TOOB_OK;

  if (wal_shield_1 == TOOB_OK && wal_shield_2 == TOOB_OK &&
      wal_shield_1 == wal_shield_2) {
    final_stat = TOOB_OK;
  } else {
    final_stat = (append_stat != TOOB_OK) ? append_stat : TOOB_ERR_FLASH_HW;
  }

  toob_secure_zeroize(&intent, sizeof(intent)); /* Stack Clean */
  return final_stat;
}

toob_status_t toob_accumulate_net_search(uint32_t active_search_ms) {
  toob_status_t final_stat = TOOB_ERR_VERIFY;

  toob_wal_entry_payload_t intent __attribute__((aligned(8)));
  toob_secure_zeroize(&intent, sizeof(intent));

  intent.magic = TOOB_WAL_ENTRY_MAGIC;
  intent.intent = TOOB_WAL_INTENT_NET_SEARCH_ACCUM;

  /* P10 Spec: Das OS sammelt kontinuierlich und schickt das Delta oder den
   * Totalwert. Wir casten via offset für den dynamischen Accumulator State. */
  intent.offset = active_search_ms;

  toob_status_t append_stat = toob_wal_naive_append(&intent);

  volatile uint32_t wal_shield_1 = 0, wal_shield_2 = 0;
  if (append_stat == TOOB_OK)
    wal_shield_1 = TOOB_OK;
  TOOB_GLITCH_DELAY();
  if (wal_shield_1 == TOOB_OK && append_stat == TOOB_OK)
    wal_shield_2 = TOOB_OK;

  if (wal_shield_1 == TOOB_OK && wal_shield_2 == TOOB_OK &&
      wal_shield_1 == wal_shield_2) {
    final_stat = TOOB_OK;
  } else {
    final_stat = (append_stat != TOOB_OK) ? append_stat : TOOB_ERR_FLASH_HW;
  }

  toob_secure_zeroize(&intent, sizeof(intent)); /* Stack Clean */
  return final_stat;
}