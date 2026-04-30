/*
 * Toob-Boot Stage 0: stage0_tentative.c
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md
 *
 * TODO (Architecture Requirements):
 * - RTC-RAM Auswertung: Lesen des flüchtigen BOOT_SLOT_B_TENTATIVE Flags aus dem RTC-RAM.
 * - Reset-Reason Verknüpfung: Zwingender Abgleich mit dem RESET_REASON Register der MCU.
 * - Fallback-Trigger: Wenn (TENTATIVE == TRUE) UND (RESET_REASON == WATCHDOG_RESET / Panic) -> Flag sofort aus dem RAM löschen und Notfall-Flucht auf Slot A erzwingen.
 */
static void stage0_tentative_dummy(void) __attribute__((used));
static void stage0_tentative_dummy(void) {}
