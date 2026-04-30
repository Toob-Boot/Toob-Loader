/*
 * Toob-Boot Stage 0: stage0_main.c
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md (Immutable Core)
 *
 * TODO (Architecture Requirements):
 * - Bounds-Validierung: Überprüfen, ob der Ziel-Pointer strikt innerhalb von S1A_BASE <= ptr <= S1B_END liegt.
 * - Magic-Header Check: Prüfen des 4-Byte Magic-Headers (0x544F4F42 / "TOOB"), um Jumps in korrupten Speicher zu blockieren.
 * - Boot-Delegation: Kontrollierte Übergabe (Jump) an Stage 1 Bank A oder B nach erfolgreicher stage0_verify Freigabe.
 */
static void stage0_main_dummy(void) __attribute__((used));
static void stage0_main_dummy(void) {}
