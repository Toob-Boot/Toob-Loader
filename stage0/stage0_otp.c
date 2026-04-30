/*
 * Toob-Boot Stage 0: stage0_otp.c
 * Relevant Spec-Dateien:
 * - docs/concept_fusion.md
 *
 * TODO (Architecture Requirements):
 * - Key-Index Rotation: Auslesen der OTP-eFuses zur Bestimmung des aktiven Root-Keys.
 * - Burn-Level Evaluation: Fallback auf den nächsten Key-Index, falls der vorherige kompromittiert oder widerrufen wurde.
 * - End-Of-Life Trigger: Meldung an Stage 1 (oder Notfall-Halt), falls der letzte verfügbare Schlüssel-Index in den eFuses aufgebraucht ist.
 */
static void stage0_otp_dummy(void) __attribute__((used));
static void stage0_otp_dummy(void) {}
