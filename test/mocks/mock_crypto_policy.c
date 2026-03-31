/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Crypto Policy Implementation (--wrap)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS & GAPS:
 * 
 * 1. docs/testing_requirements.md
 *    - Zero Code Slop: Link-Time Mocking statt #ifdef DEV_MODE.
 *      Diese Datei fängt `crypto_hal.verify_ed25519` über den GNU-Linker ab
 *      und liefert blind ein TOOB_OK zurück, falls das Environment TOOB_BYPASS_CRYPTO=1 ist,
 *      um massiven Fuzzing-Overhead zu vermeiden.
 * 
 * 2. docs/hals.md
 *    - Erlaubt das Testen falscher Crypto-Payloads durch Fault-Injection
 *      ohne echtes Monocypher auszuführen.
 * 
 * TODO: Füge __wrap_verify_ed25519 und Umgebungsvariablen-Check ein.
 */

#include "mock_crypto_policy.h"

// TODO: __wrap Routine
