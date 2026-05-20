# Toob-Boot Security Model

## Crypto Verification Trust Model

### Stage 0 (Immutable Core)
**Datei:** `stage0_verify.c`

Stage 0 verifiziert die Integrität von Stage 1 per Ed25519. Aufgrund des strikten
Flash-Budgets (4–8 KB) wird **keine** vollständige Double-Execution des
Signaturalgorithmus durchgeführt. Stattdessen wird das Ergebnis durch das
P10-konforme Double-Check-Pattern (`BOOT_GLITCH_DELAY()` + Shield-Verifikation)
abgesichert.

**Residual-Risiko:** Ein krypto-interner Fault (z.B. im Monocypher-Algorithmus
selbst) könnte ein einzelnes falsches `0` produzieren. Dieses Risiko wird durch
den TRNG-Jitter in den DSLC-Reads (Phase 4) und die physikalische Immutabilität
von Stage 0 (eFuse-geschützt) hinreichend mitigiert.

### Stage 1 (Mutable Core Engine)
**Dateien:** `boot_verify.c`, `boot_cloud_cmd.c`, `boot_panic.c`

Stage 1 implementiert das Double-Check-Pattern für alle kryptografischen
Verifikationen. Zusätzlich bietet das optionale Feature `TOOB_DOUBLE_VERIFY`
eine echte Double-Execution — zwei vollständige, unabhängige
`verify_ed25519`-Aufrufe mit Ergebnis-Konsistenzprüfung. Dies detektiert auch
krypto-interne Faults auf Kosten von ~30–50ms zusätzlicher Boot-Zeit
(Ed25519 auf Cortex-M4).

**Konfiguration:** `cmake -DTOOB_DOUBLE_VERIFY=ON`

### Trade-off: DPA vs. Glitch-Resistenz
Bei aktiviertem `TOOB_DOUBLE_VERIFY` verbleibt der Root Public Key ~30ms länger
im RAM (bis nach dem zweiten Verify-Aufruf). Dies vergrößert das
Differential-Power-Analysis-Fenster minimal, wird jedoch als akzeptabler
Trade-off gewertet, da:
1. Der Key ohnehin aus eFuses stammt (kein Geheimnis im klassischen Sinne)
2. Die Glitch-Resistenz-Verbesserung physikalisch signifikanter ist
3. Das Zeroize unmittelbar nach dem zweiten Aufruf erfolgt
