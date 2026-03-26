# Gap-Analysis V4: Toob-Boot Architektur-Synthese (The Hyper-Refinement)

Die Architektur hat mit der V3-Iteration einen Reifegrad erreicht, der fast alle gängigen Commercial-Off-The-Shelf (COTS) Bootloader übertrifft. Die Ergänzungen (Fuzzing, Predictive Preflight, CRA SBOM-Regulatorik, CRC-16) sind extrem wertvoll.

Diese V4-Analyse kratzt nun absolut am Limit der Firmware-Architektur-Theorie. Wir suchen nach den letzten 0.1% der Fehlerquellen: Race-Conditions zwischen Cloud und Physik, sowie Widersprüche im Hardware-Ressourcen-Budget.

Hier sind die 4 verbleibenden High-End-Gaps:

### 1. Cloud Lockout durch Race-Condition im DICE_MIGRATION_EVENT (Security / Network Logic)
**Problem:** In Abschnitt 1A emittiert Stage 1 *vor dem Reboot* das DICE-Migration Event. Das Backend vertraut dem Token und markiert die "neue" Identität als valide. Was aber, wenn genau *während* des Reboots der Strom ausfällt oder Stage 0 die neue Stage 1 wegen einer korrupten Signatur ablehnt? Das Gerät bootet physikalisch zwangsweise wieder mit der *alten* Stage 1. Die Cloud hat die alte Identität aber im Backend bereits entwertet, weil das Migration-Event ja schon ankam. Das Gerät ist permanent aus dem Netzwerk ausgeschlossen.
**Mitigation:** Die DICE-Migration MUSS zwingend als **Two-Way Handshake** modelliert werden. 
1. Vor dem Update: Stage 1 emittiert `INTENT_TO_MIGRATE` (Cloud merkt sich das, rotiert aber *nicht*).
2. Nach dem Reboot: Die *neue* Stage 1 bootet, verbindet sich und emittiert `CURRENT_IDENTITY_CONFIRMED`. Erst dann entwertet die Cloud den alten Key. Failsafes sind bei Identitätswechseln elementar.

### 2. Bestätigungs-Illusion bei Watchdog-Resets (Hardware / Reliability)
**Problem:** In Abschnitt 1B (`confirm_hal_t`) und 2 (Fall 4) wird der Auto-Rollback gesteuert. Ein Watchdog-Reset greift, wenn die App crasht. Aber: Ein Watchdog-Reset ist meist ein "Soft-Reset", bei dem der RTC-RAM (oder Backup-Register) *erhalten* bleibt. Wenn das OS sein `0xOK`-Flag ins RTC-RAM schreibt und kurz danach (z.B. nach 5 Sekunden Laufzeit) der Watchdog zuschlägt, findet der Bootloader beim anschließenden Boot das `0xOK` im RTC-RAM und denkt: "Klasse, OS läuft einwandfrei!" und bootet die gebrickte App in einer Endlosschleife neu. Das Confirm-Flag wird so zur Todesfalle.
**Mitigation:** Der Bootloader MUSS zwingend **das Hardware-Reset-Reason Register** der MCU (z.B. `RCC_CSR` bei STM) als allererstes auslesen. Lautet der Grund `WATCHDOG_RESET` oder `SOFTWARE_PANIC`, MUSS der Bootloader ein eventuell im RTC-RAM liegendes `0xOK` Flag ignorieren, löschen und den `Boot_Failure_Counter` knallhart hochsetzen. Nur bei einem POR (Power-On-Reset) oder sauberen Soft-Reset ist das Flag valide.

### 3. Merkle-Tree RAM-Berechnung ist eine physikalische Illusion (Efficiency / Memory)
**Problem:** Abschnitt 1B (Schicht 5) lobt den Manifest-Compiler, der den RAM-Bedarf der "Sibling-Hashes" ausrechnet. Aber die Sibling-Hashes (z.B. 288 Bytes) sind nicht das RAM-Problem! Das Nadelöhr ist der *Chunk selbst*. Wenn der Compiler (wie vorgeschlagen) große `merkle.chunk_size` zulässt, um die Baumtiefe zu verringern (z.B. 16 KB), dann muss Stage 1 **16 KB zusammenhängendes SRAM** allokieren, nur um den Funk-Payload-Chunk reinzuladen und zu hashen. Ein Bootloader, der auf `~14 KB` Gesamt-Footprint (Code + RAM) designt ist, stirbt bei einem 16 KB Array an einem sofortigen Stack/Heap-Smasher.
**Mitigation:** Die Architektur muss im Preflight-Report folgende extrem strikte Gleichung prüfen und sonst den Build abbrechen:
`Peak_SRAM_Needed = merkle.chunk_size + (tree_depth * 32) + WAL_Sector_Buffer_RAM`. Es muss klar dokumentiert sein, dass `merkle.chunk_size` auf extrem restriktiven MCUs `2 KB` bis `4 KB` praktisch nicht überschreiten darf.

### 4. Das Zeitbomben-Szenario durch Bit-Rot vs. WAL CRC-16 (Data Integrity)
**Problem:** Abschnitt 2 beschreibt nun zwingende CRC-16 Trailer für jeden WAL-Eintrag. Ein Fehler bewirkt den "Rollback auf den letzten validen Commit". Ein `TXN_COMMIT` markiert ein Update als final erfolgreich. Was passiert, wenn 6 Jahre später durch natürliche Radioaktivität / Bit-Rot ein einzelnes Bit im *alten, fertigen* `TXN_COMMIT` des Flashs kippt? Beim regulären Boot liest der Bootloader das WAL, sieht einen CRC-Fehler beim Commit und macht was? Er "un-committed" das 6 Jahre alte Update und startet plötzlich grundlos einen Fallback oder Replay einer uralten Firmware.
**Mitigation:** Die "WAL Garbage Collection" darf alte Intents nicht nur asynchron löschen ("Pre-Erasing Sektor 1"), sondern MUSS die Zustandsmaschine nach einem erfolgreichen Update **komplett finalisieren** (z.B. in einem redundanten 2-Byte "Current Primary Slot" Feld, das unabhängig vom fließenden Text-Journal ist). Ein uralter Log-Eintrag darf nach 6 Jahren nicht mehr die Boot-Stabilität diktieren. Sobald ein Update 1x erfolgreich OS-bestätigt wurde, wird das WAL geleert/abgeschlossen, um keine historischen CRC-Bomben herumliegen zu lassen.
