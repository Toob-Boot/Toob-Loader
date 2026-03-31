Hier ist mein Vorschlag für eine chronologische Entwicklungsplanung, die Abhängigkeiten respektiert und so früh wie möglich testbar wird.

---

## Modul-Übersicht & Abhängigkeitsgraph

Bevor wir in die Phasen einsteigen, hier die logische Zerlegung in eigenständige Arbeitspakete:

**Infrastruktur-Module:**

- `M-BUILD` — CMake-Skeleton, Toolchains, CI-Grundgerüst
- `M-TYPES` — `boot_types.h`, `boot_hal.h` (reine Interface-Definitionen, null Implementierung)
- `M-SANDBOX` — Sandbox-HAL (POSIX mmap-Flash, fake Clock/WDT/Crypto/Confirm)
- `M-TOOLS` — Manifest-Compiler, Sign-Tool, Delta-Builder (Python)

**Core-Module (hardware-frei):**

- `M-JOURNAL` — WAL Ring-Buffer, CRC-32, Sliding Window, ABI-Migration
- `M-CRYPTO-SW` — Monocypher-Wrapper (`crypto_hal_t` Software-Backend)
- `M-VERIFY` — Envelope-First Signaturprüfung + Merkle Chunk-Hashing
- `M-CONFIRM` — Reset-Reason Auswertung, Nonce-Check, Rollback-Trigger-Logik
- `M-STATE` — Zustands-Maschine (IDLE/STAGING/TESTING/CONFIRMED)
- `M-SWAP` — In-Place Sektor-Overwrite via Swap-Buffer
- `M-DELTA` — Forward-Only Patcher, 16KB-Chunk Checkpointing, Base-Fingerprint
- `M-ROLLBACK` — Hybrid SVN (WAL + eFuse Epoch), Fail-Counter, Recovery-OS Logik
- `M-ENERGY` — Battery-Guard, Brownout-Backoff, Deep-Sleep Orchestrierung
- `M-PANIC` — Serial Rescue (COBS Framing, 2FA Auth-Token, Penalty-Sleep)
- `M-DIAG` — CBOR Telemetrie, `.noinit` Shared-RAM, Timing-IDS
- `M-MULTIIMG` — Atomic Update Groups, TXN_ROLLBACK_BEGIN, Secondary Boot Delegation
- `M-MAIN` — `boot_main.c` Init-Kaskade, Jump-Logic, `hal_deinit()`

**Externe Module:**

- `M-LIBTOOB` — OS-seitige C-Library (confirm, update-registration, diag-extraction)
- `M-STAGE0` — Immutable Core (TMR Boot-Pointer, Hash/Verify, Tentative-Flag)
- `M-HAL-HW` — Echte Hardware-Ports (ESP32, STM32, nRF)
- `M-SUIT` — CDDL-Schema + zcbor Codegen

---

## Phase 0 — Fundament & Interfaces (Woche 1–2)

**Ziel:** Alle Schnittstellen definiert, Build-System steht, null Implementierung nötig — aber alles kompiliert.

**Pakete:**

`M-TYPES` ist das allererste Arbeitspaket. Hier entstehen die Header `boot_types.h` (mit `boot_status_t`, `reset_reason_t`), `boot_hal.h` (alle 7 Trait-Structs als reine Struct-Definitionen mit Funktionspointern) und `boot_platform_t`. Kein einziges `.c`-File wird implementiert. Der Wert dieses Pakets liegt darin, dass ab sofort jedes andere Modul gegen stabile Interfaces programmieren kann, ohne auf Implementierungen zu warten. Die `_Static_assert`-Guards für Struct-Alignment und ABI-Versionen kommen ebenfalls hier rein.

`M-BUILD` folgt parallel. Das CMake-Skeleton mit den Toolchain-Files (`toolchain-host.cmake`), der Drei-Ebenen-HAL-Assembly (`toob_hal.cmake`), die Target-Matrix (`sandbox` als einziges aktives Target) und das grundlegende CI-YAML. Wichtig: Das `malloc=MALLOC_FORBIDDEN`-Compile-Define und die C17-Warnflags (`-Werror -Wconversion`) werden sofort gesetzt. Ab hier kompiliert `toob_core` als leere Lib ohne Linker-Fehler.

`M-SANDBOX` (Grundgerüst) wird als drittes angefangen. Hier entstehen die sieben Mock-Implementierungen: `mock_flash.c` (mmap auf eine Datei, `memset` für Erase, `memcpy` für Read/Write), `mock_wdt.c` (Timeout-Tracking, kein echter Reset), `mock_crypto_policy.c` (Monocypher direkt, kein HW-Bypass), `mock_rtc_ram.c` (statische Variable als Confirm-Store) und die `chip_platform.c` für Sandbox, die alles zu `boot_platform_t` verdrahtet. `chip_config_sandbox.h` bekommt statische Defaults (4KB Sektoren, 4-Byte Alignment, 0xFF erased_value). Entscheidend: Die `chip_fault_inject.c` kommt auch schon rein — mit einem globalen `fault_inject_config` Struct, das "Brownout nach Sektor N" oder "Flash-Read liefert Garbage ab Offset X" steuert. Das kostet fast nichts extra und macht jeden späteren Test dramatisch wertvoller.

**Warum diese Reihenfolge:** Ohne stabile Interfaces kann niemand parallel arbeiten. Ohne Build-System kann niemand kompilieren. Ohne Sandbox kann niemand testen. Diese drei blockieren alles andere.

**Lieferbar:** `toob build --target sandbox` kompiliert durch (mit leeren Core-Stubs). Unit-Test-Runner startet und meldet "0 Tests".

---

## Phase 1 — WAL + Crypto-Kern (Woche 2–4)

**Ziel:** Die zwei tiefsten Abhängigkeiten implementiert und mit >90% Coverage getestet.

**Pakete:**

`M-JOURNAL` ist das kritischste Modul im gesamten Projekt. Das WAL ist die Grundlage für Brownout-Resilienz, State-Tracking, TMR-Speicherung, Delta-Checkpointing und Boot-Confirmation. Es muss zuerst stehen, weil M-SWAP, M-DELTA, M-ROLLBACK, M-CONFIRM und M-STATE alle darauf aufbauen. Die Implementierung umfasst: den Ring-Buffer mit Sliding Window über 4–8 Sektoren, CRC-32 Trailer pro Entry, den `ABI_VERSION_MAGIC` Header für Vorwärtskompatibilität, die Transfer-Bitmap (1 Bit pro Chunk), TMR Majority-Vote für langlebige Werte (`Current_Primary_Slot`, `Boot_Failure_Counter`, WAL-Sector-Base-Pointer) mit Strided-Writes über mindestens zwei physische Sektoren, den Sequence-Counter mit `0xBEEF`-Magic für O(1) Sektor-Discovery, und die `update_deadline`-basierte Transaktions-Bereinigung. Hier kommt auch das `union wal_entry_aligned` Padding-Pattern (GAP-C03) und der zugehörige `_Static_assert`.

Die Unit-Tests für M-JOURNAL (`test_journal.c`) sind die ersten echten Tests im Projekt. Sie validieren: Append + Lesen, CRC-Korruption erkennen, Ring-Overflow (Sliding Window rotiert), ABI-Version-Mismatch (alte Transaktionen verwerfen, TMR bewahren), TMR Majority-Vote (1 von 3 Kopien korrumpiert → korrekter Wert), Factory-Blank-Init (kein Magic → deterministisch Sektor 0 mit seq=1). Da die Sandbox-Flash-Mock schon steht, laufen diese Tests sofort nativ.

`M-CRYPTO-SW` wird parallel entwickelt. Der Monocypher-Wrapper (`crypto_monocypher.c`) implementiert die `crypto_hal_t`-Schnittstelle: `hash_init/update/finish` über die statische `crypto_arena`, `verify_ed25519` (Constant-Time garantiert durch Monocypher), `random` via `/dev/urandom` in der Sandbox. Die `boot_secure_zeroize.S` Assembly-Funktion kommt auch hier rein — auf dem Host als `volatile memset`-Fallback, auf ARM als echte Assembly. `verify_pqc` bleibt `NULL` für Phase 1.

**Warum Crypto jetzt:** Ohne Hashing und Signaturprüfung kann M-VERIFY nicht gebaut werden. Ohne M-VERIFY kann die State-Machine keine Images akzeptieren. Der Software-Pfad (Monocypher) ist der Default und braucht keine Hardware.

**Lieferbar:** `test_journal` und `test_crypto` laufen grün. WAL kann Entries schreiben, lesen, recovern. Ed25519-Signaturen werden korrekt verifiziert/abgewiesen.

---

## Phase 2 — Verifikation & Confirm-Logik (Woche 4–6)

**Ziel:** Die Signatur-Pipeline und das Boot-Confirmation-System stehen — der Bootloader kann "Vertrauen" und "Misstrauen" unterscheiden.

**Pakete:**

`M-VERIFY` kombiniert `boot_verify.c` und `boot_merkle.c`. Die Implementierung folgt strikt dem Envelope-First-Pattern: Zuerst wird die Ed25519-Signatur über das gesamte SUIT-Manifest geprüft (Sign-then-Hash, `BOOT_OK = 0x55AA55AA` mit Double-Check-Pattern und Branch-Delay-Injection gegen Glitching). Erst danach werden einzelne Felder gelesen. Der Merkle-Chunk-Loop liest 4KB-weise via `flash_hal.read()`, hasht via `crypto_hal.hash_update()`, vergleicht gegen den chunk_hashes-Array im Flash-Manifest und kickt den WDT zwischen jedem Chunk. Hier wird auch das Anti-Truncation-Verhalten enforced: Kein Byte wird aus dem Manifest interpretiert bevor die Signatur bestanden ist.

Parallel dazu das `M-SUIT`-Paket (Teillieferung): Das CDDL-Schema (`toob_suit.cddl`) muss soweit stehen, dass `zcbor generate` die `boot_suit.c` / `boot_suit.h` Dateien erzeugt. Der Stream-Parser evaluiert unbekannte `suit-conditions` als FAIL, ignoriert `suit-directives` und erzwingt `min_parser_version`. Für Phase 2 reicht ein Minimal-Schema (Image-Size, Chunk-Hashes, Envelope-Signature, SVN, Device-ID). Erweiterte Felder (PQC-Hybrid, Multi-Image, SBOM-Digest) kommen in späteren Phasen.

`M-CONFIRM` (`boot_confirm.c`) orchestriert die Reset-Reason-Auswertung mit der Confirm-HAL. Die Kernlogik: `get_reset_reason()` wird zuerst gelesen. Bei `WATCHDOG` oder `BROWNOUT` wird `check_ok()` ignoriert — selbst wenn es `true` liefert. Bei `POWER_ON` oder `PIN_RESET` wird `check_ok(expected_nonce)` ausgewertet. `clear()` wird vor jedem OS-Jump aufgerufen. Die 64-Bit Boot-Nonce-Generierung (via `crypto_hal.random()`) und die `NONCE_INTENT`-Sicherung im WAL kommen ebenfalls hier rein.

`M-TOOLS` (Teillieferung): Parallel auf der Python-Seite wird das `sign_tool` implementiert: `toob-keygen` (Ed25519 via PyNaCl), `toob-sign` (SUIT-Manifest bauen, Merkle-Tree Chunk-Hashes berechnen, Ed25519 signieren). Ohne dieses Tool gibt es keine signierten Test-Images für die Integration-Tests. Der `delta_builder.py` kommt erst in Phase 4.

**Warum jetzt:** M-VERIFY ist Voraussetzung für M-STATE (die State-Machine akzeptiert nur verifizierte Images). M-CONFIRM ist Voraussetzung für M-ROLLBACK. Das Sign-Tool ist Voraussetzung für realistische Tests.

**Test-Lieferbar:** `test_verify.c` (gültige Signatur → BOOT_OK, manipuliertes Manifest → BOOT_ERR_VERIFY, abgeschnittenes Manifest → BOOT_ERR_VERIFY), `test_merkle.c` (korrekter Chunk → pass, korrumpierter Chunk → fail, Bit-Rot in einem Chunk → exakte Fehlerlokalisierung), `test_confirm.c` (WDT-Reset + gesetztes Flag → Rollback, Power-On + korrekte Nonce → Boot, Power-On + falsche Nonce → Rollback). Erster Fuzz-Target: `fuzz_suit_parser.c` läuft in der CI.

---

## Phase 3 — State-Machine, Swap & Rollback (Woche 6–9)

**Ziel:** Der vollständige Happy-Path funktioniert — ein Update kann empfangen, geschrieben, verifiziert, gebootet und bestätigt werden. Plus: Rollback bei Failure.

**Pakete:**

`M-STATE` (`boot_state.c`) ist die zentrale Zustandsmaschine: IDLE → STAGING → TESTING → CONFIRMED. Sie orchestriert die Aufrufe an M-JOURNAL, M-VERIFY, M-CONFIRM, M-SWAP. Der WAL definiert den aktuellen Zustand persistent: `TXN_BEGIN` → Chunks schreiben → `TXN_COMMIT` → OS booten → `CONFIRM_COMMIT` (via libtoob). Die Maschine muss bei jedem Kaltstart den WAL-Zustand rekonstruieren und entscheiden: Weiter-Schreiben (Resume), Rollback, oder Normal-Boot.

`M-SWAP` (`boot_swap.c`) implementiert den In-Place-Overwrite via Swap-Buffer. Der Algorithmus: Quell-Sektor in Swap-Buffer kopieren → WAL-Intent loggen → Ziel-Sektor erasen → Neue Daten schreiben → WAL-Commit. Kritisch ist die Interaktion mit `get_sector_size()` für asymmetrische Flash-Layouts (STM32F4: 16KB/64KB/128KB gemischt). Der Swap-Buffer wird statisch als `uint8_t swap_buf[CHIP_FLASH_MAX_SECTOR_SIZE]` allokiert. Der WDT wird zwischen jedem Erase/Write gekickt — und bei monolithischen Vendor-ROM-Erases wird `wdt.suspend_for_critical_section()` / `resume()` genutzt (GAP-C02).

`M-ROLLBACK` (`boot_rollback.c`) implementiert: den hybriden SVN-Check (WAL-SVN für Minor-Updates, eFuse-Epoch für kritische CVEs), den `Boot_Failure_Counter` im WAL (TMR-geschützt), die Recovery-OS-Kaskade (1 Crash → Rollback Slot A, Max-Retries → Recovery-Partition, Recovery crasht auch → `RESCUE_ONLY_LOCK` oder Exponential-Backoff bei `edge_unattended_mode`), den `RECOVERY_RESOLVED`-Intent, den isolierten `SVN_recovery`-Counter und den Reset des Fail-Counters bei erfolgreichem Confirm.

`M-MAIN` (Grundgerüst): Die Init-Kaskade wird verdrahtet: `boot_platform_init()` → clock → flash → wdt → crypto → confirm → console → soc → `boot_state_run()`. Das `hal_deinit()` vor dem OS-Jump (in umgekehrter Reihenfolge) und die Bounds-Validierung des Jump-Targets kommen auch hier rein. Der `boot_delay_with_wdt()`-Helper wird implementiert.

**Parallel dazu:** `M-LIBTOOB` (Grundversion). Die OS-seitige Library braucht drei Funktionen: `toob_confirm_boot()` (Append `CONFIRM_COMMIT` ins WAL), `toob_set_next_update()` (WAL-Eintrag für Manifest-Adresse), `toob_get_boot_diag()` (zunächst Stub, wird in Phase 5 gefüllt). Die `toob_handoff_t`-Validierung (Magic + CRC-16 über `.noinit`) wird implementiert. Ohne libtoob kann kein OS das Confirm-Flag setzen, was den gesamten Lifecycle-Test blockiert. **Wichtig:** Da der Manifest-Compiler erst in Phase 4 fertig wird, libtoob aber zwingend die Adressen der `libtoob_config.h` benötigt, stellen wir in Phase 3 temporär einen Mock-Header (`libtoob_config_sandbox.h`) für das Sandbox-Target bereit!

**Warum jetzt:** Dies ist der frühestmögliche Zeitpunkt für den ersten End-to-End-Test. Alle Vorbedingungen (WAL, Crypto, Verify, Confirm) stehen.

**Test-Lieferbar:** `test_full_update.py` — der erste Integration-Test, der den kompletten OTA-Lifecycle in der Sandbox durchspielt: Image signieren → Staging → Verify → Swap → Boot → libtoob Confirm → Reboot → Normal-Boot. `test_power_loss.py` — Brownout bei 0%, 50%, 99% des Swap-Prozesses, jeweils mit WAL-Recovery. `test_rollback_chain.py` — App crasht → Rollback → App crasht erneut → Recovery-OS. `test_swap.c` (Unit) — asymmetrische Sektoren, Swap-Buffer kleiner als App-Sektor.

---

## Phase 4 — Delta-Patching & Energy-Guard (Woche 9–12)

**Ziel:** Bandbreiten-sparende Updates und Batterie-Schutz.

**Pakete:**

`M-DELTA` (`boot_delta.c`) implementiert den Forward-Only Patcher mit heatshrink-Backend. Kernmechanismen: der 8-Byte Base-Fingerprint (Truncated SHA-256) verhindert Patch auf falsches Base-Image, der 16KB-Chunk Dictionary-Reset garantiert Resume-Sicherheit nach Brownout, das WAL-Checkpointing flusht nur 8-Byte Pointer-Referenzen (`Chunk_ID`, `Offset`). Die strikte Regel: Write-Stream in den Staging-Slot ist Forward-Only, Base-Image Reads dürfen O(1) Random-Access über XIP-Flash. Das `delta_builder.py` Host-Tool wird jetzt fertiggestellt (GAP-C05: künstliches Schneiden in 16KB-Frames).

`M-ENERGY` (`boot_energy.c`) wird implementiert — aber nur dort wo `soc_hal_t` vorhanden ist. Die Logik: Vor Update-Start `can_sustain_update()` prüfen. Während des Updates interleaved `battery_level_mv()` pollen. Bei Unterschreiten von `min_battery_abort_mv`: sofort `TXN_ROLLBACK` ins WAL, alte App booten (kein endloses Sleep!). Der Exponential-Backoff-Timer für Edge-Recovery (1h, 4h, 12h, 24h MAX-CAP) wird im WAL persistiert. Die Sandbox-Mock liest `TOOB_BATTERY_MV` aus der Umgebungsvariable.

`M-TOOLS` (Erweiterung): Der `manifest_compiler` wird jetzt vervollständigt. Er liest `device.toml` + `blueprint.json` + `aggregated_scan.json`, generiert `chip_config.h`, `libtoob_config.h`, `boot_config.h`, `boot_features.h`, `flash_layout.ld`, `stage0_config.h`. Der Preflight-Report (Alignment-Check, RAM-Budget, WDT-Timeout-Berechnung mit Hardware-Treppenstufe, Crypto-Arena-Sizing) und die `platform.resc` für Renode kommen auch rein. Vendor-Plugins (`esp32.py`, `stm32.py`, `nrf.py`) werden grundlegend angelegt.

**Warum jetzt und nicht früher:** Delta-Patching ist ein Optimierungs-Feature auf dem funktionierenden Swap-Pfad. Energy-Guard ist optional (`soc_hal_t` kann `NULL` sein). Der Manifest-Compiler war bis jetzt nicht blockierend, weil die Sandbox statische Defaults nutzt — aber für Hardware-Ports in Phase 6 wird er zwingend gebraucht, also muss er jetzt fertig werden.

**Test-Lieferbar:** `test_delta.c` (Base-Fingerprint Mismatch → Reject, korrekter Patch → identisches Ziel-Image, Brownout mitten im Patch → WAL-Resume ab letztem 16KB-Chunk), `test_delta_update.py` (End-to-End Delta in Sandbox), `test_energy.c` (Batterie zu niedrig → Update abgelehnt, Brownout während Erase → sofortiger Rollback statt Sleep), `fuzz_delta_decoder.c`, `test_manifest_compiler.py` (GAP-F20: defekte JSON → `#error`).

---

## Phase 5 — Diagnostics, Serial Rescue & Telemetrie (Woche 12–15)

**Ziel:** Observability und Offline-Recovery — die Features die ein Produkt vom Prototyp unterscheiden.

**Pakete:**

`M-DIAG` (`boot_diag.c`) implementiert die CBOR-Telemetrie über `zcbor`. Die `.noinit` Shared-RAM Sektion wird mit Magic-Header, Boot-Session-ID und CRC-16 Trailer geschützt. Stage 1 streamt: `boot_time_ms`, `verify_time_ms`, `last_error_code`, `vendor_error`, `active_key_index`, `current_svn`, `boot_failure_count`, `sbom_digest` und die `ext_health`-Wear-Daten (WAL/App/Staging/Swap Erase-Counter). Die `boot_diag_get_last_error()`-ID für Delta-Crash/Base-Mismatch-Feedback an den OTA-Agent kommt auch hier rein. Das CDDL-Schema `toob_telemetry.cddl` wird finalisiert.

`M-LIBTOOB` (Erweiterung): `toob_get_boot_diag()` wird jetzt voll implementiert — es parst die `.noinit`-Daten validiert (Magic + CRC) in die `toob_boot_diag_t` Struct. Die `toob_handoff_t`-Struct wird um die Wear-Counter erweitert.

`M-PANIC` (`boot_panic.c`) implementiert Serial Rescue (Schicht 4a). COBS Framing (Encoder + Decoder), Ping-Pong Flow-Control (`READY` → Chunk → `ACK`), der kryptografische Auth-Token-Transfer (104 Bytes: Nonce + DSLC + Slot-ID, Ed25519-signiert), das "Highest-Seen-Timestamp"-Pattern gegen Replay (aus verschleißfester Persistenz, nicht WAL!), und der Exponential-Penalty-Sleep bei fehlgeschlagenen Auth-Versuchen (GAP-C06). **Wichtig (WDT-Kopplung):** Hier MUSS für den Penalty-Sleep zwingend der `boot_delay_with_wdt()` Helper aus `M-MAIN` verwendet werden, um bei langen Sleeps (bis zu mehreren Sekunden) ein WDT-Ablaufen zu verhindern. Der Recovery-Pin-Check mit Debouncing (500ms, GPIO Pull-Up/Down) wird in `boot_main.c` integriert.

`M-SUIT` (Erweiterung): Das CDDL-Schema wird um Multi-Image Felder (`[images.app]`, `[images.netcore]`, `[images.recovery]`), PQC-Hybrid-Flag, `sbom_digest`, `Required_Key_Epoch`, `device-identifier` Condition und `update_deadline` erweitert.

**Warum jetzt:** Diagnostics und Serial Rescue sind nicht auf dem kritischen Pfad für den Update-Lifecycle, aber zwingend für Produktions-Readiness. Sie hängen von allen vorherigen Modulen ab (WAL, Crypto, Confirm, State-Machine), können diese aber nicht blockieren.

**Test-Lieferbar:** `test_serial_rescue.py` (Auth-Token korrekt → Flash erlaubt, falsches Token → Reject + Penalty, Replay-Token → Reject), `fuzz_cobs_framing.c`, Telemetrie-Roundtrip-Test (S1 schreibt CBOR → libtoob liest → Werte stimmen überein).

---

## Phase 6 — Hardware-Ports & Stage 0 (Woche 15–20)

**Ziel:** Vom Sandbox-Beweis zum echten Silizium. Plus: das immutable Stage 0.

**Pakete:**

`M-HAL-HW` wird jetzt in drei Wellen ausgerollt. Die Reihenfolge richtet sich nach Komplexität und Community-Reichweite:

**Welle 1 — STM32L4** (einfachster Port, uniforme 2KB-Sektoren, kein OTFDEC, Cortex-M4 mit IWDG und Backup-Register). Hier entstehen die `arch/arm_cortex_m/`-Dateien (SysTick, NVIC, SCB) und `vendor/stm32/`-Dateien (Flash Unlock/Lock, IWDG, Backup-Register, RCC-Reset-Reason mit Caching). Das `chips/stm32l4/chip_platform.c` verdrahtet alles. Der Manifest-Compiler generiert erstmals echte `chip_config.h` aus Toobfuzzer-Daten.

**Welle 2 — ESP32-S3** (Xtensa, ROM-Pointer-basiert, RTC-Fast-MEM, RWDT, HW-SHA-256). Hier entstehen `arch/xtensa/` und `vendor/esp/`. Die größte Herausforderung: ROM-Pointer für `SPIEraseSector`/`SPIWrite` korrekt verdrahten, HW-SHA über ROM-init/update/finish. Validiert die hybride HAL-Architektur (Bare-Metal Register + Vendor-ROM-Pointer).

**Welle 3 — nRF52840** (Cortex-M4, NVMC, CC310 Hardware-Crypto, Retained-RAM, nicht-stoppbarer WDT). Validiert das CC310-Backend für Ed25519 und SHA-256, plus das `deinit()` als No-Op für den WDT.

`M-STAGE0` wird parallel zur ersten Hardware-Welle entwickelt. Stage 0 ist ein eigenes Binary mit eigenem Linker-Script. Implementierung: TMR Boot-Pointer Majority-Vote, Bounds-Validierung (`S1A_BASE <= ptr <= S1B_END`), 4-Byte Magic-Header Check, `stage0.verify_mode`-Auswahl (hash-only / ed25519-sw / ed25519-hw), RTC-RAM TENTATIVE-Flag + RESET_REASON-Auswertung (Endless-Loop Protection), Key-Index Rotation via OTP-eFuses. Stage 0 hat bewusst null Abhängigkeit auf den Core — es ist komplett eigenständig.

**Warum diese Reihenfolge:** Hardware-Ports erst jetzt, weil der gesamte Core vorher in der Sandbox validiert wurde. Das verhindert, dass Hardware-Bugs mit Logik-Bugs verwechselt werden. STM32L4 zuerst, weil es die `arch/arm_cortex_m/` und `vendor/stm32/` Layer etabliert, die für STM32H7/U5/F4 wiederverwendet werden. Stage 0 hat keine Abhängigkeit auf den Core und kann parallel laufen.

**Test-Lieferbar:** Erster HIL-Test auf echter Hardware (Flash + Boot + Rollback-Zyklus). Renode-Emulator-Tests mit auto-generierten `.resc`-Configs. Stage 0 Unit-Tests (TMR Vote mit 1-von-3 Korruption, Bounds-Check, TENTATIVE-Flag-Logik).

---

## Phase 7 — Multi-Image, PQC & Härtung (Woche 20–24)

**Ziel:** Fortgeschrittene Features für Multi-Core SoCs und Post-Quantum-Readiness.

**Pakete:**

`M-MULTIIMG` (`boot_multiimage.c`) für nRF5340 und ähnliche Multi-Core SoCs. Atomic Update Groups mit `TXN_ROLLBACK_BEGIN` im WAL (Radio-Core zuerst, dann Main-Core), Forced Hardware-Reset-Hold für Sub-Cores via `soc_hal.assert_secondary_cores_reset()`, Bus-Sanitization via `flush_bus_matrix()`, und das Stage-1.5 Pattern für physisch isolierte Sub-Core-Busse. nRF5340 wird als erster Multi-Core-Port mit `chip_ipc.c` implementiert.

PQC-Crypto-Backend (`crypto/pqc/`): ML-DSA-65 Verify-Wrapper für `crypto_hal_t.verify_pqc`. Die `crypto_arena` muss für die PQC-Matrizen ausreichen (GAP-C04: Scratchpad aus `.bss`, kein Stack). Der Manifest-Compiler prüft `bootloader_budget` gegen den PQC-RAM-Bedarf. Der Hybrid-Modus (erst Ed25519, dann PQC, beide müssen bestehen) wird in `boot_verify.c` integriert.

Flash EOL Survival Mode (GAP-C07): Der Swap-Buffer Erase-Counter wird in `boot_swap.c` implementiert. Bei Überschreiten des Datenblatt-Maximums → `STATE_READ_ONLY` (nur in-memory, nie ins WAL persistiert!). Die HAL blockiert alle weiteren Erase-Operationen.

OTFDEC Anti-Side-Channel: `set_otfdec_mode()` wird für STM32H7/U5 implementiert. Der `deinit()`-Pfad re-enabled OTFDEC zwingend vor dem OS-Jump.

**Test-Lieferbar:** `test_multiimage.c` (Atomic Group Rollback bei partiellem Failure, Sub-Core-Reset-Hold), `test_multi_image.py` (End-to-End auf nRF5340-Emulator), `test_eol_survival.py` (Flash-Counter am Limit → Read-Only, kein Brick).

---

## Übergreifende Planungs-Hinweise

**Parallelisierbarkeit:** Ab Phase 1 können zwei Tracks parallel laufen — ein "Core-Track" (Journal → Verify → State → Swap) und ein "Tools-Track" (sign_tool → manifest_compiler → delta_builder). Ab Phase 5 kommt ein dritter "HAL-Track" dazu. Das ermöglicht 2–3 Entwickler gleichzeitig, solange die Interfaces aus Phase 0 stabil bleiben.

**Risiko-Hotspots:** Das WAL (M-JOURNAL) ist das größte Einzelrisiko. Fehler dort propagieren in jedes andere Modul. Deshalb bekommt es die früheste und intensivste Test-Coverage, inklusive Fuzz-Target (`fuzz_wal_recovery.c` ab Phase 3).

**Sandbox-First als eiserne Regel:** Kein Feature wird auf Hardware getestet bevor es in der Sandbox grün ist. Die Fault-Injection (`chip_fault_inject.c`) in der Sandbox ist billiger und reproduzierbarer als jedes HIL-Rack. Hardware-Tests validieren nur, dass die HAL-Implementierung korrekt ist — nicht die Core-Logik.

**Manifest-Compiler Timing:** Der Compiler wird inkrementell gebaut (Phase 2: sign_tool, Phase 4: voller Compiler). Das ist bewusst so, weil die Sandbox keine generierten Headers braucht (`chip_config_sandbox.h` ist statisch). Erst wenn Hardware-Ports beginnen (Phase 6), muss die volle Pipeline stehen.

**zcbor-Codegen als Gating-Faktor:** Die SUIT-Parser-Generierung aus CDDL blockiert `boot_suit.c`. Das Schema sollte in Phase 2 minimal stehen und in Phase 5 erweitert werden. Alternativ: Handgeschriebener Minimal-Parser für Phase 2–3, zcbor-generierter Parser ersetzt ihn in Phase 5.

**libtoob und Core dürfen keinen Code teilen:** Die OS-Library inkludiert `libtoob_config.h` (generiert) und schreibt direkt auf die dort definierten Adressen. Sie linkt nicht gegen `core/`. Das ist Absicht — die Repositories müssen unabhängig buildbar sein.
