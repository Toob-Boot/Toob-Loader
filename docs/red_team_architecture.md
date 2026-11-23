# Toob-Loader Multi-Agent Red-Team & Attack-Corpus Architecture

> **Ziel:** Systematische, automatisierte und reproduzierbare Schwachstellensuche über alle Boot-Phasen, Chips, Paket-Grenzen und Threat Assumptions (`TA-1` .. `TA-4`, kompromittiertes App-OS `TA-3` und Supply-Chain-Komposition) — **ohne** Reward-Hacking, Emulator-Manipulation oder Team-Spionage.

---

## § 1 — Threat-Model-Abdeckung & Zeitpunkte

Red-Team-Angriffe decken den gesamten Lebenszyklus eines Toob-Boot-Geräts ab:

| Phase (`phase`) | Threat Assumption | Beispiel-Angriffsklassen |
| :--- | :--- | :--- |
| `preboot` | `TA-1` (beschreibbarer externer Flash), Glitch | Manipulierte Stage-1A/1B, geleerte/gefälschte WAL-Sektoren, unsignierter Recovery-/App-Slot, TSIG-/PQC-Bypass |
| `provisioning` | UART/COBS-Zugriff vor oder nach Lock | Wiedereintritt ins UART-Provisioning bei gesetztem DSLC, fehlendes Genesis-WAL, Key-Slot-Konfusion |
| `update` | `TA-1` / bösartiger Update-Stream | Manipulierte TBM1/TDS1/Heatshrink/Multi-Image/Reverse-Delta-Bundles, Brownout-/Power-Cut-TOCTOU, Merkle-Skip |
| `rollback` | `TA-1` + `A1`/`A2` | Unauthentifiziertes SWAPMOVE-/ONEWAY-/POINTER-Rollback, WAL-SVN-Reset, eFuse-/KDM-Floor-Downgrade |
| `recovery` | UART-XMODEM / 2FA | XMODEM-DoS, vorzeitiges `recovery_resolved`, 2FA-Challenge-/Counter-Replay, aktiver OTP-Slot-Bypass |
| `runtime` | **`TA-3` (kompromittiertes/bösartiges App-OS)** | Schreib-/Löschzugriffe aus der laufenden App auf Stage 0/WAL trotz BPROT/MPU/PMP, DMA-/Peripheral-Missbrauch, SRAM-Restsecrets nach Handoff, `.noinit`-Handoff-/Mailbox-Manipulation |
| `build` | Untrusted 3rd-Party/Private Packages | `#undef`/Header-Shadowing, Symbol-Interposition, `.init_array`-Konstruktoren, RWX-Segmente, Heap-Aufrufe, Linker-/CMake-Flag-Injektion |

---

## § 2 — Drei harte Engineering-Leitplanken (Anti-Gaming & Isolation)

### 2.1 Severity-gewichtetes, Root-Cause-dedupliziertes Scoring
Statt „roher Exploit-Anzahl“ (die Varianten-Inflation belohnt) zählt ausschließlich **automatisch gegen einen unveränderten Production-Build verifizierte** Wirkung nach deduplizierter `(Komponente, gebrochene_Invariante, Root-Cause)`:

| Klasse | Gebrochene Security-Invariante | Punkte (Erstfund) | Duplikat (gleicher `root_cause_key`) |
| :--- | :--- | :---: | :---: |
| **`P0`** | Unsignierte Code-Ausführung in Stage 0/1/Recovery/App, K4-WAL-MAC-Bypass, A1/A2-Anti-Rollback-Bypass, Stage-0-Flash-Überschreibung trotz Hardware-Lockdown | **100** | **0** |
| **`P1`** | SRAM-Secret-Leak (`journal_key`, `crypto_arena`, HUK) nach Handoff, Provisioning-/2FA-Bypass, OTFDEC-/Keystore-Bypass, Build-Gate-Bypass (`conformance`/`literallint`/`elfaudit`) | **50** | **0** |
| **`P2`** | Unheilbarer Brick (Verletzung der Non-Brickability-Invariante unter Power-Cut oder malformed Input im Production-Build) | **25** | **0** |
| **`P3`** | Chip-spezifischer Errata-, DMA/D-Cache-COH-, PMP-NAPOT-, Debug- oder TrustZone-Bypass (skaliert nach Impact) | **75** *(40–100)* | **0** |

Theoretische Berichte ohne reproduzierbaren PoC sowie Effekte durch unvollständige Emulator-Modelle (`EMULATOR_MODEL_GAP`) erhalten **0 Punkte**.

### 2.2 Strikte Trennung Red-Team vs. unabhängiger Judge (Anti-Emulator-Tampering)
- Red-Teams erhalten **nur deklarativen Payload-/Szenario-Output**. Änderungen an `toobloader/`, `cmake/`, `cli/`, `toob-go-lib/`, `test/renode_*`, `test/qemu_*` oder `scripts/` werden durch `--verify-clean-target` sofort als `INVALID_SUBMISSION` verworfen.
- Innerhalb von `payload/` sind ausführbare Skripte und Emulator-Definitionen technisch verboten: `.resc`, `.repl`, `.cs`, `.py`, `.ps1`, `.sh`, `.bat`, `.cmd`, `.exe`, `.dll`, `.so`.
- Der **unabhängige Judge (`test/attack_corpus/judge_runner.py`)** baut und startet immer den unveränderten Baseline-Production-Build (`TOOB_PROFILE_PRODUCTION`, `TOOB_DOUBLE_VERIFY=ON`, `TOOB_MOCK_EFUSES=OFF`) in der unveränderten Renode-/QEMU-Instanz und prüft maschinelle Orakel (`oracle.json`).

### 2.3 Physische Workspace-Isolation gegen Team-Spionage
- Jedes Red-Team läuft in einem eigenen isolierten `branch`-Workspace.
- Teams sehen weder andere Team-Branches noch das Judge-Verzeichnis; Kommunikation erfolgt strikt unidirektional `Team -> Judge`.

---

## § 3 — 6 Orthogonale Red-Teams & interne Sub-Rollen

Jedes Team koordiniert intern drei spezialisierte Sub-Rollen (*Recon & CVE/Errata-Researcher* mit Web-Recherche → *Exploit-Engineer* → *Local-Repro-Tester*), greift aber eine orthogonale Domäne an:

1. **Team 1 — Lifecycle, OTA-State-Machine & Power-Cut:** Pre-Boot, Provisioning, Full-/Delta-OTA (TBM1/TDS1/Heatshrink), Swap/Pointer/Oneway-Transport, Torn-Writes, K4-WAL/TMR, Recovery-XMODEM, Rescue-2FA.
2. **Team 2 — Post-Boot / Runtime / Compromised App-OS (`TA-3`):** Angriffe aus einer gültig signierten, aber bösartigen App im aktiven App-Slot (Bare-Metal, FreeRTOS, Zephyr, ESP-IDF, Rust `no_std`): NVMC/Flash-Erase auf Stage 0/WAL, BPROT/MPU/PMP-Umgehung, Mailbox-/`.noinit`-Handoff-Poisoning, SRAM-Secret-Forensik, ungelockte Peripherie/Debug/WDT.
3. **Team 3 — Krypto, Wire-Parser & Formal-vs-C-Drift:** KDM-Quorum, Hybrid-PQC-Pinning, COBS/TCI1/TDR1/TBM1/TDS1-Edge-Cases sowie Unterschiede zwischen Rocq/CBMC-Modellen und realem `-Os`-Maschinencode.
4. **Team 4 — Silicon- & Arch-Spezifische Angriffe (13-Chip-Matrix + Web-Recherche):**
   - **ARM Cortex-M:** `nrf52840`, `rp2040`, `stm32f072`, `stm32f103`, `stm32f429`, `stm32h753`, `stm32l476`, `corstone300`
   - **RISC-V:** `sifive_fe310`, `esp32c3`, `esp32c6`
   - **Xtensa:** `esp32`, `esp32s3`
5. **Team 5 — Supply-Chain & Multi-Package-Composition:** Bösartige Drittanbieter-/Privat-Packages gegen `conformance`, `literallint`, `elfaudit`, CMake-/Linker-Isolation und die 2-Phasen-Firecracker-Pipeline.
6. **Team 6 — Machine-Code Fault Injection (FIH):** Ausweitung von `test/fih_emu/fih_fault_campaign.py` auf ARM/RISC-V/Xtensa-`-Os`-ELFs (Instruction-Skips, Register-Flips, Return-Corruption).

---

## § 4 — Deklaratives Attack-Corpus-Schema (`test/attack_corpus/`)

Jedes bestätigte Exploit-Szenario und jeder dauerhafte Negativ-Regressionstest liegt als selbstbeschreibendes Bundle vor:

```text
test/attack_corpus/
  README.md
  judge_runner.py
  test_judge_runner.py
  ATK-XXXX-<chip>-<phase>-<slug>/
    attack.toml      # Metadaten: id, team, chip, phase, severity_class, threat_assumption,
                     #            runner, verification_scope, expected_outcome,
                     #            invariant_id, root_cause_key, title, references
    scenario.json    # Deklarativer Ablauf: action + Parameter / payload_file / overlays
    oracle.json      # Maschinelle Kriterien: UART-Must/MustNot, BPROT/SRAM-Audit,
                     #                       Stage0-SHA256-Unchanged, Gate-Exit
    payload/         # C-App-Quellen (.c/.h), Binaries (.bin/.toob), Evil-Packages
```

Verdicts pro Bundle: `DEFENDED_PASS`, `EXPLOIT_CONFIRMED`, `EMULATOR_MODEL_GAP`, `INVALID_SUBMISSION`.

---

## § 5 — 4-stufige Testpyramide, Emulator-Grenzen & Rollout-Phasen

1. **Stufe A — `host_sil` & `build_gates`:** Schnelles deterministisches Replay von Parser-, WAL-, TA-1-Negativvektoren (`test/fih_emu/neg_e2e_vectors.c` unter Clang ASan+UBSan) sowie Paket-Kompositionsangriffen (`toob conformance`, `literallint`, `elfaudit`).
2. **Stufe B — Deklarativer Multi-Chip-Emulator-Runner:** Startet unveränderte Production-Builds in Renode (`renode_nrf52840`, …) und QEMU (`qemu_esp32c6`, …) inklusive On-the-Fly-Kompilierung/Signierung bösartiger Gast-Apps für `TA-3`-Runtime-Angriffe und binärer Flash-/UICR-/eFuse-Overlays.
3. **Stufe C — Machine-Code FIH & Handoff-SRAM-Forensik:** Instruktions-Skip- und Register-Flip-Injektion (`test/fih_emu/fih_fault_campaign.py`) sowie vollständiger SRAM-/Arena-/Key-Zeroization-Dump am exakten App-Einsprungpunkt.
4. **Stufe D — Formal Backport:** Jeder durch `EXPLOIT_CONFIRMED` entdeckte Logik-/State-Bug wird nach dem C-Fix als neues Theorem bzw. CBMC-Property in `test/formal/rocq/` und `test/formal/cbmc/` verankert.

### Ehrliche Emulator-Grenzen (`verification_scope`)
Logik-, State-, Parser-, Memory-, BPROT/MPU/PMP-, Runtime-OS- und Single-Instruction-Skip-Bugs sind in Renode/QEMU verlässlich prüfbar. Physikalische EMFI-/Voltage-Glitch-Wellenformen, reale D-Cache-Timing-Races und undokumentierte Silicon-Errata werden im Review explizit als `silicon_audit_required` markiert.

### Rollout-Phasen
- **Phase 0 (Fundament — aktiv):** `docs/red_team_architecture.md`, `test/attack_corpus/` Schema, unveränderbarer `judge_runner.py`, `scripts/run_attack_corpus.ps1` und 6 verifizierte Seed-Bundles (`ATK-0001` .. `ATK-0006`).
- **Phase 1 (Kalibrierter Pilot):** 3 isolierte Teams (Team 1 Lifecycle/Power-Cut, Team 2 Runtime/TA-3, Team 4 `nrf52840` + `esp32c6`/`stm32h753`) über isolierte `branch`-Workspaces gegen den Judge.
- **Phase 2 (Voll-Kampagne & CI):** Alle 6 Teams über die gesamte 13-Chip-Matrix sowie feste Integration des Korpus in `scripts/run_security_suite.ps1`.
