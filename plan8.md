# Backlog — Registry Chip-Packages: Korrektheit, Auflösung & Standardisierung

**Scope:** `toob-registry/registry/chips/*`, neue Driver-Packages unter `drivers/slot/` und `drivers/otp/`, der Manifest-Compiler, sowie zwei klar markierte Core-Tickets (Bringup-Interpreter, ABI-v3-Vorbereitung). Grundlage ist **ARCHITEKTUR-registry-chips.md** — jedes Ticket referenziert den zugehörigen Abschnitt (§).

**Leitprinzip:** Erst den Ist-Zustand vertrauenswürdig machen (EPIC A), dann Code bewegen (EPIC B), dann Struktur erzwingen (EPIC C/D). Kein Big Bang; jede Stufe ist einzeln shipbar (§7).

---

## Legende & Konventionen

**Priorität:** P0 (Korrektheits-/Sicherheitsdefekt, sofort) · P1 (latenter Bug / reale Brick- oder Bypass-Konsequenz) · P2 (Robustheit/Struktur) · P3 (Hygiene/Doku)

**Typ:** `bug` · `security` · `refactor` · `codegen` · `infra` · `dx` · `cleanup` · `spike`

**Aufwand:** S (≤ ½ Tag) · M (1–2 Tage) · L (> 2 Tage / koordiniert)

**Definition of Done (global):**
1. Build grün für Sandbox- **und** Production-Profil des ESP32-C6-Targets.
2. Bei Verhaltensänderung: gezielter Test (Host-Mock, Conformance-Vektor oder ELF-Audit-Case) deckt das alte Fehlverhalten ab.
3. Betroffene Abschnitte in ARCHITEKTUR-registry-chips.md bestätigt oder per PR angepasst (Doku und Code driften nicht).
4. Kein neuer Verstoß gegen die Fail-Fast-Invarianten (§6.5).

---

## Ticket-Übersicht

| ID | Titel | Prio | Typ | Aufwand |
|---|---|---|---|---|
| REG-001 | Mock-Mechanik reparieren: Struct-/TU-Swap statt wirkungslosem `--wrap` | P0 | bug/security | M |
| REG-002 | Adress-Overlap 0x50000000: Confirm-Storage vs. `.noinit` klären & absichern | P0 | bug/security | S–M |
| REG-003 | Delta/Scratch-Kohärenzregel im Manifest-Compiler | P1 | bug/codegen | S |
| REG-004 | XIP-Remap: Register & Größen aus Config statt Hardcode | P1 | bug/security | M |
| REG-005 | TRNG-Sampling-Disziplin (Entropie-Wartezeit) | P1 | security | S |
| REG-006 | Silent Fallbacks eliminieren (Baudrate-`#error`, `get_active_slot` fail-fast) | P1 | bug | S |
| REG-007 | Recovery-Krypto „none": Begründungspflicht + signierter Template-Default | P1 | security | S |
| REG-008 | `hardware.json`-Widersprüche auflösen (`ram_size`, Capability-Semantik) | P2 | bug/cleanup | S |
| REG-009 | Versions-Pins statt `"latest"` in Manifest & Template | P2 | infra | S |
| REG-010 | Panic-Sites unterscheidbar machen | P2 | dx | S |
| REG-011 | Kleinbefunde-Sammelticket (Timeout, Fehlerdomäne, seal_key-Zeroize, WDT-Fenster, Sprache) | P3 | cleanup | S–M |
| REG-020 | Extraktion: `drivers/slot/esp_mmu_remap/` (pointer-Provider) | P1 | refactor | M |
| REG-021 | Extraktion: `drivers/otp/esp_efuse/` (Keystore + Provisioning) | P1 | refactor | M |
| REG-022 | Core: `boot_platform_bringup`-Tabellen-Interpreter | P2 | refactor | M |
| REG-023 | Codegen: `generated_platform_wiring.inc` (Wiring-Emission) | P2 | codegen | L |
| REG-024 | ABI v3 Spike: Crypto-Trait-Entflechtung (crypto/keystore/entropy) | P2 | spike | M |
| REG-030 | JSON-Schemas + CI-Gate für `hardware.json`/`chip_manifest.json` | P1 | infra | M |
| REG-031 | Zahlenformat-Normalisierung + strukturierte Reset-Causes + Register-Blocks | P2 | codegen | M |
| REG-032 | Provenance-Metadaten für Hardware-Konstanten | P2 | infra | S–M |
| REG-033 | Initializer-Makros `TOOB_*_HAL_V2` mit ABI-Stempel | P2 | dx | S |
| REG-034 | `slot_caps` als tagged union (ABI v2.1) | P2 | refactor | M |
| REG-035 | Sprachpolitik: Englisch in Registry-Code | P3 | cleanup | S |
| REG-040 | Literal-Bann-Lint für `chips/` und `drivers/` | P2 | infra | S–M |
| REG-041 | Post-Link-ELF-Audit (Mock-Poison-Pill, Overlap, Budgets) | P1 | infra | M |
| REG-042 | HAL-Conformance-Harness als Registry-Zulassung (+ Mock/Real-Äquivalenz) | P1 | infra | L |

---

# EPIC A — Korrektheit im Ist-Zustand (Stufe 1)

> Diese Tickets machen den heutigen Code vertrauenswürdig, **bevor** er bewegt wird. Kein Strukturumbau.

---

### REG-001 — Mock-Mechanik reparieren: Struct-/TU-Swap statt wirkungslosem `--wrap`
**Prio:** P0 · **Typ:** bug/security · **Aufwand:** M · **Arch-Ref:** §5.4
**Dateien:** `chips/esp32c6/mock_efuse.c` (entfällt), `chips/esp32c6/chip_platform.c`, Build-System

**Problem**
`mock_efuse.c` definiert `__wrap_esp32c6_read_pubkey` etc. — aber `--wrap` greift nur bei vom Linker aufgelösten **globalen** Symbolreferenzen. Die Zielfunktionen sind `static` in `chip_platform.c` und werden ausschließlich über Funktionspointer im `crypto_hal`-Struct referenziert. Der Linker hat nichts umzubiegen: **die Mocks werden nie aufgerufen.** Sandbox-Builds lesen mutmaßlich echte (leere/ungeflashte) eFuse-Register. Zweiter Defekt: Mock- und Real-Kontrakte divergieren — Real-`read_dslc` liefert 1 Byte (`*len >= 1`), Mock liefert 32 Bytes (`*len >= 32`); Real-`read_pubkey` ignoriert `key_index` (statisch KEY0), der Mock implementiert Rotation via Fallback-Key. Rotationstests, die gegen den Mock grün sind, wären auf Silizium rot.

**Root Cause**
Link-Time-Wrapping wurde für ein Referenzmuster gewählt (direkter Call), das im Pointer-basierten HAL-Wiring nicht existiert. Die Kontrakt-Divergenz blieb unentdeckt, weil es keinen Äquivalenztest gibt (→ REG-042).

**Lösung**
1. `mock_efuse.c` und den `--wrap`-Ansatz vollständig entfernen.
2. Übergangslösung bis REG-021: die eFuse-Funktionen in ein eigenes TU-Paar innerhalb des Chip-Packages ziehen (`efuse_real.c` / `efuse_mock.c`) mit **identischer globaler Symbolliste**; Build-Profil (`TOOB_PROFILE=sandbox|production`) wählt die TU. Das Wiring in `chip_platform.c` bleibt unverändert.
3. Kontrakte angleichen: DSLC-Längensemantik festlegen (Entscheidung dokumentieren: 1 Byte oder 32 Bytes — der Core-Konsument `boot_state.c` ist maßgeblich) und in **beiden** TUs identisch implementieren; `key_index`-Verhalten in beiden TUs identisch (entweder beide Rotation oder beide statisch, mit TODO auf echten Multi-Key-Support).
4. Poison-Pill vorziehen (voller Umfang in REG-041): Build bricht ab, wenn `*_mock`-Symbole im Production-Profil landen.

**Akzeptanzkriterien**
- [ ] Sandbox-Build ruft nachweislich die Mock-TU (Testvektor: RFC-8032-Key kommt zurück).
- [ ] Production-Build enthält kein Mock-Symbol (nm-Check).
- [ ] Mock und Real bestehen dieselbe Kontrakt-Vektor-Suite (Längen, key_index, Fehlercodes).
- [ ] `--wrap`-Flags aus dem Build-System entfernt.

---

### REG-002 — Adress-Overlap 0x50000000: Confirm-Storage vs. `.noinit`
**Prio:** P0 · **Typ:** bug/security · **Aufwand:** S–M · **Arch-Ref:** §3.1 R5, §6.3
**Dateien:** `chips/esp32c6/chip_config.h`, `esp32c6_stage1.ld`, `generated_memory.ld` (Compiler), `hardware.json`

**Problem**
`ADDR_CONFIRM_RTC_RAM` zeigt auf `CHIP_REG_RTC_RAM_BASE` = `0x50000000`. Das Linkerscript legt `lp_ram` mit ORIGIN `0x50000000` an und platziert dort `.noinit` (`toob_handoff_state`, `toob_diag_state`). Falls `generated_memory.ld` den Confirm-Bereich nicht explizit auscarvt, schreibt der Confirm-Treiber seine Nonce in die ersten 8 Bytes des Handoff-States — dieselbe Bug-Klasse wie die bestätigte Delta/Scratch-Adresskollision.

**Root Cause**
Fest-Adressen, die der Bootloader beschreibt, sind nirgends als reservierte Regionen deklariert; Linker-Platzierung und Treiber-Adressen werden nie gegeneinander geprüft.

**Lösung**
1. **Sofort verifizieren:** `generated_memory.ld` + Map-File des aktuellen Builds prüfen — überlappt `.noinit` mit `0x50000000 + [0..8)`?
2. Bei Overlap: Confirm-Storage an dedizierte Adresse legen (z. B. letzte 64 Bytes des LP_RAM) **oder** `.noinit`-ORIGIN verschieben; Entscheidung in `hardware.json` als `reserved_ram_regions`-Eintrag kodieren (R5).
3. Unabhängig vom Befund: `reserved_ram_regions` ins Schema aufnehmen und den Manifest-Compiler die Linker-Platzierung dagegen prüfen lassen (Vorstufe des ELF-Audits REG-041 — hier reicht der Codegen-seitige Check).

**Akzeptanzkriterien**
- [ ] Schriftlicher Befund (Overlap ja/nein) mit Map-File-Beleg im Ticket.
- [ ] `hardware.json` deklariert Confirm-Storage als reservierte Region.
- [ ] Compiler bricht ab, wenn eine `.noinit`-/Section-Platzierung eine reservierte Region schneidet (Negativtest vorhanden).

---

### REG-003 — Delta/Scratch-Kohärenzregel im Manifest-Compiler
**Prio:** P1 · **Typ:** bug/codegen · **Aufwand:** S · **Arch-Ref:** §3.2 R7
**Dateien:** Manifest-Compiler, `chips/esp32c6/template_device.toml`

**Problem**
`template_device.toml` setzt `enable_deltas = true` („Force Scratch Slot Generation") auf einem Chip, dessen Manifest `has_scratch: false` deklariert. Genau diese Config-Inkohärenz ist der Brutkasten der bestätigten Delta/Scratch-Adresskollision.

**Lösung**
1. Compiler-Regel: `enable_deltas = true` ist nur gültig, wenn `slot_capabilities.has_scratch == true` **oder** das `exec_model` eine deklarierte scratch-lose Delta-Strategie besitzt. Sonst Build-Abbruch mit Erklärtext (welcher Chip, welche Fähigkeit fehlt, welche Optionen bestehen).
2. `template_device.toml` korrigieren: entweder `enable_deltas = false` oder die scratch-lose Strategie explizit konfigurieren.

**Akzeptanzkriterien**
- [ ] Negativtest: heutiges Template gegen heutiges Manifest bricht mit verständlicher Meldung.
- [ ] Positivtest: kohärente Konfiguration baut durch.

---

### REG-004 — XIP-Remap: Register & Größen aus Config statt Hardcode
**Prio:** P1 · **Typ:** bug/security · **Aufwand:** M · **Arch-Ref:** §5.1, §3.1 R2
**Dateien:** `chips/esp32c6/chip_platform.c` (bis REG-020), `hardware.json`

**Problem**
`esp32c6_xip_remap_commit` schreibt MMU-/Cache-Register als nackte Literale (`0x60002380`, `0x6000237C`, `0x600C8098–A4`, `0x42000000`) — Konventionsbruch gegen „alle Adressen aus hardware.json". Gravierender: die Schleife mappt fest **6 Pages = 384 KB** und synct fest **393216 Bytes**, während `app_size` im Geräte-TOML konfigurierbar ist. Ändert ein Kunde `app_size`, remappt der Bootloader still zu wenig oder zu viel — je nach Richtung nicht ausgeführter App-Code oder fremde Flash-Inhalte im XIP-Fenster.

**Lösung**
1. MMU-Index/-Content-Register, Cache-Sync-Registerblock, XIP-Base, Page-Size und Valid-Bit-Maske nach `hardware.json` (`register_blocks`, R2).
2. Page-Count = `CHIP_APP_SLOT_SIZE / CHIP_MMU_PAGE_SIZE` (Codegen-Konstante, mit Compile-Assert auf Teilbarkeit); Sync-Size = `CHIP_APP_SLOT_SIZE`.
3. Timeout zeitbasiert über `clock_hal->get_tick_ms` statt Iterationszähler; Fehlerdomäne korrigieren (nicht `BOOT_ERR_FLASH_HW`, sondern `BOOT_ERR_STATE` oder neuer MMU-Fehlercode).

**Akzeptanzkriterien**
- [ ] Keine numerischen Register-Literale mehr in der Funktion (Vorgriff auf REG-040).
- [ ] Host-/HIL-Test: `app_size`-Änderung im TOML ändert Page-Count und Sync-Size nachweislich mit.
- [ ] `_Static_assert`: `CHIP_APP_SLOT_SIZE % CHIP_MMU_PAGE_SIZE == 0`.

---

### REG-005 — TRNG-Sampling-Disziplin
**Prio:** P1 · **Typ:** security · **Aufwand:** S · **Arch-Ref:** §6.5
**Dateien:** `chips/esp32c6/chip_platform.c` (RNG-Teil; wandert später mit REG-024/021)

**Problem**
`esp32c6_hw_random` liest `CHIP_REG_RNG_DATA_REG` in einer engen Schleife. Espressifs TRNG liefert nur bei begrenzter Leserate volle Entropie; Back-to-back-Reads liefern korrelierte Werte. Aus dieser Quelle stammen `seal_key` (Stage-1→OS-Proof) und perspektivisch die per-Boot-randomisierten CFI-Tokens — das ist Sicherheits-, keine Stilfrage. Zusätzlich: der Kommentar beschreibt den ESP32 (Original), nicht den C6 — Copy-Paste-Drift, die genau die falsche Timing-Annahme transportieren kann.

**Lösung**
1. Zwischen Word-Reads eine dokumentierte Mindestwartezeit einziehen (systimer-basiert; Wert gegen C6-TRM verifizieren, nicht vom ESP32 übernehmen).
2. Kommentar auf C6 korrigieren, TRM-Referenz + Provenance angeben (Vorgriff auf REG-032).
3. Testbarkeit: im Sandbox-Profil einen einfachen Monobit-/Repeat-Check über N Samples als Smoke-Test (kein NIST-Suite-Anspruch — nur „nicht offensichtlich korreliert").

**Akzeptanzkriterien**
- [ ] Reads sind zeitlich beabstandet; Wartezeit als benannte Konstante mit TRM-Referenz.
- [ ] Kommentarblock beschreibt den C6, nicht den ESP32.
- [ ] Smoke-Test vorhanden.

---

### REG-006 — Silent Fallbacks eliminieren
**Prio:** P1 · **Typ:** bug · **Aufwand:** S · **Arch-Ref:** §6.5
**Dateien:** `chips/esp32c6/chip_platform.c`

**Problem**
Zwei Verstöße gegen die eigene Fail-Fast-Philosophie: (1) Fehlt `TOOB_DRIVER_UART_BAUDRATE`, fällt die Console-Init still auf `115200U` zurück — ein kaputter Codegen-Lauf wird maskiert statt gemeldet. (2) `esp32c6_get_active_slot` defaultet bei nicht klassifizierbarem MMU-Zustand (weder App- noch Staging-Base) still auf Slot 0 — ein Anomalie-Signal wird geschluckt.

**Lösung**
1. `#else`-Zweig durch `#error "TOOB_DRIVER_UART_BAUDRATE missing — manifest compiler output incomplete"` ersetzen.
2. `get_active_slot`: nicht klassifizierbarer, aber als valid markierter MMU-Eintrag ⇒ `BOOT_ERR_STATE`. (Invalid-Bit ⇒ Slot 0 bleibt korrekt: das ist der definierte Kaltstart-Zustand.)

**Akzeptanzkriterien**
- [ ] Build ohne Baudraten-Makro bricht mit `#error`.
- [ ] Host-Test: MMU-Content mit fremder Page-Adresse ⇒ `BOOT_ERR_STATE`, kein Slot-0-Default.

---

### REG-007 — Recovery-Krypto „none": Begründungspflicht + signierter Default
**Prio:** P1 · **Typ:** security · **Aufwand:** S · **Arch-Ref:** §3.2 R8
**Dateien:** `chips/esp32c6/chip_manifest.json`, `template_device.toml`, Manifest-Compiler

**Problem**
`recovery.crypto.backend = "none"` steht als Default in Manifest **und** Template. Ein unsigniertes Recovery ist ein potenzieller Unsigned-Code-Execution-Pfad am signierten Boot vorbei — als Template-Default wird eine Security-Posture-Entscheidung normalisiert, die bewusst getroffen werden muss.

**Lösung**
1. Compiler: `backend = "none"` im Recovery-Block erfordert Pflichtfeld `justification` (String, nicht leer); fehlt es ⇒ Abbruch.
2. Architektur-Entscheidung dokumentieren: **ist** das C6-Recovery-Image Teil des Stage-1-Merkle-Baums (dann ist „none" vertretbar und die Begründung lautet genau das) oder nicht (dann Default auf `sha256_sw` + Signatur drehen)?
3. Template auf den begründeten bzw. signierten Zustand bringen.

**Akzeptanzkriterien**
- [ ] „none" ohne Begründung bricht den Build.
- [ ] Entscheidung (Merkle-gedeckt ja/nein) schriftlich im Manifest-Kommentar/Doku.

---

### REG-008 — `hardware.json`-Widersprüche auflösen
**Prio:** P2 · **Typ:** bug/cleanup · **Aufwand:** S · **Arch-Ref:** §3.1 R3
**Dateien:** `chips/esp32c6/hardware.json`

**Problem**
(1) `memory.ram_size = "0x8000"` (32 KB) widerspricht dem Linkerscript (496 KB IRAM) — vermutlich meint das Feld LP_RAM oder ist schlicht falsch; der Codegen könnte darauf Entscheidungen treffen. (2) `crypto_capabilities.hw_sha256 = true` widerspricht dem Code-Kommentar („no HW SHA on C6 BootROM") und `has_hw_acceleration = false` — Silizium-Präsenz und Boot-Nutzbarkeit sind vermengt. (3) `"description": "Derived from scan: skipped"` ist ein Scan-Artefakt als Produktionstext.

**Lösung**
1. `memory` korrigieren und eindeutig benennen (`iram_base/iram_size`, `lp_ram_base/lp_ram_size`).
2. Capabilities auf Zwei-Ebenen-Schema (R3: `hw_present`/`boot_usable`/`note`) heben; `has_hw_acceleration` wird vom Codegen aus `boot_usable` abgeleitet.
3. Scan-Artefakte durch echte Beschreibungen ersetzen (Region 0: „BootROM/Stage-0-Bereich, von Slot-Vergabe ausgenommen" o. ä.) — Provenance-Kennzeichnung folgt in REG-032.

**Akzeptanzkriterien**
- [ ] Kein Feld widerspricht Linkerscript oder Code-Kommentaren.
- [ ] `hw_present`/`boot_usable` für alle Crypto-Capabilities gesetzt.

---

### REG-009 — Versions-Pins statt `"latest"`
**Prio:** P2 · **Typ:** infra · **Aufwand:** S · **Arch-Ref:** §3.2 R6
**Dateien:** `chip_manifest.json`, `template_device.toml`, Manifest-Compiler

**Problem**
`"min_compiler": "latest"` und `core_sdk = "latest"` sind als *Minimum* semantisch leer und nicht reproduzierbar — dieselbe Fehlerklasse wie der im CLI gefixte Lockfile-Bypass. Templates leben Pinning nicht vor.

**Lösung**
Schema lehnt `"latest"` in `min_*`-Feldern ab; Manifest und Template auf konkrete Versionen pinnen (`core/vX.Y.Z`, Compiler-Mindestversion). `latest` bleibt zulässig ausschließlich als explizite *Auflösungs*-Anweisung in Nicht-`min_`-Feldern, die das CLI zum Lock-Zeitpunkt in einen Pin übersetzt.

**Akzeptanzkriterien**
- [ ] Schema-Negativtest: `"min_compiler": "latest"` wird abgelehnt.
- [ ] ESP32-C6-Manifest + Template gepinnt.

---

### REG-010 — Panic-Sites unterscheidbar machen
**Prio:** P2 · **Typ:** dx · **Aufwand:** S · **Arch-Ref:** §5.3
**Dateien:** `chips/esp32c6/chip_platform.c` (übergangsweise), Core-`site_id`-Enum

**Problem**
Clock-, WDT- und Confirm-Init-Fehlschlag panicken alle mit `BOOT_ERR_STATE`. Ein Feld-Forensik-Record sagt damit nur „irgendwas bei Init" — die vorhandene site_id-Infrastruktur wird an dieser Stelle nicht genutzt.

**Lösung**
Pro Bringup-Schritt eine eigene site_id (`SITE_BRINGUP_CLOCK`, `SITE_BRINGUP_WDT`, …) vergeben und an `boot_panic` durchreichen. (Wird mit REG-022 strukturell; dieses Ticket ist der sofort wirksame Vorgriff.)

**Akzeptanzkriterien**
- [ ] Jeder Init-Fehlschlag erzeugt einen im Forensik-Record eindeutig zuordenbaren Site-Code.

---

### REG-011 — Kleinbefunde-Sammelticket
**Prio:** P3 · **Typ:** cleanup · **Aufwand:** S–M · **Arch-Ref:** §6.5, §3.4
**Dateien:** `chip_platform.c`, `startup.c`, `chip_config.h`, `hardware.json`

**Inhalt (je eigener Commit, gemeinsamer PR):**
1. `seal_key` nach `boot_proof_verify` und vor `jump_to_os` zeroizen (`boot_ct_utils`-Zeroize; sensitives Material liegt sonst lesbar auf dem Stage-1-Stack im OS).
2. WDT-freies Fenster dokumentieren: zwischen `wdt_sterilize_all` und `wdt->init` (nach Clock+Flash) hängt ein Flash-Init-Hang permanent. Bewusste Abwägung als Kommentar an beide Stellen; prüfen, ob SWD-Auto-Feed statt Voll-Sterilisierung das Fenster schließen kann, ohne die BootROM-Timeout-Gefahr zurückzuholen.
3. `verify_signature_ph`-Feldausrichtung reparieren (Handedit-Spur; erledigt sich endgültig mit REG-033).
4. WDT-Register-Offsets aus `chip_config.h` nach `hardware.json` (R2; finaler Entfall des Shims mit REG-023).
5. Typo „brcking"; ESP32-vs-C6-Kommentardrift (mit REG-005 koordinieren); deutsche Kommentare in Registry-Dateien auf Englisch (Umsetzungsdetail von REG-035).

**Akzeptanzkriterien**
- [ ] Alle fünf Punkte einzeln nachvollziehbar committet.

---

# EPIC B — Auflösung von `chip_platform.c` (Stufen 2–4)

---

### REG-020 — Extraktion: `drivers/slot/esp_mmu_remap/`
**Prio:** P1 · **Typ:** refactor · **Aufwand:** M · **Arch-Ref:** §2.2, §5.1
**Abhängigkeit:** REG-004 (Fixes wandern mit, nicht doppelt)

**Problem**
Slot-Operationen (`xip_remap_commit`, `get_active_slot`) sind der größte und gefährlichste Codeblock in `chip_platform.c` — und der einzige Treiber, der nicht als Package existiert, obwohl UART/Flash/WDT/RTC/Clock es längst sind.

**Lösung**
1. Neues Package `drivers/slot/esp_mmu_remap/` mit eigenem Manifest (deklariert: bedient `slot_caps`, `exec_model: xip_remap`, ABI v2), globalen Symbolen `esp_mmu_remap_commit` / `esp_mmu_get_active_slot`.
2. `chip_manifest.json`: Treiber unter `sources.drivers` referenzieren; `slot_capabilities` bleibt die deklarative Quelle.
3. Conformance-Vektoren beilegen (Remap auf Slot-0-/Slot-1-Adresse, fremde Adresse ⇒ Fehler, Timeout-Pfad) — Zulassungsgrundlage für REG-042.
4. Einordnung: dieses Package ist die **pointer-Provider-Bindung** des Slot-Transport-Systems; Naming und Ops-Signaturen mit den vier Core-Providern (`swapscratch`, `oneway`, `swapmove`, `pointer`) abstimmen.

**Akzeptanzkriterien**
- [ ] `chip_platform.c` enthält keine Slot-Logik mehr.
- [ ] Package baut eigenständig, Conformance-Vektoren grün.
- [ ] `template_device.toml`-Build des C6 verhält sich bit-identisch (Map-File-Diff der relevanten Sections).

---

### REG-021 — Extraktion: `drivers/otp/esp_efuse/`
**Prio:** P1 · **Typ:** refactor · **Aufwand:** M · **Arch-Ref:** §2.2, §5.2, §5.4
**Abhängigkeit:** REG-001 (TU-Paar wird hierhin verschoben), REG-011.4 (Offsets im JSON)

**Problem**
eFuse-Lesezugriffe, Provisioning-Stubs und die Mock-TU leben verstreut im Chip-Package statt als versionierbares OTP-Driver-Package.

**Lösung**
1. Neues Package `drivers/otp/esp_efuse/` mit `esp_efuse.c` (real) + `esp_efuse_mock.c` (Profil-gewählt), identische Symbolliste/Kontrakte (aus REG-001 übernommen).
2. Registeradressen (`EFUSE_BLK_KEY0_DATA0`, `SYS_DATA_PART2`) via `register_blocks` aus `hardware.json`.
3. Provisioning-Stubs (NOT_SUPPORTED bis ROM-Call-Integration) mitziehen; Fähigkeitsstand im Package-Manifest deklarieren (`"provisioning": "stubbed"`), nicht nur im Kommentar.
4. Perspektive dokumentieren: dieses Package wird mit ABI v3 (REG-024) der `keystore_hal_t`-Provider.

**Akzeptanzkriterien**
- [ ] `chip_platform.c` enthält keine eFuse-/Provisioning-Logik mehr.
- [ ] Mock/Real-Kontrakt-Suite (aus REG-001) läuft im Package-CI.
- [ ] Production-ELF weiterhin mock-frei (nm-Check).

---

### REG-022 — Core: `boot_platform_bringup`-Tabellen-Interpreter
**Prio:** P2 · **Typ:** refactor (Core-Ticket) · **Aufwand:** M · **Arch-Ref:** §5.3
**Abhängigkeit:** REG-010 (site_ids existieren)

**Problem**
Jedes Chip-Package re-implementiert dieselbe geordnete Init-Sequenz mit denselben Panic-Mappings — n Kopien einer normativen Regel (`hals.md`).

**Lösung**
1. Core-API `boot_platform_bringup(platform, steps[], n)` mit `bringup_step_t { kind, mandatory, panic_site }` (Signatur siehe Architektur §5.3).
2. Interpreter ruft pro Schritt das `init()` des Traits (Dispatch über `kind`), panickt bei Pflicht-Fehlschlag mit dem schritt-eigenen `panic_site`, toleriert optionale Fehlschläge (Console) mit Diag-Vermerk.
3. Chip-seitig schrumpft `boot_platform_init` auf: Interrupts aus → Tabelle definieren → `boot_platform_bringup` → Plattform zurückgeben.
4. Konsistenz-Guard im Core: Tabelle muss die normative Reihenfolge einhalten (`_Static_assert`-artige Laufzeitprüfung im Debug-Profil oder Codegen-Garantie ab REG-023).

**Akzeptanzkriterien**
- [ ] C6-`boot_platform_init` enthält keine eigene Sequenz-/Panic-Logik mehr.
- [ ] Host-Test: Pflicht-HAL-Fehlschlag an Position k erzeugt Forensik-Record mit site_id von Schritt k.
- [ ] `hals.md` referenziert den Interpreter als einzige normative Implementierung.

---

### REG-023 — Codegen: `generated_platform_wiring.inc`
**Prio:** P2 · **Typ:** codegen · **Aufwand:** L · **Arch-Ref:** §5.5
**Abhängigkeit:** REG-020, REG-021, REG-022, REG-033; REG-030 dringend empfohlen

**Problem**
Nach den Extraktionen ist `chip_platform.c` reine Struct-Montage aus Informationen, die die Manifeste bereits enthalten — handgepflegte Redundanz mit Drift-Risiko.

**Lösung**
1. Manifest-Compiler emittiert `generated_platform_wiring.inc`: Trait-Instanzen via `TOOB_*_HAL_V2`-Makros aus den referenzierten Driver-Symbolen, `boot_platform_t`-Montage, Bringup-Tabelle, minimales `boot_platform_init()`.
2. `chip_config.h`-Aliase (WDT-Register für `startup.c`, `ADDR_CONFIRM_RTC_RAM`) in den Codegen übernehmen; Shim-Datei entfällt.
3. Out-of-Tree-Escape dokumentieren: handgeschriebenes Wiring bleibt möglich (gleiche Makros), Registry-Packages nutzen den Codegen verpflichtend.
4. `chip_platform.c` aus dem ESP32-C6-Package löschen; `sources.platform` im Manifest-Schema optional machen (nur noch Out-of-Tree).

**Akzeptanzkriterien**
- [ ] C6 baut vollständig ohne handgeschriebenes `chip_platform.c`/`chip_config.h`.
- [ ] Generat ist deterministisch (zweimal generieren ⇒ byte-identisch; Reproduzierbarkeits-Anforderung wie im CLI).
- [ ] Diff-Test: generiertes Wiring vs. letztes Hand-Wiring funktional identisch (HIL-Smoke-Boot).

---

### REG-024 — ABI v3 Spike: Crypto-Trait-Entflechtung
**Prio:** P2 · **Typ:** spike (Core-Koordination) · **Aufwand:** M · **Arch-Ref:** §4.3
**Abhängigkeit:** REG-021 (Keystore-Provider existiert als Package)

**Problem**
`crypto_hal_t` mischt Algorithmen, Keystore/OTP und Entropie. Das koppelt die Zertifizierungs-Profilgrenze (`default`/`cnsa`/`fips`) an Keystore-Details und macht Profil-Swaps invasiver als nötig.

**Lösung (Spike, keine Umsetzung)**
1. Header-Entwurf: `crypto_hal_t` (nur Algorithmen), `keystore_hal_t`, `entropy_hal_t`; `provisioning_hal_t`-Konsolidierung in den Keystore-Provider prüfen.
2. Migrationsplan: v2-Kompatibilitäts-Shim (v3-Traits hinter v2-Fassade) vs. harter Schnitt; Auswirkung auf `boot_platform_t`, Codegen (REG-023) und bestehende Chips.
3. Entscheidungsvorlage inkl. Zertifizierungs-Sicht: bestätigt der Schnitt, dass ein `cnsa`-/`fips`-Profilwechsel ein reiner `crypto/`-Package-Swap ist?

**Akzeptanzkriterien**
- [ ] Header-Entwurf + Migrationsplan + Entscheidungsvorlage liegen vor; Go/No-Go für v3 dokumentiert.

---

# EPIC C — Format- & Schema-Standardisierung

---

### REG-030 — JSON-Schemas + CI-Gate
**Prio:** P1 · **Typ:** infra · **Aufwand:** M · **Arch-Ref:** §3.1, §3.2, §6.1

**Lösung**
1. Formale Schemas für `hardware.json` (R1–R5) und `chip_manifest.json` (R6–R8); TOML-Validierung für `template_device.toml` (Partitions-Arithmetik, Pflichtfelder).
2. CI: jeder Registry-PR validiert alle Manifeste; Schema-Versionierung (`"schema": 1`) für spätere Migrationen.
3. Bestands-Manifeste (C6 + weitere Chips) migrieren.

**Akzeptanzkriterien**
- [ ] Alle Regeln R1–R8 maschinell geprüft (je ein Negativtest pro Regel).
- [ ] CI-Gate aktiv; Bestand valide.

---

### REG-031 — Zahlenformat, Register-Blocks, strukturierte Reset-Causes
**Prio:** P2 · **Typ:** codegen · **Aufwand:** M · **Arch-Ref:** §3.1 R1/R2/R4
**Abhängigkeit:** REG-030 (Schema trägt die neuen Formen)

**Lösung**
1. `hardware.json` auf einheitliches Zahlenformat normalisieren (Adressen/Masken hex-string, Größen dezimal).
2. `registers` → `register_blocks` mit base+regs-Offsets (R2); Codegen emittiert daraus `CHIP_REG_<BLOCK>_<REG>`-Makros — die WDT-Alias-Ableitungen aus `chip_config.h` entstehen dann generiert.
3. `rst_*`-Flachkonstanten → `reset_causes`-Map mit `class`-Tag (R4); Codegen emittiert Konstanten **und** Klassifizierungstabelle für `boot_state.c` (crash/intentional/power — direkt anschlussfähig an die P7b-Crash-Attribution).

**Akzeptanzkriterien**
- [ ] C6-`hardware.json` vollständig migriert; Codegen-Output deckt alle bisherigen Makros (Diff-Liste leer).
- [ ] Reset-Klassifizierung wird aus dem JSON generiert, nicht mehr im C-Code gepflegt.

---

### REG-032 — Provenance-Metadaten
**Prio:** P2 · **Typ:** infra · **Aufwand:** S–M · **Arch-Ref:** §3.3

**Lösung**
1. `provenance`-Objekt (source/ref/verified) für `register_blocks`, `reserved_ram_regions`, Timing-Konstanten ins Schema.
2. Compiler-Verhalten: `source: scan` ⇒ Warnung im Production-Profil („unverified hardware constant"); Whitelist pro Wert nach manueller TRM-Verifikation.
3. C6-Bestand kennzeichnen (ehrlich: was stammt aus toobfuzzer-Blueprints, was ist TRM-verifiziert?).
4. Export: Compiler kann eine Provenance-Tabelle (CSV/MD) emittieren — CRA-Evidenz-Baustein für die Technical Documentation.

**Akzeptanzkriterien**
- [ ] Schema + Warnverhalten umgesetzt; C6 vollständig gekennzeichnet.
- [ ] Provenance-Export vorhanden.

---

### REG-033 — Initializer-Makros `TOOB_*_HAL_V2`
**Prio:** P2 · **Typ:** dx · **Aufwand:** S · **Arch-Ref:** §4.4

**Lösung**
Pro Trait ein Initializer-Makro (setzt `abi_version` automatisch, Pflichtfelder positional, Optionales via `__VA_ARGS__`); C6-Wiring darauf umstellen (übergangsweise von Hand, ab REG-023 als Codegen-Zielsprache).

**Akzeptanzkriterien**
- [ ] Kein handgesetztes `abi_version`-Feld mehr im C6-Wiring.
- [ ] Vergessenes Pflichtfeld ⇒ Compile-Fehler (Negativtest).

---

### REG-034 — `slot_caps` als tagged union (ABI v2.1)
**Prio:** P2 · **Typ:** refactor (Core-koordiniert) · **Aufwand:** M · **Arch-Ref:** §4.2
**Abhängigkeit:** REG-020; Koordination mit dem Slot-Transport-Strang (vier Provider)

**Lösung**
1. `slot_caps_t` auf exec_model-getaggte union umstellen (Struktur siehe Architektur §4.2); `get_active_slot` bleibt gemeinsame Pflicht.
2. Core-Dispatch ausschließlich über den Tag; Initializer-Makros pro Modell (`TOOB_SLOT_CAPS_XIP_REMAP(...)` etc.), die nur den passenden union-Zweig befüllen können.
3. Alle bestehenden Provider-Bindungen migrieren.

**Akzeptanzkriterien**
- [ ] „Falscher Pointer fürs Modell" ist nicht mehr repräsentierbar (Compile-Negativtest).
- [ ] C6 (pointer/xip_remap) läuft unverändert (HIL-Smoke).

---

### REG-035 — Sprachpolitik: Englisch in Registry-Code
**Prio:** P3 · **Typ:** cleanup · **Aufwand:** S · **Arch-Ref:** §3.4

**Lösung**
Alle Code-Kommentare und Manifest-Texte in `registry/` auf Englisch; CONTRIBUTING-Notiz („English in registry code, German allowed in internal docs"); optional ein einfacher CI-Heuristik-Check (Umlaut-/ß-Scan in `.c/.h/.json` unter `registry/`).

**Akzeptanzkriterien**
- [ ] C6-Package kommentarseitig englisch; Policy dokumentiert.

---

# EPIC D — Verifikations-Gates

---

### REG-040 — Literal-Bann-Lint
**Prio:** P2 · **Typ:** infra · **Aufwand:** S–M · **Arch-Ref:** §6.2
**Abhängigkeit:** REG-031 (Makro-Deckung), sonst false positives

**Lösung**
1. Lint (clang-query/Regex-Hybrid) über `chips/` und `drivers/`: numerische Literale außer 0/1 und Schleifen-/Shift-Idiomen sind Fehler; jede Adresse/Maske/Größe muss aus `generated_boot_config.h` stammen.
2. Whitelist-Mechanismus mit Pflicht-Begründungskommentar (`/* lint-allow: <reason> */`) für seltene legitime Fälle.
3. CI-Gate; Bestand bereinigen (nach REG-004/031 sollte die Liste kurz sein).

**Akzeptanzkriterien**
- [ ] Der alte `xip_remap_commit`-Stand schlägt im Lint fehl (Regressionstest mit eingefrorenem Snapshot).
- [ ] C6-Bestand lint-clean oder begründet gewhitelistet.

---

### REG-041 — Post-Link-ELF-Audit
**Prio:** P1 · **Typ:** infra · **Aufwand:** M · **Arch-Ref:** §6.3
**Abhängigkeit:** REG-002 (reserved_ram_regions existieren), REG-001 (Mock-Symbolkonvention)

**Lösung**
1. Skript (nm/readelf) nach jedem Link, drei Prüfungen: **(a)** Mock-Poison-Pill — keine `*_mock`-Symbole im Production-Profil; **(b)** Adress-Overlap — Section-Platzierung (`.noinit`, Stacks) gegen alle `reserved_ram_regions`; **(c)** Budgets — Sektionsgrößen gegen `stage1_size`/Partitionen aus dem Geräte-TOML.
2. In den `toob`-CLI-Build-Flow integrieren (läuft lokal wie in CI identisch — Reproduzierbarkeits-Linie des CLI fortgesetzt).
3. Je Prüfung ein konstruierter Negativ-Case im CI (absichtlich verletzendes Test-Target).

**Akzeptanzkriterien**
- [ ] Alle drei Prüfungen mit Negativ-Cases grün/rot wie erwartet.
- [ ] Audit läuft verpflichtend in CI und im CLI-Build.

---

### REG-042 — HAL-Conformance-Harness als Registry-Zulassung
**Prio:** P1 · **Typ:** infra · **Aufwand:** L · **Arch-Ref:** §6.4
**Abhängigkeit:** REG-020/021 (erste Packages als Pilot), REG-030 (Manifest-Deklarationen)

**Problem**
Es gibt keinen maschinellen Nachweis, dass ein Chip-/Driver-Package die HAL-Verträge einhält — Vertragstreue ist heute Hoffnung plus Review. Der Mock-Befund (REG-001) zeigt die Konsequenz.

**Lösung**
1. Harness-Firmware + Host-Runner: pro Trait eine Vektor-Suite (Fehlercode-Semantik, Grenzwerte/Alignment, deklarierte Timings vs. Messung wo HIL verfügbar; Flash: erased_value/write_align-Verhalten; Slot: Remap-/Fehlerpfade; OTP: Längen-/Index-Kontrakte).
2. **Mock/Real-Äquivalenz als Pflichtteil:** beide TUs eines Packages durchlaufen dieselbe Suite; jede Divergenz (Längen, Indizes, Fehlercodes) ist ein Zulassungs-Fail.
3. Registry-Policy: Package-Publish erfordert grünen Conformance-Lauf (Ergebnis-Artefakt wird dem Package beigelegt — zugleich Vertrauens-/Marketing-Asset für Community-Ports und CRA-Evidenz).
4. Pilot: `esp_mmu_remap` + `esp_efuse`, dann Bestandstreiber (uart/flash/wdt/rtc/clock) nachziehen.

**Akzeptanzkriterien**
- [ ] Harness läuft für beide Pilot-Packages; Ergebnis-Artefakt im Package.
- [ ] Publish ohne grünen Lauf wird von der Registry abgelehnt.
- [ ] Der alte Mock/Real-Divergenzfall (DSLC 1 B vs. 32 B) schlägt als Regressionstest fehl.

---

## Empfohlene Reihenfolge (abhängigkeitsbewusst)

**Sprint 1 — „Trust the ground" (Stufe 1):**
`REG-001` → `REG-002` → `REG-003` → `REG-006` → `REG-007` → `REG-005` → `REG-004` → `REG-010` → `REG-008`/`REG-009` → `REG-011`.

**Sprint 2 — Extraktion + erste Gates (Stufe 2):**
`REG-020` → `REG-021` → `REG-041` (Poison-Pill + Overlap jetzt strukturell) → `REG-030`.

**Sprint 3 — Core & Schema-Tiefe (Stufe 3):**
`REG-022` → `REG-031` → `REG-033` → `REG-034` → `REG-032` → `REG-040`.

**Sprint 4 — Generierung & Zulassung (Stufe 4):**
`REG-023` → `REG-042` → `REG-035` → parallel `REG-024` (ABI-v3-Entscheidung).

---

## Architektur-Merksatz für neue Mitarbeiter

Ein Chip-Package **beschreibt** Hardware — es implementiert keine Logik, die der Core orchestrieren (Bringup), ein Driver-Package kapseln (Slot/OTP/Quirks) oder der Manifest-Compiler generieren kann (Wiring, Konstanten, Linker-MEMORY). Alle Zahlen kommen aus `hardware.json` mit Provenance; alle Verträge werden maschinell geprüft (Schema, Lint, ELF-Audit, Conformance), nicht gehofft. Wer eine Adresse in eine `.c`-Datei tippt, hat mit hoher Wahrscheinlichkeit die falsche Datei offen.