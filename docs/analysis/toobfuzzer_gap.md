# Toobfuzzer Integration — Cross-Document Gap Analysis

> **Fokus:** Logische Verbindungen zwischen `toobfuzzer_integration.md` und dem gesamten Dokumentations-Ökosystem.  
> **Datum:** 2026-03-31  
> **Analysierte Dokumente:** Alle in `docs/index.md` verlinkten Dateien, gelesen von Anfang bis Ende.

---

## Methodik

Jeder Gap wird nummeriert und enthält:

1. **Problem** — Was genau unstimmig, lückenhaft oder widersprüchlich ist.
2. **Betroffene Dokumente** — Wo der Konflikt/die Lücke auftritt.
3. **Mitigation** — Die beste Lösung.

---

## GAP-F01: `blueprint.json` Schema — Fehlende Felder vs. `concept_fusion.md` Kapitel 6.1

**Problem:** `concept_fusion.md` (Kap. 6.1) definiert eine **explizite Pflichtliste** an Daten, die der Toobfuzzer pro HAL-Trait liefern MUSS:

| HAL Trait       | Geforderte Daten in `concept_fusion.md` 6.1                                                         | In `toobfuzzer_integration.md` Blueprint-Schema vorhanden?                                                                  |
| --------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `flash_hal_t`   | `sector_size`, `write_align`, `app_alignment`, Flash Base, ROM-Pointer Erase/Write, Unlock-Routinen | ✅ `write_alignment_bytes`, `app_alignment_bytes`, `erase_sector_sequence` — **aber `Flash Base Address` fehlt im Schema!** |
| `clock_hal_t`   | Hex-Adresse Reset-Reason Register + Bit-Masken (WDT, SOFTWARE, BROWNOUT), Tick-Counter              | ❌ **Komplett fehlend** im `blueprint.json` Schema                                                                          |
| `wdt_hal_t`     | Feed/Kick Register (Hex-Adresse) + Magic-Value                                                      | ❌ **Komplett fehlend** im `blueprint.json` Schema                                                                          |
| `confirm_hal_t` | Hex-Adresse Survival-Storage (RTC-RAM)                                                              | ❌ **Komplett fehlend** im `blueprint.json` Schema                                                                          |
| `crypto_hal_t`  | ROM-Pointer für HW-SHA `init/update/finish`                                                         | ❌ **Komplett fehlend** im `blueprint.json` Schema                                                                          |

Das `concept_fusion.md` Kapitel 6.2 zeigt sogar eine fertige `chip_config.h` mit `REG_RESET_REASON`, `REG_WDT_FEED`, `VAL_WDT_KICK`, `ADDR_CONFIRM_RTC_RAM` — diese Werte werden nirgends im `toobfuzzer_integration.md` Schema dokumentiert.

**Betroffene Dokumente:** `toobfuzzer_integration.md` (Sektion 2B), `concept_fusion.md` (Kap. 6.1 + 6.2)

**Mitigation:** Das `blueprint.json` Schema in `toobfuzzer_integration.md` muss **alle 5 HAL-Trait-Datenquellen** vollständig abbilden. Mindestens folgende Toplevel-Keys fehlen im dokumentierten Schema:

```json
"reset_reason": { "register_address": "0x...", "wdt_mask": "0x...", ... },
"watchdog": { "feed_register": "0x...", "kick_value": "0x..." },
"confirm_storage": { "rtc_ram_address": "0x..." },
"crypto_rom_pointers": { "sha_init": "0x...", "sha_update": "0x...", "sha_finish": "0x..." }
```

---

## GAP-F02: `request.md` (Stage 4 Prompt) definiert ein ANDERES Schema als `toobfuzzer_integration.md`

**Problem:** `request.md` enthält das tatsächliche Stage 4 JSON-Schema, das der Fuzzer produziert. Dieses Schema hat **komplett andere Keys** als das in `toobfuzzer_integration.md` gezeigte:

| Key                                             | In `request.md` Stage 4 | In `toobfuzzer_integration.md` |
| ----------------------------------------------- | ----------------------- | ------------------------------ |
| `flash_capabilities.write_alignment_bytes`      | ✅                      | ✅                             |
| `flash_capabilities.app_alignment_bytes`        | ✅                      | ✅                             |
| `flash_capabilities.is_dual_bank`               | ✅                      | ❌                             |
| `flash_capabilities.read_while_write_supported` | ✅                      | ❌                             |
| `reset_reason` (komplett)                       | ✅                      | ❌                             |
| `crypto_capabilities` (komplett)                | ✅                      | ❌                             |
| `survival_mechanisms`                           | ✅                      | ❌                             |
| `factory_identity`                              | ✅                      | ❌                             |
| `multi_core_topology`                           | ✅                      | ❌                             |
| `flash_controller.erase_sector_sequence`        | ❌                      | ✅                             |
| `timing_safety_factor`                          | ❌                      | ✅ (GAP-40)                    |

Die zwei Dokumente beschreiben **widersprüchliche Schemata** für dasselbe Artefakt (`blueprint.json`).

**Betroffene Dokumente:** `request.md`, `toobfuzzer_integration.md`

**Mitigation:** Ein kanonisches, konsolidiertes `blueprint.json` Schema als **einzige Quelle der Wahrheit** definieren. Am besten direkt in `toobfuzzer_integration.md` oder als dedizierte Schema-Referenz. `request.md` ist laut Index veraltet — die dort definierten Felder müssen in das aktive Dokument übernommen werden.

---

## GAP-F03: `aggregated_scan.json` — `max_erase_time_us` existiert im Schema, wird aber nicht konsumiert

**Problem:** `toobfuzzer_integration.md` definiert `max_erase_time_us` im `aggregated_scan.json` Segment-Schema (GAP-40 Basis). Die `chip_config.h` Generierung (Sektion 3, Schritt 3) zeigt **nur Flash-Konstanten** (`CHIP_FLASH_SECTOR_SIZE`, `CHIP_FLASH_WRITE_ALIGNMENT`, `CHIP_APP_ALIGNMENT_BYTES`). Es fehlt das entscheidende WDT-Timeout `#define`, das laut `concept_fusion.md` Schicht 5 dynamisch als `längste_Einzeloperation + 2x_Marge` berechnet und auf die Hardware-Treppenstufe gerundet werden muss.

**Betroffene Dokumente:** `toobfuzzer_integration.md` (Sektion 3), `concept_fusion.md` (Schicht 5), `hals.md` (`wdt_hal_t.init`)

**Mitigation:** Im Integrations-Workflow (Sektion 3) muss explizit dokumentiert werden, dass der Manifest-Compiler aus `max_erase_time_us * timing_safety_factor` den `#define BOOT_WDT_TIMEOUT_MS` Wert berechnet und in `chip_config.h` schreibt. Die aktuelle Code-Gen Sektion erwähnt das nicht.

---

## GAP-F04: `timing_safety_factor` als Float — Widerspruch zu `concept_fusion.md` Gleitkomma-Verbot

**Problem:** `toobfuzzer_integration.md` definiert `"timing_safety_factor": 2.0` als **Float** im `blueprint.json`. `concept_fusion.md` Schicht 5 schreibt ausdrücklich: _"Das Builder-Plugin verbietet Gleitkomma in die C-Header"_. Der Widerspruch: Der Faktor existiert als Float im JSON, soll aber nicht als Float in C landen. Der Konversions-Schritt (Float → Integer-Aufrundung auf Hardware-Treppenstufe) ist nirgends dokumentiert.

**Betroffene Dokumente:** `toobfuzzer_integration.md` (Sektion 2B), `concept_fusion.md` (Schicht 5)

**Mitigation:** Explizit dokumentieren, dass `timing_safety_factor` ein reiner **Manifest-Compiler-interner Rechenwert** ist, der niemals direkt in C-Header fließt. Das Build-Plugin konsumiert ihn zur WDT-Kalkulation und produziert einen **reinen Integer `uint32_t`** (`BOOT_WDT_TIMEOUT_MS`).

---

## GAP-F05: `chip_config.h` — In `concept_fusion.md` vs. `toobfuzzer_integration.md` verschiedene Makro-Namen

**Problem:** Die beiden Dokumente zeigen unterschiedliche Makro-Namen für denselben generierten Header:

| Makro             | `concept_fusion.md` (Kap. 6.2) | `toobfuzzer_integration.md` (Sektion 3) |
| ----------------- | ------------------------------ | --------------------------------------- |
| Sector Size       | `CHIP_FLASH_BASE_ADDR`         | `CHIP_FLASH_SECTOR_SIZE`                |
| Write Alignment   | `CHIP_FLASH_WRITE_ALIGN`       | `CHIP_FLASH_WRITE_ALIGNMENT`            |
| App Alignment     | _(nicht gezeigt)_              | `CHIP_APP_ALIGNMENT_BYTES`              |
| ROM Erase Pointer | `ROM_PTR_FLASH_ERASE`          | _(nicht gezeigt)_                       |

Kein konsistentes Naming.

**Betroffene Dokumente:** `concept_fusion.md` (Kap. 6.2), `toobfuzzer_integration.md` (Sektion 3)

**Mitigation:** Ein **kanonisches `chip_config.h` Template** definieren (idealerweise als Verweis auf `tools/templates/boot_config.h.j2` aus `structure_plan.md`) und beide Dokumente darauf verweisen lassen.

---

## GAP-F06: Keine Dokumentation der `blueprint.json` → `chip_config.h` Mapping-Regeln

**Problem:** Beide Dokumente zeigen **Beispiel-Snippets**, aber keines definiert die vollständige, verbindliche Transformation von JSON-Keys zu C-`#define`-Namen. Ein implementierender Entwickler muss raten, wie z.B. `flash_capabilities.write_alignment_bytes` zu `CHIP_FLASH_WRITE_ALIGN` (oder `CHIP_FLASH_WRITE_ALIGNMENT`?) wird.

**Betroffene Dokumente:** `toobfuzzer_integration.md`, `concept_fusion.md`

**Mitigation:** Eine explizite Mapping-Tabelle in `toobfuzzer_integration.md` ergänzen:

```
JSON Path                                    → C Macro
flash_capabilities.write_alignment_bytes     → CHIP_FLASH_WRITE_ALIGN
aggregated_scan[*].size (max)                → CHIP_FLASH_MAX_SECTOR_SIZE
flash_controller[0].rom_address              → ROM_PTR_FLASH_ERASE
...
```

---

## GAP-F07: `hals.md` Metadaten-Tabelle referenziert Toobfuzzer-Quellen die nicht im Integration-Doc stehen

**Problem:** `hals.md` (Zeile 176-188) hat eine Metadaten-Tabelle, die explizit auf Fuzzer-Datenquellen verweist:

- `erased_value` ← _"aus Fuzzer 'run_ping' Test"_: Der `run_ping` Key existiert im `aggregated_scan.json` Schema (`toobfuzzer_integration.md`) tatsächlich, aber nur als String (`"erased"` / `"zeroed"`). Die Transformation `"erased" → 0xFF` und `"zeroed" → 0x00` ist nirgends dokumentiert.
- `max_sector_size` ← _"aus aggregated_scan.json 'size' Feld"_: Korrekt, aber der Algorithmus (MAX über alle Segmente) ist nur in `hals.md` impliziert, nicht in `toobfuzzer_integration.md`.

**Betroffene Dokumente:** `hals.md` (Metadaten-Tabelle), `toobfuzzer_integration.md`

**Mitigation:** Die Transformationslogik (`run_ping` String → `uint8_t erased_value`, `size` → `max()` Aggregation) muss im Integrations-Workflow (Sektion 3) explizit als Manifest-Compiler-Logik dokumentiert werden.

---

## GAP-F08: `structure_plan.md` — `chip_config.h` wird als "Ebene 3 Chip-Adapter" beschrieben, aber `toobfuzzer_integration.md` sagt "AUTO-GENERATED"

**Problem:** `structure_plan.md` listet `chip_config.h` unter `hal/chips/<chip>/` als statische Datei mit Kommentar _"Flash-Map, Pin-Belegung, RAM-Größen"_. `toobfuzzer_integration.md` und `concept_fusion.md` beschreiben dieselbe Datei als **vollständig auto-generiert** durch den Manifest-Compiler. `structure_plan.md` kennzeichnet `boot_config.h` im `core/include/` als `← GENERIERT`, aber `chip_config.h` NICHT.

Wer schreibt diese Datei? Der Entwickler manuell? Der Manifest-Compiler? Oder beides (Template + Override)?

**Betroffene Dokumente:** `structure_plan.md`, `toobfuzzer_integration.md`, `concept_fusion.md`

**Mitigation:** Klarstellen: `chip_config.h` enthält zwei Kategorien:

1. **Statische Chip-Konstanten** (UART-Pins, RAM-Adressen) — manuell vom Port-Entwickler.
2. **Dynamische Fuzzer-Werte** (`CHIP_FLASH_SECTOR_SIZE`, ROM-Pointer) — auto-generiert.  
   Die Grenze zwischen beiden muss explizit definiert werden (z.B. über einen `/* AUTO-GENERATED SECTION */` Marker oder separate Dateien).

---

## GAP-F09: `flash_hal_t.sector_size` vs. `get_sector_size(addr)` — Toobfuzzer liefert nur eine Sector-Size

**Problem:** `hals.md` definiert sowohl ein statisches `max_sector_size` Feld als auch eine dynamische `get_sector_size(addr, size_out)` Funktion für variable Sektoren (z.B. STM32F4: 16/64/128 KB gemischt). `toobfuzzer_integration.md` zeigt im `aggregated_scan.json` Schema pro Segment ein `"size": 4096` Feld. Es ist **unklar**, ob der Fuzzer tatsächlich variable Sektoren pro Adressbereich einzeln auflistet oder ob er nur eine einzige uniforme Größe annimmt.

Falls der Fuzzer nur uniforme Sektoren erkennt, fehlt die Datenquelle für die dynamische `get_sector_size()` Implementation auf Chips mit variablen Sektoren.

**Betroffene Dokumente:** `hals.md` (`get_sector_size`), `toobfuzzer_integration.md` (Sektion 2A)

**Mitigation:** Explizit dokumentieren, dass `aggregated_scan.json` per Segment-Key **verschiedene Sektorgrößen** auflistet und der Manifest-Compiler diese als Lookup-Table in `chip_config.h` generiert (z.B. als Array `CHIP_SECTOR_MAP[]`). Wenn der Fuzzer das bereits kann, muss es im Integrations-Doc stehen.

---

## GAP-F10: `provisioning_guide.md` Sektion 2 — Fuzzer-Workflow-Lücke

**Problem:** `provisioning_guide.md` (Sektion 2) beschreibt die Toobfuzzer-Kalibrierung als Factory-Schritt und erwähnt drei Outputs: `sector_size`, `max_erase_time_us`, `write_alignment`. Zusätzlich einen `VDD-Drop` für `min_battery_mv`. Dieser **VDD-Drop/Brownout-Penalty** wird in `toobfuzzer_integration.md` **nullmal erwähnt**. Keine der beiden JSON-Schemata enthält ein Feld für Batterie-/Spannungs-Limits.

**Betroffene Dokumente:** `provisioning_guide.md` (Sektion 2), `toobfuzzer_integration.md`, `hals.md` (`soc_hal_t.min_battery_mv`)

**Mitigation:** Entweder:

- `blueprint.json` um ein `"power"` Objekt erweitern (`min_battery_start_mv`, `brownout_threshold_mv`), oder
- Explizit klarstellen, dass `min_battery_mv` ein rein manueller `device.toml` Wert ist und der Fuzzer hier keinen Beitrag leistet.

---

## GAP-F11: Fehlende Verlinkung `toobfuzzer_integration.md` → `request.md` (Stage 4)

**Problem:** `toobfuzzer_integration.md` erwähnt die Stage 4 Injection als Quelle für `blueprint.json`. `request.md` enthält den exakten Python-Code und das vollständige JSON-Schema für Stage 4. **Weder verlinkt `toobfuzzer_integration.md` auf `request.md`, noch umgekehrt.** Ein Entwickler der das Integrations-Dokument liest, weiß nicht, wo das Schema herkommt.

**Betroffene Dokumente:** `toobfuzzer_integration.md`, `request.md`

**Mitigation:** Da `request.md` als "veraltet" markiert ist, müssen die Stage-4-relevanten Teile entweder:

1. In `toobfuzzer_integration.md` als eigene Sektion konsolidiert, oder
2. In ein eigenständiges `toobfuzzer_stage4_spec.md` ausgelagert werden.

---

## GAP-F12: `getting_started.md` — Fuzzer-Kommando-Inkonsistenz

**Problem:** `getting_started.md` verwendet `toobfuzzer init --target stm32` und `toobfuzzer run`. `toobfuzzer_integration.md` spricht von `toobfuzzer3/` als Verzeichnisnamen. Der Index spricht von `toobfuzzer`. Drei verschiedene Bezeichnungen für dasselbe Tool:

1. `toobfuzzer` (Index + Getting Started CLI)
2. `toobfuzzer3` (Integration Doc + request.md)
3. `toobfuzzer3/` (als Repository-Pfad)

**Betroffene Dokumente:** `getting_started.md`, `toobfuzzer_integration.md`, `index.md`, `request.md`

**Mitigation:** Einheitliche Benennung durchsetzen. Vorschlag: CLI = `toobfuzzer`, Repo = `toobfuzzer3/` (Versionssuffix), interner Verweis immer `toobfuzzer`.

---

## GAP-F13: `concept_fusion.md` Kap. 6 — Bare-Metal ROM-Pointer ohne Error-Handling Spezifikation

**Problem:** `concept_fusion.md` Kap. 6 zeigt direkte ROM-Pointer-Aufrufe (`ROM_PTR_FLASH_ERASE`, `ROM_PTR_FLASH_WRITE`) als Funktionszeiger. Weder `concept_fusion.md` noch `toobfuzzer_integration.md` definieren:

- Was passiert wenn der ROM-Pointer `NULL` ist (Chip-Revision hat die Funktion entfernt)?
- Was der Rückgabewert dieser ROM-Funktionen ist (Vendor-spezifisch, nicht standardisiert).
- Wie `hals.md` `get_last_vendor_error()` an den ROM-Rückgabewert gekoppelt wird.

**Betroffene Dokumente:** `toobfuzzer_integration.md` (Sektion 2B), `concept_fusion.md` (Kap. 6), `hals.md` (`get_last_vendor_error`)

**Mitigation:** Im `blueprint.json` Schema pro ROM-Pointer ein `"return_convention"` Feld ergänzen (z.B. `"return_convention": "0_success"` oder `"esp_err_t"`). Zudem in `hals.md` klarstellen, dass die HAL-Implementation ROM-Rückgabewerte auf `boot_status_t` mappen MUSS.

---

## GAP-F14: `confirm_hal_t` — `set_ok()` Funktion fehlt im Struct, aber `toobfuzzer_integration.md` impliziert sie

**Problem:** `hals.md` (Zeile 257) erklärt explizit: _"`set_ok(nonce)` existiert absichtlich NICHT im Bootloader-Interface."_ Das Setzen erfolgt ausschließlich über `libtoob` im OS. Aber `concept_fusion.md` Kap. 6.1 fordert vom Toobfuzzer die _"Hex-Adresse im Survival-Storage (z.B. RTC-Reset-Resilient RAM), wo das 2FA-Handoff-Flag gefahrlos abgelegt werden darf"_ — für die `confirm_hal_t`.

Die Frage: Wenn `libtoob` (OS-seitig) das Flag schreibt und die Adresse aus dem Toobfuzzer stammt, wie gelangt die Adresse in die `libtoob`? Dieser Cross-Boundary-Informationsfluss ist nirgends spezifiziert.

**Betroffene Dokumente:** `hals.md`, `libtoob_api.md`, `toobfuzzer_integration.md`, `concept_fusion.md`

**Mitigation:** Dokumentieren, dass `ADDR_CONFIRM_RTC_RAM` sowohl in `chip_config.h` (für den Bootloader-Read) als auch in einem OS-sichtbaren Header oder `.noinit` Handoff-Feld (für `libtoob`-Write) propagiert werden muss. Der Manifest-Compiler muss diesen Wert in **beide** Richtungen bereitstellen.

---

## GAP-F15: `libtoob_api.md` — Kein Bezug zum Toobfuzzer

**Problem:** `libtoob_api.md` definiert die OS-seitige Library, die direkt auf WAL-Flash-Sektoren und `.noinit` RAM schreibt. Die **physischen Adressen** dieser Bereiche (WAL-Sektor-Base, `.noinit` RAM-Base) müssen zur Compile-Zeit bekannt sein. Es gibt keinen dokumentierten Pfad, wie diese Adressen vom Toobfuzzer/Manifest-Compiler in die `libtoob` fließen.

**Betroffene Dokumente:** `libtoob_api.md`, `toobfuzzer_integration.md`

**Mitigation:** Explizit dokumentieren, dass der Manifest-Compiler neben `chip_config.h` (für Stage 1) auch ein `libtoob_config.h` (für das Feature-OS) generiert, das WAL-Adressen und `.noinit` Offsets enthält.

---

## GAP-F16: `toob_telemetry.md` — `ext_health` Erase-Counts ohne Fuzzer-Initialisierung

**Problem:** Die Telemetrie-Spec definiert `wal_erase_count`, `app_slot_erase_count`, `swap_buffer_erase_count`. `concept_fusion.md` definiert einen EOL-Threshold bei ~80.000/100.000 Zyklen. Aber der **initiale Erase-Wear der Fuzzer-Kalibrierung** (die ja selbst intensiv schreibt/löscht!) wird nirgends berücksichtigt. Wenn der Fuzzer auf der Produktionslinie 500 Erase-Cycles verbraucht, muss der initiale Counter-Stand bei 500 beginnen, nicht bei 0.

**Betroffene Dokumente:** `toob_telemetry.md`, `provisioning_guide.md`, `toobfuzzer_integration.md`

**Mitigation:** Im Provisioning-Workflow (`provisioning_guide.md`) dokumentieren, dass der Fuzzer nach Abschluss seinen eigenen Erase-Count als `"fuzzer_erase_overhead"` im `aggregated_scan.json` exportiert. Der Manifest-Compiler setzt den initialen WAL-Counter auf diesen Wert.

---

## GAP-F17: `merkle_spec.md` — Chunk-Size Abhängigkeit vom Toobfuzzer nicht spezifiziert

**Problem:** `merkle_spec.md` definiert die Chunk-Size als "typisch 4 KB oder 8 KB". `concept_fusion.md` definiert die Delta-Chunks als 16 KB. `hals.md` zeigt `get_sector_size()` als variabel. Die **Abhängigkeit** der Merkle-Chunk-Size von der physischen Sektor-Geometrie (geliefert vom Fuzzer) ist nirgends explizit. Muss die Chunk-Size ein Vielfaches der Sektor-Size sein? Was wenn der Fuzzer 128 KB-Sektoren meldet?

**Betroffene Dokumente:** `merkle_spec.md`, `toobfuzzer_integration.md`, `concept_fusion.md`

**Mitigation:** In `merkle_spec.md` eine explizite Constraint-Regel ergänzen: `chunk_size` MUSS ≤ `min_sector_size` sein UND ein Teiler der Sektor-Größe. Der Manifest-Compiler berechnet die optimale `chunk_size` basierend auf dem `aggregated_scan.json`.

---

## GAP-F18: `stage_1_5_spec.md` — Serial Rescue Auth-Token, aber keine Fuzzer-Daten für DSLC-Adresse

**Problem:** `stage_1_5_spec.md` beschreibt den Offline-2FA-Handshake, der den DSLC (Device Specific Lock Code) benötigt. `hals.md` definiert `crypto_hal_t.read_dslc()`. `concept_fusion.md` Kap. 6.1 fordert die DSLC-Quelle vom Toobfuzzer. Aber das `blueprint.json` Schema aus `toobfuzzer_integration.md` enthält **kein** DSLC-Feld. Nur `request.md` (Stage 4) hat `factory_identity.uid_address`.

**Betroffene Dokumente:** `stage_1_5_spec.md`, `toobfuzzer_integration.md`, `hals.md`, `request.md`

**Mitigation:** `toobfuzzer_integration.md` Blueprint-Schema um `factory_identity` erweitern (wie in `request.md` definiert). Alternativ klarstellen, dass die DSLC-Adresse ein manueller `device.toml`-Wert ist.

---

## GAP-F19: `sandbox_setup.md` — Kein Bezug zum Toobfuzzer für Sandbox-Konfiguration

**Problem:** Die Sandbox baut mit `toob build --target sandbox`. Welche Werte kommen in die `chip_config.h` der Sandbox? `structure_plan.md` hat ein `sandbox/` Verzeichnis mit eigener `chip_config.h`. Aber der Fuzzer läuft nicht auf dem Host-PC. Es ist unklar, ob:

1. Die Sandbox hart-kodierte Default-Werte nutzt (4 KB Sektor, 4 Byte Alignment), oder
2. Ein echtes `aggregated_scan.json` von echter Hardware injiziert werden kann (HIL-crossover).

**Betroffene Dokumente:** `sandbox_setup.md`, `toobfuzzer_integration.md`, `structure_plan.md`

**Mitigation:** Explizit dokumentieren, dass die Sandbox statische `chip_config.h` Defaults nutzt (kein Fuzzer nötig) und dass für parametrisierte Tests ein optionales `--scan-file` CLI-Flag existiert.

---

## GAP-F20: `testing_requirements.md` — Kein Test-Szenario für Fuzzer-Output-Validierung

**Problem:** `testing_requirements.md` definiert SIL- und HIL-Tests, aber **keinen einzigen Test**, der validiert, dass:

- `aggregated_scan.json` korrekt geparst wird
- `blueprint.json` vollständig ist (Schema-Validierung)
- Die generierte `chip_config.h` konsistent mit den JSON-Inputs ist
- ROM-Pointer tatsächlich auf valide Funktionen zeigen (Plausibilitätscheck)

**Betroffene Dokumente:** `testing_requirements.md`, `toobfuzzer_integration.md`

**Mitigation:** Eigene Test-Kategorie "Manifest Compiler Validation" in `testing_requirements.md` ergänzen, die den gesamten Fuzzer-JSON → `chip_config.h` → HAL-Trait Pipeline-Pfad validiert.

---

## GAP-F21: `hals.md` — `flash_hal_t` hat `sector_size` als statisches Feld, was der Fuzzer-Architektur widerspricht

**Problem:** In `structure_plan.md` (Zeile 788) steht: `.sector_size = 2048`. In `hals.md` existiert kein statisches `sector_size` Feld im Struct — stattdessen gibt es `max_sector_size` und `get_sector_size(addr)`. `toobfuzzer_integration.md` referenziert in Sektion 1 `current_sector_size = platform->flash->sector_size`, was weder `max_sector_size` noch `get_sector_size()` ist.

Drei Dokumente, drei verschiedene Annahmen über den Sektorgröße-Zugriff.

**Betroffene Dokumente:** `toobfuzzer_integration.md` (Sektion 1), `hals.md`, `structure_plan.md`

**Mitigation:** `toobfuzzer_integration.md` Sektion 1 korrigieren: Der Core nutzt `platform->flash->get_sector_size(addr, &size)` für adressen-spezifische Größen und `platform->flash->max_sector_size` nur für Swap-Buffer-Dimensionierung. Die falsche Referenz `platform->flash->sector_size` muss entfernt werden.

---

## GAP-F22: `concept_fusion.md` Kap. 6 — "90% Platform-Code generiert sich selbst" nicht quantifiziert

**Problem:** Sowohl `concept_fusion.md` als auch `toobfuzzer_integration.md` behaupten, 90% des Platform-Codes werde auto-generiert. `structure_plan.md` zeigt jedoch, dass `chip_platform.c` (40 Zeilen Wiring) und `startup.c` (20 Zeilen) **manuell** geschrieben werden. Zudem sind die Vendor-Dateien (`vendor_flash.c`, `vendor_iwdg.c` etc.) ebenfalls manueller Code. Die "90%" Behauptung ist irreführend — der Fuzzer generiert nur `chip_config.h`, nicht den eigentlichen HAL-C-Code.

**Betroffene Dokumente:** `concept_fusion.md` (Kap. 6), `toobfuzzer_integration.md` (Titel + Ergebnis)

**Mitigation:** Die "90%" Claim präzisieren: "90% der **hardware-spezifischen Konfigurationskonstanten** werden auto-generiert. Der HAL-Implementierungscode selbst wird manuell geschrieben, aber durch die generierten Konstanten parametrisiert."

---

## GAP-F23: Multi-Image / Multi-Core — Toobfuzzer hat kein Multi-Core Schema

**Problem:** `concept_fusion.md` Schicht 5 definiert Atomic Update Groups für Multi-Core SoCs (nRF5340). Die `soc_hal_t` hat `assert_secondary_cores_reset()` und `flush_bus_matrix()`. Aber `toobfuzzer_integration.md` zeigt kein Schema für Multi-Core-Daten. Die Flash-Base-Adresse des Netzwerk-Cores, dessen unabhängiges Alignment, und die IPC-Mechanismen fehlen komplett.

Nur `request.md` (Stage 4) hat ein `multi_core_topology` Feld — aber das steht in einem als veraltet markierten Dokument.

**Betroffene Dokumente:** `toobfuzzer_integration.md`, `concept_fusion.md` (Schicht 5), `hals.md` (`soc_hal_t`), `request.md`

**Mitigation:** Das `multi_core_topology` Schema aus `request.md` Stage 4 in `toobfuzzer_integration.md` als Schema-Erweiterung übernehmen.

---

## GAP-F24: `index.md` Hinweis-Box — "GAP-Analyse V4 Modifikationen" nicht nachvollziehbar

**Problem:** `index.md` (Zeile 70-71) behauptet, `toobfuzzer_integration.md` sei durch die "Gap-Analyse V4" gehärtet worden, inklusive "Timing-Safeties für den Watchdog". Die einzige sichtbare V4-Modifikation in `toobfuzzer_integration.md` ist der `GAP-40` Kommentar bei `timing_safety_factor` und der `GAP-46` Kommentar beim Schema. Es fehlt eine Traceability — welche konkreten GAPs aus der V4-Analyse wo eingearbeitet wurden.

**Betroffene Dokumente:** `index.md`, `toobfuzzer_integration.md`, `analysis/Toob-Boot_gap_analysis_v4.md`

**Mitigation:** Am Ende von `toobfuzzer_integration.md` eine "Änderungshistorie" mit GAP-IDs ergänzen, die nachvollziehbar macht, welche V4-Findings einflossen.

---

## GAP-F25: `toobfuzzer_integration.md` — Kein Schema-Versionierungsmechanismus

**Problem:** Wenn sich das `blueprint.json` oder `aggregated_scan.json` Schema ändert (z.B. neue Felder für PQC-Crypto oder Multi-Core), gibt es keinen dokumentierten Mechanismus zur Schema-Versionierung. Der Manifest-Compiler könnte an unbekannten Keys scheitern oder, schlimmer, sie still ignorieren.

**Betroffene Dokumente:** `toobfuzzer_integration.md`

**Mitigation:** Ein `"schema_version": "1.0"` Top-Level-Feld in beiden JSON-Artefakten definieren. Der Manifest-Compiler prüft dieses Feld und bricht bei unbekannter Major-Version mit klarer Fehlermeldung ab.

---

## GAP-F26: `toobfuzzer_integration.md` — Verschleierter Error-Pfad bei fehlender Fuzzer-Datei

**Problem:** Sektion 3 (Step 2) sagt: _"Das Plugin zieht sich automatisch die neuste blueprint.json und aggregated_scan.json."_ Es ist nicht definiert:

- Woher? Lokales Dateisystem? Remote-Server? Eingebettet im `device.toml`?
- Was passiert wenn die Datei nicht existiert? Bricht der Build ab? Fallen Defaults ein?

**Betroffene Dokumente:** `toobfuzzer_integration.md` (Sektion 3)

**Mitigation:** Den Discovery-Pfad explizit definieren: Suchordnung `./fuzzer_output/<chip>/` → `~/.toob/cache/<chip>/` → Build-Fehler mit Anweisung zum Fuzzer-Lauf.

---

## GAP-F27: `concept_fusion.md` — `crypto_arena` Berechnung referenziert Fuzzer indirekt

**Problem:** Schicht 5 in `concept_fusion.md` definiert: _"Die `crypto_arena` wird dynamisch anhand der gewählten Krypto-Module berechnet."_ Die Krypto-Modul-Auswahl hängt von den `crypto_capabilities` ab, die der Fuzzer in `blueprint.json` liefert (hat der Chip HW-SHA? HW-Ed25519?). Dieser transitive Abhängigkeitspfad `Fuzzer → crypto_capabilities → Modul-Auswahl → Arena-Berechnung` ist nirgends als End-to-End-Pipeline dokumentiert.

**Betroffene Dokumente:** `concept_fusion.md` (Schicht 5), `toobfuzzer_integration.md`, `hals.md` (`crypto_hal_t.has_hw_acceleration`)

**Mitigation:** Im Integrations-Workflow explizit den Pfad: `blueprint.json:crypto_capabilities.hw_sha256 == true → Manifest-Compiler wählt HW-Backend → Arena-Size = min(X) → #define BOOT_CRYPTO_ARENA_SIZE` dokumentieren.

---

## GAP-F28: `toobfuzzer_integration.md` Sektion 4 (Platform-HAL Assemblierung) — Referenz auf Templates ohne Pfad

**Problem:** Sektion 4 erwähnt _"die generalisierten Templates unter `hal/vendor/esp/`"_. `structure_plan.md` zeigt den Pfad als `hal/vendor/esp/` (korrekt). Aber `toobfuzzer_integration.md` beschreibt nicht, welche `.c` Dateien in diesem Template-Verzeichnis existieren und wie genau das "Mapping" des generierten `#define` ROM-Pointers in die Template-Datei mechanisch funktioniert (Include? Macro-Expansion? Jinja2 Rendering?).

**Betroffene Dokumente:** `toobfuzzer_integration.md` (Sektion 4), `structure_plan.md`

**Mitigation:** In Sektion 4 explizit beschreiben: `chip_platform.c` (manuell) inkludiert `chip_config.h` (generiert) und verdrahtet die Vendor-Funktionen über die darin definierten Makros in die `boot_platform_t` Struktur. Keine Jinja2-Magie auf C-Seite.

---

## GAP-F29: `toob_telemetry.md` + `libtoob_api.md` — Rückgabetyp-Inkonsistenz

**Problem:** `toob_telemetry.md` (Zeile 46) definiert die Funktion `toob_get_boot_diag()` mit Rückgabetyp `boot_status_t`. `libtoob_api.md` definiert `toob_get_boot_logs()` mit Rückgabetyp `toob_status_t`. Beide Funktionen dienen demselben Zweck (Boot-Diagnostik extrahieren), haben aber verschiedene Namen, verschiedene Return-Typen und verschiedene Struct-Parameter (`toob_telemetry_t` vs. `toob_boot_diag_t`).

Dies ist keine direkte Fuzzer-Lücke, aber eine Inkonsistenz die den Datenpfad Fuzzer → Telemetrie → libtoob → OS verschleiert.

**Betroffene Dokumente:** `toob_telemetry.md`, `libtoob_api.md`

**Mitigation:** Konsolidieren: Ein Funktionsname (`toob_get_boot_diag`), ein Rückgabetyp (`toob_status_t`), ein Struct (`toob_boot_diag_t` mit CBOR-korrespondierenden Feldern).

---

## GAP-F30: `provisioning_guide.md` — Nennt nur `aggregated_scan.json`, nicht `blueprint.json`

**Problem:** `provisioning_guide.md` Sektion 2-3 beschreibt den Fuzzer-Workflow und erwähnt nur `aggregated_scan.json` als Output. `blueprint.json` (mit ROM-Pointern, Crypto-Capabilities, Alignment) wird nicht erwähnt. Sektion 3 sagt: _"Das aggregated_scan.json File wird in den Manifest-Compiler geworfen."_ In Wirklichkeit braucht der Compiler **beide** Dateien.

**Betroffene Dokumente:** `provisioning_guide.md` (Sektion 2+3), `toobfuzzer_integration.md`

**Mitigation:** `provisioning_guide.md` korrigieren: Der Fuzzer produziert sowohl `aggregated_scan.json` als auch `blueprint.json`. Beide fließen in den Manifest-Compiler.

---

## Zusammenfassung

| Kategorie                                                                | Anzahl | IDs                               |
| ------------------------------------------------------------------------ | ------ | --------------------------------- |
| **Schema-Widersprüche** (Felder fehlen oder divergieren)                 | 7      | F01, F02, F05, F06, F07, F09, F21 |
| **Fehlende Pipeline-Schritte** (undokumentierte Transformationen)        | 6      | F03, F04, F14, F15, F27, F28      |
| **Cross-Doc Inkonsistenzen** (verschiedene Dokumente widersprechen sich) | 7      | F08, F10, F13, F22, F29, F30, F12 |
| **Fehlende Verlinkungen** (Dokumente referenzieren nicht aufeinander)    | 3      | F11, F16, F24                     |
| **Fehlende Test-/Validierungs-Coverage**                                 | 3      | F17, F20, F25                     |
| **Sonderfälle unspezifiziert** (Sandbox, Multi-Core, Error-Handling)     | 4      | F18, F19, F23, F26                |
| **Gesamt**                                                               | **30** |                                   |

> [!IMPORTANT]
> Die kritischsten Findings sind **F01** (5 von 7 HAL-Trait-Datenquellen fehlen im dokumentierten Schema), **F02** (zwei widersprüchliche Schemata für dasselbe Artefakt) und **F14** (undokumentierter Cross-Boundary-Informationsfluss zwischen Bootloader und OS für die Confirm-Adresse).
