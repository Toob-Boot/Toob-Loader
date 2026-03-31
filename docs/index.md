# Toob-Boot Dokumentation (Index)

Willkommen im Dokumentationsverzeichnis von **Toob-Boot**. Diese Sammlung an Dokumenten spezifiziert die gesamte Architektur, Hardware-Abstraktion, Tooling-Integration und die Edge-Recovery-Abläufe des P10-Compliance-Bootloaders. 

Hier ist ein nach Themen gruppierter Überblick über alle Spezifikationsdokumente.

---

## 🏗️ 1. Kern-Architektur & Boot-Ablauf

*   **[`concept_fusion.md`](concept_fusion.md)**
    Die zentrale **Architektur-Bibel**. Beschreibt die 5-Schichten Struktur (S0-S4), das Triple Modular Redundancy (TMR) System, das Flash-Agnostic Write-Ahead-Log (WAL), sowie die State-Machine und Anti-Glitch-Sicherungen. *Startpunkt für jeden neuen Entwickler.*

*   **[`structure_plan.md`](structure_plan.md)**
    Der **Repository-Blueprint**. Zeigt die Verzeichnisstruktur (`core/`, `hal/`, `libtoob/`) und definiert die dreischichtige HAL-Wiederverwendung (Architektur → Vendor → Chip). Es sichert die P10-Regeln auf Source-Code-Ebene ab.

*   **[`hals.md`](hals.md)**
    Die Hardware Abstraction Layer Spezifikation. Dokumentiert, welche **C-Traits** (`flash_hal_t`, `crypto_hal_t`, `wdt_hal_t`, etc.) exakt implementiert werden müssen, welche Limits es gibt und wie die Hardware-Abstraktionen mit dem WDT agieren müssen.

*   **[`libtoob_api.md`](libtoob_api.md)**
    Das OS-Facing Interface. Erklärt die `libtoob` C-Library (für Feature-OS), über die das Target-Slot Handoff (via `.noinit`) stattfindet und wie Updates sowie Boot-Confirmations (`COMMITTED` Flag) sicherheitskritisch verwaltet werden.

---

## 🔒 2. Sicherheit, Überprüfung & Recovery

*   **[`merkle_spec.md`](merkle_spec.md)**
    Spezifikation zum O(1) Stream-Hashing für gigantische OS-Images. Erklärt den Chunk-basierten Signatur-Check und Flash-Streaming, sodass der RAM des Microcontrollers nicht durch das OS-Hashing überlaufen kann.

*   **[`stage_1_5_spec.md`](stage_1_5_spec.md)**
    Spezifikation für die radikale ("Zero-Day Brick") Offline-Recovery per serieller UART-Schnittstelle. Verwendet "Naked COBS", Ed25519-Auth-Tokens und striktes Flow-Control zur Bare-Metal-Rettung.

*   **[`toob_telemetry.md`](toob_telemetry.md)**
    Definition des hochkompakten CBOR-basierten Formates. Dient der Weiterleitung kritischer Metriken (Boot-Dauer, WDT-Kicks, Hardware-Faults) in das Feature-OS über eine strukturierte ABI.

---

## 🛠️ 3. Integration & Tooling

*   **[`toobfuzzer_integration.md`](toobfuzzer_integration.md)**
    Beschreibt das fundamentale "Zero-Code"-Prinzip: Wie die dynamischen Limits der Silizium-Hardware (Sector-Sizes, Flash-Alignments) mittels `toobfuzzer` extrahiert (`blueprint.json` / `aggregated_scan.json`) und ohne C-Bloat im Manifest-Compiler eingewebt werden.

*   **[`provisioning_guide.md`](provisioning_guide.md)**
    Hardening-Bibel für die Factory-Produktionsstraße: Deaktivierung von JTAG/SWD, Einbrennen von eFuses/DSLC-Werten und RMA-Locking (Return Merchandise Authorization).

*   **[`getting_started.md`](getting_started.md)**
    Praxisbezogener Quick-Start-Guide für die CLI (`repowatt/toob`), Einbindung von eigenen Keys (`toob-keygen`, `toob-sign`) und korrekte `libtoob`-Integration im eigenen OS.

---

## 🧪 4. Testing & Entwicklungsumgebung

*   **[`testing_requirements.md`](testing_requirements.md)**
    NASA P10 Compliance Vorgaben und Validierungs-Gates. Definiert die SIL (Software-In-the-Loop) Mock-Verfahren und HIL (Hardware-In-the-Loop) Brownout/Power-Loss Szenarien inkl. O(n) Check-Rules.

*   **[`sandbox_setup.md`](sandbox_setup.md)**
    Technisches How-To für den "OS-Sandboxing Compile". Erlaubt die vollständige Host-native Ausführung (x86/ARM64) des Bootloader-State-Machines unter Isolation der C-HAL Aufrufe via `GNU --wrap` Linker.

---

## 📉 5. Planung, Historie & Entwicklung

*   **[`dev_plan.md`](dev_plan.md)**
    Der Master-Implementierungsplan. Unterteilt die gesamte Entwicklung von Phase 0 (Fundament) bis Phase 6 (Vendor Ports) in greifbare C-Pakete mit strikten P10-Compliance-Prüfungen.

*   **[`dev_diary.md`](dev_diary.md)**
    Das fortlaufende Entwickler-Tagebuch. Dokumentiert Design-Entscheidungen, Lessons-Learned und technische Hindernisse während der Implementierung des Bootloaders ("Warum wurde es so gebaut?").

*   **`analysis/` (Ordner)**
    Enthält die verschiedenen Iterationen von Gap-Analysen (wie z.B. `big_gap_analysis_v2.md`), über die wir die finalen 50 Produktions-Gaps eliminiert haben.

---
> **Hinweis zur Toobfuzzer Integration:**
> *Wir haben kurz debattiert, ob `toobfuzzer_integration.md` bereits veraltet ist. Da aber die Fuzzer-Schemata (`blueprint.json` etc.) durch die Gap-Analyse V4 massiv gehärtet wurden (inklusive Timing-Safeties für den Watchdog), haben wir dieses Dokument als aktives Core-Feature mit V4-Modifikationen integriert!*
